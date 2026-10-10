"""
Training and Export Pipeline for Phishing URL Detection.

Loads and cleans malicious_phish.csv, extracts 29 features using URLFeatureExtractor,
performs domain-grouped 5-fold split (fold 0: 80% train / 20% test),
identifies top 50 TLDs, trains an optimized LightGBM classifier,
calibrates decision threshold to strictly enforce FPR <= 0.05,
and serializes the artifact to model/phishing_model.joblib.
"""

import argparse
import logging
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedGroupKFold
import tldextract

# Add current directory to path to import feature_extractor
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from feature_extractor import SCHEME_REGEX, URLFeatureExtractor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("TrainAndExport")


def resolve_dataset_path(provided_path: Optional[str] = None) -> str:
    """Find the malicious_phish.csv dataset file."""
    if provided_path and os.path.exists(provided_path):
        return os.path.abspath(provided_path)

    candidates = [
        os.path.join(os.getcwd(), "malicious_phish.csv"),
        os.path.join(CURRENT_DIR, "..", "..", "malicious_phish.csv"),
        os.path.join(CURRENT_DIR, "..", "malicious_phish.csv"),
        os.path.join(CURRENT_DIR, "malicious_phish.csv"),
    ]

    for cand in candidates:
        norm = os.path.normpath(cand)
        if os.path.exists(norm):
            return norm

    raise FileNotFoundError(
        f"Could not locate 'malicious_phish.csv'. Checked candidates: {candidates}"
    )


def load_and_clean_data(dataset_path: str) -> pd.DataFrame:
    """
    Load malicious_phish.csv and clean according to specifications:
    - Filter type in ['benign', 'phishing'] and map benign -> 0, phishing -> 1
    - Strip whitespace, drop null/blank rows
    - Remove control characters [\\x00-\\x1f\\x7f-\\x9f]
    - Drop conflicting URLs (URLs with conflicting labels)
    - Drop duplicate URLs
    - Parse host and registrable domain for grouping
    """
    logger.info("Loading dataset from: %s", dataset_path)
    df = pd.read_csv(dataset_path)
    logger.info("Raw dataset shape: %s", df.shape)

    # 1. Filter benign and phishing
    data = df.loc[df["type"].isin(["benign", "phishing"]), ["url", "type"]].copy()
    logger.info("Binary classes count before cleaning: %d", len(data))

    # 2. Map labels
    data["label"] = data["type"].map({"benign": 0, "phishing": 1}).astype(int)

    # 3. Drop nulls and strip outer whitespace
    data = data.dropna(subset=["url", "type"])
    data["url"] = data["url"].astype(str).str.strip()
    data = data[data["url"] != ""].copy()

    # 4. Remove control characters
    has_ctrl = data["url"].str.contains(r"[\x00-\x1f\x7f-\x9f]", regex=True)
    logger.info("Rows with control characters: %d", has_ctrl.sum())
    data = data.loc[~has_ctrl].copy()

    # 5. Remove conflicting URLs
    conflicts = data.groupby("url")["label"].nunique()
    bad_urls = conflicts[conflicts > 1].index
    logger.info("Conflicting URLs: %d", len(bad_urls))
    data = data.loc[~data["url"].isin(bad_urls)].copy()

    # 6. Drop duplicate URLs
    before_dup = len(data)
    data = data.drop_duplicates(subset="url").reset_index(drop=True)
    logger.info("Duplicate rows removed: %d", before_dup - len(data))

    # 7. Safe host and domain extraction for StratifiedGroupKFold
    logger.info("Extracting hostnames and registrable domains for grouping...")
    ext = tldextract.TLDExtract(
        suffix_list_urls=(), include_psl_private_domains=True
    )

    hosts = []
    for u in data["url"]:
        parse_target = u
        if not SCHEME_REGEX.match(parse_target) and not parse_target.startswith("//"):
            parse_target = "//" + parse_target
        try:
            h = urlsplit(parse_target).hostname or ""
        except Exception:
            h = ""
        hosts.append(h)

    data["host"] = hosts
    # Drop rows without a host
    data = data[data["host"] != ""].copy().reset_index(drop=True)

    # Group by registrable domain
    host_to_domain = {}
    for h in data["host"].unique():
        t = ext(h)
        host_to_domain[h] = t.top_domain_under_public_suffix or h

    data["domain"] = data["host"].map(host_to_domain)

    logger.info(
        "Clean dataset ready: %d rows (Benign: %d, Phishing: %d, Unique domains: %d)",
        len(data),
        (data["label"] == 0).sum(),
        (data["label"] == 1).sum(),
        data["domain"].nunique(),
    )
    return data


def perform_domain_split(
    data: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Split data using StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    grouped by registrable domain. Fold 0 is used for train (80%) and test (20%).
    """
    logger.info("Performing StratifiedGroupKFold (n_splits=5, seed=42)...")
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    train_idx, test_idx = next(
        sgkf.split(data, data["label"], groups=data["domain"])
    )

    train_df = data.iloc[train_idx].reset_index(drop=True)
    test_df = data.iloc[test_idx].reset_index(drop=True)

    logger.info(
        "Split complete: Train=%d (%.2f%%), Test=%d (%.2f%%)",
        len(train_df),
        (len(train_df) / len(data)) * 100,
        len(test_df),
        (len(test_df) / len(data)) * 100,
    )
    logger.info(
        "Train phishing share: %.2f%%, Test phishing share: %.2f%%",
        (train_df["label"].mean()) * 100,
        (test_df["label"].mean()) * 100,
    )

    # Verify no domain leakage
    overlap = set(train_df["domain"]) & set(test_df["domain"])
    if overlap:
        logger.warning("Domain overlap detected: %d domains!", len(overlap))
    else:
        logger.info("Zero domain overlap confirmed between train and test splits.")

    return train_df, test_df


def identify_top_tlds(train_df: pd.DataFrame, top_k: int = 50) -> List[str]:
    """Identify the top K most frequent TLDs in the training set."""
    ext = tldextract.TLDExtract(
        suffix_list_urls=(), include_psl_private_domains=True
    )
    host_to_suffix = {}
    for h in train_df["host"].unique():
        t = ext(h)
        host_to_suffix[h] = t.suffix.lower() if t.suffix else ""

    train_suffixes = train_df["host"].map(host_to_suffix)
    valid_suffixes = train_suffixes[train_suffixes != ""]
    top_tlds = valid_suffixes.value_counts().head(top_k).index.tolist()
    logger.info("Top %d training TLDs identified: %s", len(top_tlds), top_tlds[:10])
    return top_tlds


def extract_features_dataset(
    extractor: URLFeatureExtractor,
    urls: pd.Series,
    top_tlds: List[str],
    name: str = "dataset",
) -> pd.DataFrame:
    """Extract features for an entire series of URLs with timing and batch logging."""
    logger.info("Extracting features for %s (%d URLs)...", name, len(urls))
    t0 = time.time()

    # Pre-warm extractor cache with unique hosts in this dataset
    url_list = urls.tolist()
    features = [extractor.extract(u) for u in url_list]
    elapsed = time.time() - t0
    logger.info(
        "Extracted %d URLs in %.2f seconds (%.1f URLs/sec)",
        len(url_list),
        elapsed,
        len(url_list) / max(elapsed, 0.001),
    )

    df_feats = pd.DataFrame(features)
    # Ensure tld is categorical with fixed category list
    categories = list(top_tlds) + ["other"]
    df_feats["tld"] = pd.Categorical(df_feats["tld"], categories=categories)
    return df_feats


def calibrate_threshold(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    target_fpr: float = 0.05,
) -> Tuple[float, float, float, float]:
    """
    Search threshold on probabilities where FPR <= target_fpr (targeting max Recall).
    Returns (calibrated_threshold, final_fpr, final_recall, final_accuracy).
    """
    fprs, tprs, thresholds = roc_curve(y_true, y_prob)

    # Valid indices where FPR <= target_fpr
    valid_mask = fprs <= target_fpr
    if not np.any(valid_mask):
        best_threshold = 0.5
    else:
        # Largest FPR index that is still <= target_fpr yields maximum Recall (TPR)
        best_idx = np.where(valid_mask)[0][-1]
        best_threshold = float(thresholds[best_idx])

    # Evaluate exact threshold
    pred = (y_prob >= best_threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred).ravel()
    actual_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # Ensure discrete tie-breaking does not violate FPR <= target_fpr
    if actual_fpr > target_fpr:
        neg_scores = np.sort(y_prob[y_true == 0])
        max_fp = int(np.floor(target_fpr * len(neg_scores)))
        if max_fp > 0:
            best_threshold = float(neg_scores[-max_fp])
        else:
            best_threshold = float(neg_scores[-1] + 1e-6)

        pred = (y_prob >= best_threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, pred).ravel()
        actual_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    actual_recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    actual_accuracy = float((tp + tn) / len(y_true))
    return best_threshold, actual_fpr, actual_recall, actual_accuracy


def train_and_export(
    data_path: Optional[str] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Main training, evaluation, threshold calibration, and serialization routine."""
    dataset_file = resolve_dataset_path(data_path)

    if output_path is None:
        model_dir = os.path.join(CURRENT_DIR, "model")
        os.makedirs(model_dir, exist_ok=True)
        output_file = os.path.join(model_dir, "phishing_model.joblib")
    else:
        output_file = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # 1. Clean Data
    data = load_and_clean_data(dataset_file)

    # 2. Domain-grouped Split
    train_df, test_df = perform_domain_split(data)

    # 3. Top 50 TLDs
    top_50_tlds = identify_top_tlds(train_df, top_k=50)

    # 4. Feature Extraction
    extractor = URLFeatureExtractor(top_tlds=top_50_tlds)
    X_train = extract_features_dataset(extractor, train_df["url"], top_50_tlds, "Train")
    X_test = extract_features_dataset(extractor, test_df["url"], top_50_tlds, "Test")

    y_train = train_df["label"].to_numpy()
    y_test = test_df["label"].to_numpy()

    feature_names = X_train.columns.tolist()
    logger.info("Number of features: %d: %s", len(feature_names), feature_names)

    # 5. Train LightGBM Classifier
    logger.info("Training LightGBM Classifier (n_estimators=300, lr=0.05, num_leaves=31)...")
    clf = lgb.LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=31,
        random_state=42,
        n_jobs=-1,
    )

    t_train = time.time()
    clf.fit(X_train, y_train)
    logger.info("LightGBM training completed in %.2f seconds", time.time() - t_train)

    # 6. Evaluate and Calibrate Threshold (FPR <= 0.05)
    logger.info("Evaluating on test split and calibrating decision threshold...")
    y_prob_test = clf.predict_proba(X_test)[:, 1]
    roc_auc = float(roc_auc_score(y_test, y_prob_test))

    threshold, final_fpr, final_recall, final_acc = calibrate_threshold(
        y_test, y_prob_test, target_fpr=0.05
    )

    y_pred = (y_prob_test >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    # 7. Print summary metrics
    print("\n" + "=" * 60)
    print("           PHISHING MODEL EVALUATION SUMMARY")
    print("=" * 60)
    print(f"Dataset Size       : {len(data):,} URLs")
    print(f"Train Samples      : {len(train_df):,} URLs")
    print(f"Test Samples       : {len(test_df):,} URLs")
    print(f"ROC-AUC            : {roc_auc:.4f}")
    print(f"Calibrated Threshold: {threshold:.4f}")
    print(f"False Positive Rate: {final_fpr * 100:.2f}% (Target: <= 5.00%)")
    print(f"Phishing Recall    : {final_recall * 100:.2f}%")
    print(f"Accuracy           : {final_acc * 100:.2f}%")
    print("-" * 60)
    print("Confusion Matrix on Test Split:")
    print(f"  True Negatives (Legit detected)   : {tn:,}")
    print(f"  False Positives (False alarms)    : {fp:,}")
    print(f"  False Negatives (Missed phishing) : {fn:,}")
    print(f"  True Positives (Phish caught)     : {tp:,}")
    print("=" * 60 + "\n")

    # 8. Export Serialized Artifact
    artifact = {
        "model": clf,
        "top_tlds": top_50_tlds,
        "threshold": threshold,
        "feature_names": feature_names,
        "metrics": {
            "fpr": final_fpr,
            "recall": final_recall,
            "roc_auc": roc_auc,
        },
    }

    logger.info("Serializing model artifact to: %s", output_file)
    joblib.dump(artifact, output_file, compress=3)
    file_size_mb = os.path.getsize(output_file) / (1024 * 1024)
    logger.info("Model saved successfully! Artifact size: %.2f MB", file_size_mb)

    # 9. Smoke Test Loaded Artifact
    loaded = joblib.load(output_file)
    test_url = "https://secure-login-verify-account.example.com/update"
    sample_feat = extractor.extract(test_url)
    df_sample = pd.DataFrame([sample_feat])[loaded["feature_names"]]
    df_sample["tld"] = pd.Categorical(
        df_sample["tld"], categories=loaded["top_tlds"] + ["other"]
    )
    p_phish = float(loaded["model"].predict_proba(df_sample)[0, 1])
    is_phish = p_phish >= loaded["threshold"]

    logger.info(
        "Smoke Test on sample phishing lure: URL='%s' -> Prob=%.4f (Threshold=%.4f) -> Class=%s",
        test_url,
        p_phish,
        loaded["threshold"],
        "Phishing" if is_phish else "Benign",
    )

    return artifact


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train and export phishing URL detection model."
    )
    parser.add_argument(
        "--data-path",
        type=str,
        default=None,
        help="Path to malicious_phish.csv (defaults to auto-detection)",
    )
    parser.add_argument(
        "--output-path",
        type=str,
        default=None,
        help="Path to save phishing_model.joblib",
    )
    args = parser.parse_args()

    train_and_export(
        data_path=args.data_path,
        output_path=args.output_path,
    )
