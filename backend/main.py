"""
CyberSec URL Threat Assessment API.

Production-grade FastAPI service tailored for high-speed deterministic inference
and Vercel serverless deployment.
Branding & Terminology: URL Security & Threat Inspector powered by a Lexical & Gradient Classifier.
Zero Cold-Start: Model bundle and categorical encodings loaded once at startup.
"""

from contextlib import asynccontextmanager
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
import joblib
import pandas as pd
from pydantic import BaseModel, Field

# Ensure local backend modules can be imported
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from feature_extractor import URLFeatureExtractor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("URLThreatInspector")

# -----------------------------------------------------------------------------
# Dynamic Model Bundle Path Resolution (Serverless & Zero Cold-Start Ready)
# -----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.joblib")

def _resolve_model_path() -> str:
    """Locate the phishing_model.joblib artifact dynamically across candidate paths."""
    candidates = [
        MODEL_PATH,
        os.path.join(os.getcwd(), "url_project", "backend", "model", "phishing_model.joblib"),
        os.path.join(os.getcwd(), "backend", "model", "phishing_model.joblib"),
        os.path.join(os.getcwd(), "model", "phishing_model.joblib"),
    ]
    for path in candidates:
        norm = os.path.normpath(path)
        if os.path.exists(norm):
            return norm
    raise FileNotFoundError(
        f"Unable to find 'phishing_model.joblib'. Checked locations: {candidates}"
    )


MODEL_PATH = _resolve_model_path()
logger.info("Initializing URL Security & Threat Inspector from: %s", MODEL_PATH)

try:
    BUNDLE: Dict[str, Any] = joblib.load(MODEL_PATH)
    MODEL = BUNDLE["model"]
    TOP_TLDS: List[str] = BUNDLE["top_tlds"]
    THRESHOLD: float = float(BUNDLE["threshold"])
    FEATURE_NAMES: List[str] = BUNDLE["feature_names"]
    METRICS: Dict[str, Any] = BUNDLE.get("metrics", {})

    # Instantiate feature extractor and precompute categorical schema
    EXTRACTOR = URLFeatureExtractor(top_tlds=TOP_TLDS)
    CATEGORIES: List[str] = TOP_TLDS + ["other"]
    logger.info(
        "Model successfully loaded. Features: %d, Top TLDs: %d, Calibrated Threshold: %.4f",
        len(FEATURE_NAMES),
        len(TOP_TLDS),
        THRESHOLD,
    )
except Exception as exc:
    logger.critical("Failed to load model bundle at startup: %s", exc, exc_info=True)
    raise RuntimeError(f"Startup initialization failed: {exc}") from exc


# -----------------------------------------------------------------------------
# Pydantic v2 Models
# -----------------------------------------------------------------------------
class URLAnalysisRequest(BaseModel):
    """URL inspection request payload."""
    url: str = Field(
        ...,
        description="Target URL string to inspect for potential malicious phishing activity.",
        examples=["https://secure-login-verify-account.example.com/update"],
    )


class URLForensics(BaseModel):
    """Detailed structural and lexical forensic breakdown of inspected URL."""
    url_length: int = Field(..., description="Raw URL length without scheme protocol.")
    domain_length: int = Field(..., description="Length of the parsed host domain.")
    path_depth: int = Field(..., description="Number of hierarchical path components.")
    param_count: int = Field(..., description="Number of query parameters.")
    digit_ratio: float = Field(..., description="Proportion of numeric digits in the URL.")
    has_ip_host: bool = Field(..., description="Whether the host is an explicit IPv4 or IPv6 address.")
    has_punycode: bool = Field(..., description="Whether the host contains punycode encoding (xn--).")
    host_entropy: float = Field(..., description="Shannon entropy of host characters in bits.")
    suspicious_keywords_count: int = Field(..., description="Count of identified social-engineering lures.")
    tld: str = Field(..., description="Registrable public suffix matched or categorized as 'other'.")


class URLAnalysisResponse(BaseModel):
    """Deterministic security analysis response."""
    url: str = Field(..., description="Analyzed URL.")
    verdict: str = Field(
        ...,
        description="Security threat verdict: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS'.",
        examples=["MALICIOUS"],
    )
    is_threat: bool = Field(
        ...,
        description="Binary classification indicating whether the URL exceeds the calibrated safety threshold.",
    )
    threat_probability: float = Field(
        ...,
        description="Estimated probability score of malicious phishing intent (0.0 to 1.0).",
    )
    threshold_applied: float = Field(
        ...,
        description="Calibrated decision boundary enforcing False Positive Rate <= 0.05.",
    )
    latency_ms: float = Field(
        ...,
        description="Total deterministic inference latency in milliseconds.",
    )
    forensics: URLForensics = Field(
        ...,
        description="Lexical and structural metrics extracted from the inspected URL.",
    )


class BatchURLAnalysisRequest(BaseModel):
    """Batch URL inspection request payload."""
    urls: List[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of URL strings to analyze concurrently (up to 100).",
    )


class ServiceHealthResponse(BaseModel):
    """System diagnostic health and classifier baseline response."""
    status: str
    service: str
    classifier_engine: str
    model_calibrated_threshold: float
    model_metrics: Dict[str, Any]
    feature_dimensions: int


# -----------------------------------------------------------------------------
# Core Deterministic Inference Routine
# -----------------------------------------------------------------------------
def analyze_single_url(raw_url: str) -> URLAnalysisResponse:
    """
    Executes lexical inspection, categorical alignment, and gradient classification
    for a single URL. Measures deterministic execution time.
    """
    start_time = time.perf_counter()

    # 1. Feature extraction
    raw_features = EXTRACTOR.extract(raw_url)

    # 2. Categorical alignment for LightGBM
    # Match the exact category list from training
    df_input = pd.DataFrame([raw_features])[FEATURE_NAMES]
    df_input["tld"] = pd.Categorical(df_input["tld"], categories=CATEGORIES)

    # 3. Model inference
    proba = float(MODEL.predict_proba(df_input)[0, 1])
    threat_probability = round(proba, 4)

    # 4. Threat assessment and verdict assignment
    # Calibrated decision threshold enforces False Positive Rate <= 0.05
    is_threat = threat_probability >= THRESHOLD

    if threat_probability >= 0.70:
        verdict = "MALICIOUS"
    elif is_threat:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    forensics = URLForensics(
        url_length=int(raw_features["url_length"]),
        domain_length=int(raw_features["domain_length"]),
        path_depth=int(raw_features["path_depth"]),
        param_count=int(raw_features["param_count"]),
        digit_ratio=round(float(raw_features["digit_ratio"]), 4),
        has_ip_host=bool(raw_features["has_ip"] == 1),
        has_punycode=bool(raw_features["has_punycode"] == 1),
        host_entropy=round(float(raw_features["host_entropy"]), 4),
        suspicious_keywords_count=int(raw_features["suspicious_count"]),
        tld=str(raw_features["tld"]),
    )

    return URLAnalysisResponse(
        url=raw_url,
        verdict=verdict,
        is_threat=is_threat,
        threat_probability=threat_probability,
        threshold_applied=round(THRESHOLD, 4),
        latency_ms=elapsed_ms,
        forensics=forensics,
    )


# -----------------------------------------------------------------------------
# FastAPI Application Configuration
# -----------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context ensuring readiness."""
    logger.info("CyberSec URL Threat Assessment API is operational and ready for traffic.")
    yield
    logger.info("CyberSec URL Threat Assessment API is shutting down.")


app = FastAPI(
    title="CyberSec URL Threat Assessment API",
    version="1.0.0",
    description=(
        "Production-grade URL Security & Threat Inspector powered by a deterministic "
        "Lexical & Gradient Classifier. Evaluates 29 lexical, structural, and statistical "
        "forensic indicators with decision thresholds calibrated to maintain False Positive Rate <= 5%."
    ),
    lifespan=lifespan,
)

# Enable CORS for cross-origin integration (frontend, browser extensions, microservices)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# API Endpoints
# -----------------------------------------------------------------------------
@app.get(
    "/",
    tags=["Inspection Engine Metadata"],
    summary="Service metadata and classification specifications",
)
def get_service_metadata() -> Dict[str, Any]:
    """Provides service status, classifier specifications, and security operating metrics."""
    return {
        "service": "URL Security & Threat Inspector",
        "classifier_architecture": "Lexical & Gradient Classifier (LightGBM)",
        "version": "1.0.0",
        "decision_threshold": round(THRESHOLD, 4),
        "target_false_positive_rate": "<= 0.05",
        "benchmark_metrics": METRICS,
        "supported_features": len(FEATURE_NAMES),
        "status": "OPERATIONAL",
    }


@app.get(
    "/health",
    response_model=ServiceHealthResponse,
    tags=["Diagnostics"],
    summary="Health check and engine state probe",
)
def get_health() -> ServiceHealthResponse:
    """Returns engine health, model calibration, and verification telemetry."""
    return ServiceHealthResponse(
        status="HEALTHY",
        service="CyberSec URL Threat Assessment API",
        classifier_engine="LightGBM Boosted Tree Ensemble",
        model_calibrated_threshold=round(THRESHOLD, 4),
        model_metrics=METRICS,
        feature_dimensions=len(FEATURE_NAMES),
    )


@app.post(
    "/analyze",
    response_model=URLAnalysisResponse,
    status_code=status.HTTP_200_OK,
    tags=["Threat Inspection"],
    summary="Inspect a single URL for malicious phishing indicators",
)
def analyze_url(payload: URLAnalysisRequest) -> URLAnalysisResponse:
    """
    Performs deterministic threat inspection on the provided URL:
    1. Extracts 29 lexical, domain, structural, and lure indicators.
    2. Aligns categorical top-level domain encodings.
    3. Executes gradient boosted inference.
    4. Evaluates probability against the calibrated safety threshold (FPR <= 0.05).
    5. Returns verdict ('BENIGN', 'SUSPICIOUS', 'MALICIOUS') with forensic indicators.
    """
    clean_url = payload.url.strip()
    if not clean_url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="URL payload cannot be blank or empty.",
        )
    return analyze_single_url(clean_url)


# Direct API route alias for frontend / proxy flexibility
@app.post(
    "/api/analyze",
    response_model=URLAnalysisResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
def analyze_url_alias(payload: URLAnalysisRequest) -> URLAnalysisResponse:
    """API alias for /analyze."""
    return analyze_url(payload)


@app.post(
    "/api/v1/analyze",
    response_model=URLAnalysisResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
def analyze_url_v1_alias(payload: URLAnalysisRequest) -> URLAnalysisResponse:
    """API v1 alias for /analyze."""
    return analyze_url(payload)


@app.post(
    "/api/py/analyze",
    response_model=URLAnalysisResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
def analyze_url_py_alias(payload: URLAnalysisRequest) -> URLAnalysisResponse:
    """API alias for /api/py/analyze (supports Vercel rewrite pass-through)."""
    return analyze_url(payload)


@app.post(
    "/batch-analyze",
    response_model=List[URLAnalysisResponse],
    status_code=status.HTTP_200_OK,
    tags=["Threat Inspection"],
    summary="Inspect multiple URLs in a single batch request",
)
def batch_analyze_urls(payload: BatchURLAnalysisRequest) -> List[URLAnalysisResponse]:
    """Inspects a batch of up to 100 URLs in a single deterministic scan."""
    results: List[URLAnalysisResponse] = []
    for u in payload.urls:
        clean_url = u.strip()
        if clean_url:
            results.append(analyze_single_url(clean_url))
    return results


# -----------------------------------------------------------------------------
# Local Development Entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "127.0.0.1")
    logger.info("Starting local development server on http://%s:%d", host, port)
    uvicorn.run("main:app", host=host, port=port, reload=False)
