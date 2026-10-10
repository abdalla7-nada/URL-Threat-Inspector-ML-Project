"""
Automated Test Suite for Bare Domain Path Debiasing and Canonical Allowlist Expansion.
Verifies mitigation of the +4.0952 log-odds zero-length path artifact on LightGBM
and validates alias coverage across the Enterprise Trust Tier.
"""

import os
import sys
import time
from typing import List, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
for p in [BASE_DIR, PROJECT_ROOT]:
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi.testclient import TestClient
from main import app
from allowlist import is_allowlisted_domain

client = TestClient(app)

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def test_canonical_allowlist_expansion() -> None:
    """Assert canonical brand aliases resolve to BENIGN with 1.0% threat score."""
    print(f"\n{CYAN}>>> 1. Testing Canonical Allowlist Brand Expansion...{RESET}")

    canonical_vectors: List[Tuple[str, str]] = [
        ("https://www.wikipedia.com", "Wikipedia Dot-Com Alias"),
        ("https://wikipedia.com", "Wikipedia Bare Dot-Com"),
        ("https://wikipedia.org", "Wikipedia Canonical Dot-Org"),
        ("https://wikipedia.net", "Wikipedia Dot-Net Alias"),
        ("https://m.wikipedia.org", "Wikipedia Mobile Subdomain"),
        ("https://google.co.uk", "Google UK Regional Domain"),
        ("https://google.com.eg", "Google Egypt Regional Domain"),
        ("https://google.net", "Google Dot-Net Infrastructure"),
        ("https://azure.com", "Microsoft Azure Cloud Portal"),
        ("https://office.com", "Microsoft Office Portal"),
        ("https://aws.amazon.com", "Amazon Web Services Console"),
        ("https://amazon.eg", "Amazon Egypt Regional Domain"),
        ("https://icloud.com", "Apple iCloud Ecosystem"),
        ("https://github.io", "GitHub Pages User Domain"),
    ]

    for url, desc in canonical_vectors:
        resp = client.post("/analyze", json={"url": url})
        assert resp.status_code == 200, f"Failed for {url}: {resp.text}"
        data = resp.json()

        assert data["verdict"] == "BENIGN", f"Expected BENIGN for {url}, got {data['verdict']}"
        assert data["threat_probability"] == 0.01, f"Expected 0.01 for {url}, got {data['threat_probability']}"
        assert data["forensics"]["is_allowlisted"] is True, f"Expected is_allowlisted=True for {url}"
        print(f"  {GREEN}[PASS]{RESET} {desc:<35} ({url:<30}) -> BENIGN (1.0%) Allowlisted: True")


def test_unlisted_legitimate_bare_domains() -> None:
    """Assert non-allowlisted legitimate bare domains remain BENIGN (< 47.05%)."""
    print(f"\n{CYAN}>>> 2. Testing Debiasing on Unlisted Legitimate Bare Domains...{RESET}")

    unlisted_bare_domains: List[Tuple[str, str]] = [
        ("https://unlisted-legitimate-firm.org", "Unlisted Enterprise Firm"),
        ("https://example-real-business.org", "Real Business Non-Profit"),
        ("https://my-local-bakery.com", "Small Business Retail Domain"),
        ("https://acme-consulting-services.net", "Corporate Services Domain"),
        ("https://regional-dentist-clinic.org", "Healthcare Provider Bare Root"),
    ]

    for url, desc in unlisted_bare_domains:
        resp = client.post("/analyze", json={"url": url})
        assert resp.status_code == 200, f"Failed for {url}: {resp.text}"
        data = resp.json()

        prob = data["threat_probability"]
        verdict = data["verdict"]
        is_threat = data["is_threat"]
        forensics = data["forensics"]

        # Crucial: Threat score must not spike to 90%+; must be < 47.05%
        assert prob < 0.4705, f"Debiasing failed for {url}: Score={prob:.4f} >= 0.4705"
        assert verdict == "BENIGN", f"Expected BENIGN for {url}, got {verdict}"
        assert is_threat is False, f"Expected is_threat=False for {url}"

        # Transparency check: UI forensics must reflect true raw attributes, not model substitution
        assert forensics["path_depth"] == 0, f"Expected forensic path_depth=0, got {forensics['path_depth']}"
        assert forensics["is_allowlisted"] is False, f"Expected is_allowlisted=False for {url}"

        print(f"  {GREEN}[PASS]{RESET} {desc:<35} ({url:<38}) -> Verdict: {verdict} | Score: {prob*100:.2f}% | Path Depth: {forensics['path_depth']}")


def test_phishing_bare_domains_retained_detection() -> None:
    """Assert phishing bare domains with credential lures are still flagged as threats (> 50%)."""
    print(f"\n{CYAN}>>> 3. Testing Adversarial Phishing Bare Domains Retained Detection...{RESET}")

    phishing_bare_domains: List[Tuple[str, str]] = [
        ("http://secure-login-verify-account.com", "Credential Harvesting Bare Domain"),
        ("http://account-login-verification-secure.com", "Account Verification Bare Domain"),
        ("http://verify-bank-account-signin.com", "Banking Lure Bare Domain"),
        ("http://login-verify-account-update.com", "Update Auth Bare Domain"),
    ]

    for url, desc in phishing_bare_domains:
        resp = client.post("/analyze", json={"url": url})
        assert resp.status_code == 200, f"Failed for {url}: {resp.text}"
        data = resp.json()

        prob = data["threat_probability"]
        verdict = data["verdict"]
        is_threat = data["is_threat"]

        # Must be flagged as a threat (> threshold 47.05%)
        assert is_threat is True, f"Expected is_threat=True for phishing domain {url}"
        assert prob >= 0.4705, f"Expected threat prob >= 0.4705 for {url}, got {prob}"
        assert verdict in ["SUSPICIOUS", "MALICIOUS"], f"Expected SUSPICIOUS or MALICIOUS for {url}, got {verdict}"

        print(f"  {GREEN}[PASS]{RESET} {desc:<38} ({url:<45}) -> Verdict: {verdict:<10} | Score: {prob*100:.2f}% | Threat: True")


def test_paths_not_distorted() -> None:
    """Assert URLs with actual paths use real features without debiasing interference."""
    print(f"\n{CYAN}>>> 4. Testing URLs with Real Paths (Zero Distortion)...{RESET}")

    path_vectors: List[Tuple[str, str, str]] = [
        ("https://developer.mozilla.org/en-US/docs/Web", "Deep Benign Path", "BENIGN"),
        ("http://192.168.1.1/login-admin-verify-password", "Malicious Deep Path Lure", "MALICIOUS"),
    ]

    for url, desc, expected_verdict in path_vectors:
        resp = client.post("/analyze", json={"url": url})
        assert resp.status_code == 200
        data = resp.json()

        assert data["verdict"] == expected_verdict, f"Expected {expected_verdict} for {url}, got {data['verdict']}"
        assert data["forensics"]["path_depth"] >= 1, "Path depth should reflect real structure"
        print(f"  {GREEN}[PASS]{RESET} {desc:<35} -> Verdict: {data['verdict']} | Path Depth: {data['forensics']['path_depth']}")


def main() -> None:
    print("=" * 90)
    print(" CYBERSEC URL THREAT INSPECTOR - PATH-LENGTH DEBIASING & ALLOWLIST EXPANSION SUITE")
    print(" Validating Mitigation of Zero-Length Path Artifact & Canonical Aliases")
    print("=" * 90)

    start_time = time.perf_counter()

    test_canonical_allowlist_expansion()
    test_unlisted_legitimate_bare_domains()
    test_phishing_bare_domains_retained_detection()
    test_paths_not_distorted()

    elapsed = (time.perf_counter() - start_time) * 1000
    print("\n" + "=" * 90)
    print(f" {GREEN}ALL PATH DEBIASING & ALLOWLIST ASSERTIONS PASSED (100% SUCCESS) in {elapsed:.1f}ms{RESET}")
    print("=" * 90)


if __name__ == "__main__":
    main()
