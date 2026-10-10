"""
Enterprise Trust Tier & Allowlist Regression Verification Suite.

Validates that:
1. Top Global Domains (both bare root domains and sub-paths) resolve to BENIGN (threat_probability <= 0.05).
2. Critical Phishing Vectors and Adversarial Subdomains are NEVER bypassed (Zero False Negatives).
3. Sub-millisecond short-circuit latency (< 2ms) for allowlisted domains and < 15ms for non-allowlisted domains.
"""

import os
import sys
import time
from typing import Any, Dict, List, Tuple

# Ensure backend root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from main import app, analyze_single_url, EXTRACTOR
from allowlist import is_allowlisted_domain

client = TestClient(app)

# Terminal ANSI styling
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"


# =============================================================================
# Test Vectors Definition
# =============================================================================
ALLOWLIST_BENIGN_VECTORS = [
    ("Vector A1 (Wikipedia Bare Root)", "https://www.wikipedia.org"),
    ("Vector A2 (Wikipedia Scheme Root)", "https://wikipedia.org"),
    ("Vector A3 (Google Bare Root)", "https://google.com"),
    ("Vector A4 (GitHub Bare Root)", "https://github.com"),
    ("Vector A5 (Microsoft Bare Root)", "https://microsoft.com"),
    ("Vector A6 (Wikipedia Sub-path)", "https://www.wikipedia.org/wiki/Computer_security"),
    ("Vector A7 (GitHub Repo Sub-path)", "https://github.com/torvalds/linux"),
    ("Vector A8 (Google Search Query)", "https://google.com/search?q=cybersecurity"),
    ("Vector A9 (Microsoft Security Doc)", "https://microsoft.com/en-us/security"),
    ("Vector A10 (Amazon AWS Subdomain)", "https://aws.amazon.com/s3/"),
    ("Vector A11 (Apple Bare Root)", "https://apple.com"),
    ("Vector A12 (Cloudflare Bare Root)", "https://cloudflare.com"),
]

MALICIOUS_THREAT_VECTORS = [
    (
        "Vector B1 (Raw IPv4 Admin Lure)",
        "http://192.168.1.1/login-admin-verify-password",
        ["MALICIOUS"],
    ),
    (
        "Vector B2 (PayPal Brand Spoofing)",
        "http://paypal-verification-center-update.com/signin",
        ["MALICIOUS", "SUSPICIOUS"],
    ),
    (
        "Vector B3 (Microsoft Subdomain Lure)",
        "http://login.microsoftonline.com.security-auth-check.xyz",
        ["MALICIOUS", "SUSPICIOUS"],
    ),
    (
        "Vector B4 (Google IDN/Subdomain Lure)",
        "http://google.com.security-account-recovery.top/login",
        ["MALICIOUS", "SUSPICIOUS"],
    ),
    (
        "Vector B5 (Apple ID Spoofing Portal)",
        "http://apple.com-id-verify.com/signin",
        ["MALICIOUS", "SUSPICIOUS"],
    ),
]


def test_allowlist_domain_normalization():
    """Verify tldextract domain normalization and allowlist matching logic."""
    print(f"\n{BOLD}{CYAN}>>> 1. Testing Domain Normalization & Root Domain Extraction...{RESET}")

    test_cases = [
        ("www.wikipedia.org", "wikipedia.org", True),
        ("wikipedia.org", "wikipedia.org", True),
        ("en.wikipedia.org", "wikipedia.org", True),
        ("google.com", "google.com", True),
        ("accounts.google.com", "google.com", True),
        ("github.com", "github.com", True),
        ("microsoft.com", "microsoft.com", True),
        ("login.microsoftonline.com.security-auth-check.xyz", "security-auth-check.xyz", False),
        ("paypal-verification-center-update.com", "paypal-verification-center-update.com", False),
        ("google.com.attacker.com", "attacker.com", False),
        ("google.com-recovery.net", "com-recovery.net", False),
        ("192.168.1.1", "", False),
    ]

    for host, expected_root, expected_allowlisted in test_cases:
        extracted_root = EXTRACTOR.get_registered_domain(host)
        assert extracted_root == expected_root, (
            f"Extraction mismatch for {host}: expected '{expected_root}', got '{extracted_root}'"
        )
        is_allowed = is_allowlisted_domain(extracted_root)
        assert is_allowed == expected_allowlisted, (
            f"Allowlist status mismatch for {host} (root '{extracted_root}'): "
            f"expected {expected_allowlisted}, got {is_allowed}"
        )
        print(f"  {GREEN}[PASS]{RESET} {host.ljust(48)} -> root: {extracted_root.ljust(30)} allowlisted: {is_allowed}")

    print(f"  {BOLD}{GREEN}[PASS] Domain normalization assertions passed (12/12).{RESET}")


def test_top_global_domains_benign():
    """Assert all top global domains resolve to BENIGN with is_threat=False and is_allowlisted=True."""
    print(f"\n{BOLD}{CYAN}>>> 2. Testing Top Global Domains (Bare & Sub-paths) via API...{RESET}")

    results = []
    for label, url in ALLOWLIST_BENIGN_VECTORS:
        resp = client.post("/analyze", json={"url": url})
        assert resp.status_code == 200, f"Failed request for {url}: {resp.status_code} - {resp.text}"
        data = resp.json()

        assert data["verdict"] == "BENIGN", f"Expected BENIGN for {url}, got {data['verdict']}"
        assert data["is_threat"] is False, f"Expected is_threat=False for {url}"
        assert data["threat_probability"] <= 0.05, (
            f"Threat probability {data['threat_probability']} exceeds 0.05 for allowlisted {url}"
        )
        assert data["forensics"]["is_allowlisted"] is True, (
            f"Expected forensics.is_allowlisted=True for {url}"
        )

        results.append({
            "label": label,
            "url": url,
            "verdict": data["verdict"],
            "prob": data["threat_probability"],
            "latency_ms": data["latency_ms"],
            "is_allowlisted": data["forensics"]["is_allowlisted"],
        })

        print(
            f"  {GREEN}[PASS]{RESET} {label.ljust(35)} "
            f"Verdict: {GREEN}{data['verdict'].ljust(8)}{RESET} "
            f"Score: {(data['threat_probability'] * 100):.1f}%   "
            f"Latency: {data['latency_ms']:.2f}ms"
        )

    print(f"  {BOLD}{GREEN}[PASS] All {len(ALLOWLIST_BENIGN_VECTORS)} top global domain vectors resolved to BENIGN.{RESET}")
    return results


def test_threat_vectors_zero_bypass():
    """Assert all adversarial and phishing vectors are classified as threats (Zero False Negatives)."""
    print(f"\n{BOLD}{CYAN}>>> 3. Testing Adversarial Threats & Spoofing Vectors (Zero Bypass)...{RESET}")

    results = []
    for label, url, allowed_verdicts in MALICIOUS_THREAT_VECTORS:
        resp = client.post("/analyze", json={"url": url})
        assert resp.status_code == 200, f"Failed request for {url}: {resp.status_code} - {resp.text}"
        data = resp.json()

        assert data["verdict"] in allowed_verdicts, (
            f"Expected verdict in {allowed_verdicts} for {url}, got {data['verdict']}"
        )
        assert data["is_threat"] is True, f"Expected is_threat=True for threat {url}"
        assert data["forensics"]["is_allowlisted"] is False, (
            f"Threat {url} must NOT be allowlisted!"
        )

        results.append({
            "label": label,
            "url": url,
            "verdict": data["verdict"],
            "prob": data["threat_probability"],
            "latency_ms": data["latency_ms"],
            "is_allowlisted": data["forensics"]["is_allowlisted"],
        })

        color = RED if data["verdict"] == "MALICIOUS" else YELLOW
        print(
            f"  {GREEN}[PASS]{RESET} {label.ljust(35)} "
            f"Verdict: {color}{data['verdict'].ljust(10)}{RESET} "
            f"Score: {(data['threat_probability'] * 100):.1f}%   "
            f"Allowlisted: {data['forensics']['is_allowlisted']}"
        )

    print(f"  {BOLD}{GREEN}[PASS] All {len(MALICIOUS_THREAT_VECTORS)} malicious threats correctly flagged (Zero False Negatives).{RESET}")
    return results


def test_latency_sla_benchmarks():
    """
    Verify latency SLAs:
    - Allowlisted domains must resolve in < 2ms.
    - Non-allowlisted domains must retain sub-15ms inference latency.
    """
    print(f"\n{BOLD}{CYAN}>>> 4. Testing Deterministic Latency SLAs...{RESET}")

    # Warmup
    for _ in range(5):
        analyze_single_url("https://www.wikipedia.org")
        analyze_single_url("http://192.168.1.1/admin-check")

    # Benchmark allowlisted domains
    allowlisted_latencies = []
    for _ in range(30):
        t0 = time.perf_counter()
        res = analyze_single_url("https://www.wikipedia.org")
        elapsed_ms = (time.perf_counter() - t0) * 1000
        allowlisted_latencies.append(elapsed_ms)

    # Benchmark non-allowlisted domains
    non_allowlisted_latencies = []
    for _ in range(30):
        t0 = time.perf_counter()
        res = analyze_single_url("http://192.168.1.1/login-admin-verify-password")
        elapsed_ms = (time.perf_counter() - t0) * 1000
        non_allowlisted_latencies.append(elapsed_ms)

    avg_allow = sum(allowlisted_latencies) / len(allowlisted_latencies)
    min_allow = min(allowlisted_latencies)
    max_allow = max(allowlisted_latencies)

    avg_non = sum(non_allowlisted_latencies) / len(non_allowlisted_latencies)
    min_non = min(non_allowlisted_latencies)
    max_non = max(non_allowlisted_latencies)

    print(f"  Allowlisted Domain Latency (30 iterations):")
    print(f"    Average: {BOLD}{avg_allow:.3f}ms{RESET} (SLA < 2.0ms)")
    print(f"    Min:     {min_allow:.3f}ms")
    print(f"    Max:     {max_allow:.3f}ms")

    print(f"  Non-Allowlisted Domain Latency (30 iterations):")
    print(f"    Average: {BOLD}{avg_non:.3f}ms{RESET} (SLA < 15.0ms)")
    print(f"    Min:     {min_non:.3f}ms")
    print(f"    Max:     {max_non:.3f}ms")

    assert avg_allow < 2.0, f"Allowlisted average latency {avg_allow:.3f}ms exceeded 2.0ms SLA!"
    assert avg_non < 15.0, f"Non-allowlisted average latency {avg_non:.3f}ms exceeded 15.0ms SLA!"

    print(f"  {BOLD}{GREEN}[PASS] Latency SLAs verified: Allowlist < 2ms, Inference < 15ms.{RESET}")


def run_full_suite():
    print(f"\n{BOLD}{'=' * 85}{RESET}")
    print(f"{BOLD} CYBERSEC URL THREAT INSPECTOR - ENTERPRISE TRUST TIER REGRESSION SUITE{RESET}")
    print(f"{CYAN} Validating False Positive Resolution for Bare Domains & Adversarial Invariants{RESET}")
    print(f"{BOLD}{'=' * 85}{RESET}")

    start_total = time.perf_counter()

    test_allowlist_domain_normalization()
    test_top_global_domains_benign()
    test_threat_vectors_zero_bypass()
    test_latency_sla_benchmarks()

    elapsed = (time.perf_counter() - start_total) * 1000
    print(f"\n{BOLD}{'=' * 85}{RESET}")
    print(f"{BOLD}{GREEN} ALL ENTERPRISE TRUST TIER REGRESSION TESTS PASSED (100% SUCCESS) in {elapsed:.1f}ms{RESET}")
    print(f"{BOLD}{'=' * 85}{RESET}\n")


if __name__ == "__main__":
    run_full_suite()
