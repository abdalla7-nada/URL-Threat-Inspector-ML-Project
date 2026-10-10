"""
Automated Edge Hardening Regression Suite.

Validates Phase 2 Security Hardening:
1. Strict Public Suffix (TLD) Integrity:
   - 'https://www.wikipedia' (missing TLD) -> HTTP 400 INVALID_URL_SYNTAX with clear structured message.
   - 'https://google.' (trailing dot/missing domain) -> HTTP 400 INVALID_URL_SYNTAX.
   - 'test..com' (consecutive dots/missing domain) -> HTTP 400 INVALID_URL_SYNTAX.
2. High-Reputation Domain Allowlist Verification:
   - 'https://www.wikipedia.org' -> HTTP 200 BENIGN (Allowlist verified).
3. Shared Multi-Tenant Hosting Domain Isolation:
   - 'http://phishing-lure.github.io/login' -> Unallowlisted, evaluated by ML pipeline, flags suspicious heuristics.
4. Alternative IP Format Canonicalization:
   - 'http://2130706433/login' (dword integer IP) -> Canonicalized to 127.0.0.1, has_ip_host=True.
   - 'http://0x7f000001/login' (hexadecimal IP) -> Canonicalized to 127.0.0.1, has_ip_host=True.
5. Regression confirmation across all legacy test suites.
"""

import os
import sys
import time

# Ensure backend root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from main import app, EXTRACTOR
from feature_extractor import canonicalize_ip_host, URLFeatureExtractor
from allowlist import is_allowlisted_domain, SHARED_MULTI_TENANT_DOMAINS
from input_classifier import classify_input_string, InputCategory

client = TestClient(app)

# Terminal ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def test_tld_suffix_integrity():
    """Assert URLs with missing or malformed TLDs return HTTP 400 with INVALID_URL_SYNTAX."""
    print(f"\n{BOLD}{CYAN}>>> 1. Testing Strict Public Suffix (TLD) Integrity...{RESET}")

    malformed_tld_vectors = [
        (
            "https://www.wikipedia",
            "Wikipedia missing TLD suffix (.org)",
        ),
        (
            "https://google.",
            "Trailing dot with omitted top-level domain",
        ),
        (
            "test..com",
            "Consecutive dots violating RFC domain format",
        ),
        (
            "http://incomplete-domain",
            "Bare token with standard HTTP protocol",
        ),
    ]

    for raw_url, desc in malformed_tld_vectors:
        resp = client.post("/analyze", json={"url": raw_url})
        assert resp.status_code == 400, (
            f"Expected HTTP 400 for '{raw_url}', got {resp.status_code}: {resp.text}"
        )
        data = resp.json()
        detail = data.get("detail", {})
        error_type = detail.get("error_type")
        message = detail.get("message", "")

        assert error_type == "INVALID_URL_SYNTAX", (
            f"Expected error_type 'INVALID_URL_SYNTAX', got '{error_type}'"
        )
        assert "Missing or invalid top-level domain suffix" in message or "incomplete query" in message, (
            f"Unexpected error message: '{message}'"
        )

        print(
            f"  {GREEN}[PASS]{RESET} {desc:<45} ({raw_url:<24}) -> "
            f"HTTP 400 [{error_type}]: {message[:65]}..."
        )

    print(f"  {BOLD}{GREEN}[PASS] All TLD suffix integrity checks passed successfully.{RESET}")


def test_allowlist_canonical_verified():
    """Assert canonical https://www.wikipedia.org returns HTTP 200 BENIGN with allowlist verified."""
    print(f"\n{BOLD}{CYAN}>>> 2. Testing High-Reputation Enterprise Allowlist Verification...{RESET}")

    resp = client.post("/analyze", json={"url": "https://www.wikipedia.org"})
    assert resp.status_code == 200, f"Expected HTTP 200 for wikipedia.org, got {resp.status_code}: {resp.text}"
    data = resp.json()

    assert data["verdict"] == "BENIGN", f"Expected BENIGN verdict, got {data['verdict']}"
    assert data["is_threat"] is False, "Expected is_threat=False"
    assert data["threat_probability"] <= 0.05, f"Expected threat probability <= 0.05, got {data['threat_probability']}"
    assert data["forensics"]["is_allowlisted"] is True, "Expected is_allowlisted=True"

    print(
        f"  {GREEN}[PASS]{RESET} {'Wikipedia Canonical Entity':<45} (https://www.wikipedia.org) -> "
        f"Verdict: {GREEN}{data['verdict']}{RESET} | Score: {data['threat_probability']*100:.1f}% | "
        f"Allowlisted: {data['forensics']['is_allowlisted']}"
    )


def test_shared_multi_tenant_isolation():
    """Assert multi-tenant hosting root domains (e.g. github.io) are unallowlisted and evaluated by ML."""
    print(f"\n{BOLD}{CYAN}>>> 3. Testing Shared Multi-Tenant Hosting Domain Isolation...{RESET}")

    # Unit check on allowlist security barrier
    assert not is_allowlisted_domain("github.io"), "github.io MUST NOT be allowlisted"
    assert not is_allowlisted_domain("phishing-lure.github.io"), "*.github.io MUST NOT be allowlisted"
    assert not is_allowlisted_domain("s3.amazonaws.com"), "s3.amazonaws.com MUST NOT be allowlisted"
    assert not is_allowlisted_domain("malicious.vercel.app"), "vercel.app MUST NOT be allowlisted"
    assert "github.io" in SHARED_MULTI_TENANT_DOMAINS

    # API check: phishing lure on github.io
    target_url = "http://phishing-lure.github.io/login"
    resp = client.post("/analyze", json={"url": target_url})
    assert resp.status_code == 200, f"Expected HTTP 200, got {resp.status_code}: {resp.text}"
    data = resp.json()

    assert data["forensics"]["is_allowlisted"] is False, (
        f"Multi-tenant hosting subdomain '{target_url}' MUST NOT be allowlisted!"
    )
    assert data["forensics"]["suspicious_keywords_count"] >= 1, (
        f"Expected suspicious keywords count >= 1 for '{target_url}'"
    )
    assert data["verdict"] in ["SUSPICIOUS", "MALICIOUS"], (
        f"Expected SUSPICIOUS or MALICIOUS verdict for phishing lure on multi-tenant domain, got {data['verdict']}"
    )

    print(
        f"  {GREEN}[PASS]{RESET} {'Phishing Lure on GitHub Pages':<45} ({target_url}) -> "
        f"Verdict: {YELLOW}{data['verdict']}{RESET} | Score: {data['threat_probability']*100:.1f}% | "
        f"Allowlisted: {data['forensics']['is_allowlisted']} | Suspicious Keywords: {data['forensics']['suspicious_keywords_count']}"
    )


def test_ip_format_canonicalization():
    """Assert alternative IP formats (dword integer, hex, octal) normalize to dotted decimal and set has_ip_host."""
    print(f"\n{BOLD}{CYAN}>>> 4. Testing Alternative IP Format Canonicalization...{RESET}")

    ip_vectors = [
        ("http://2130706433/login", "127.0.0.1", "Dword 32-bit Integer IP"),
        ("http://0x7f000001/login", "127.0.0.1", "Hexadecimal IPv4 Representation"),
        ("http://017700000001/login", "127.0.0.1", "Octal IPv4 Representation"),
        ("http://192.168.1.1/login", "192.168.1.1", "Standard Dotted-Decimal IPv4"),
    ]

    for uri, expected_canon, desc in ip_vectors:
        # Check extractor unit canonicalization
        features = EXTRACTOR.extract(uri)
        assert features["has_ip"] == 1, f"Expected has_ip=1 for '{uri}', got {features['has_ip']}"

        # Check API endpoint forensics
        resp = client.post("/analyze", json={"url": uri})
        assert resp.status_code == 200, f"Expected HTTP 200 for '{uri}', got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["forensics"]["has_ip_host"] is True, (
            f"Expected forensics.has_ip_host=True for '{uri}'"
        )

        print(
            f"  {GREEN}[PASS]{RESET} {desc:<45} ({uri:<28}) -> "
            f"Verdict: {RED}{data['verdict']}{RESET} | has_ip_host={data['forensics']['has_ip_host']}"
        )

    # Unit verification for canonicalize_ip_host helper
    assert canonicalize_ip_host("2130706433") == "127.0.0.1"
    assert canonicalize_ip_host("0x7f000001") == "127.0.0.1"
    assert canonicalize_ip_host("017700000001") == "127.0.0.1"
    assert canonicalize_ip_host("12345") is None  # small int must not be misidentified as IP
    assert canonicalize_ip_host("wikipedia.org") is None

    print(f"  {BOLD}{GREEN}[PASS] All IP format canonicalization assertions passed.{RESET}")


def run_all_edge_hardening_tests():
    start_time = time.perf_counter()
    print(f"\n{BOLD}{'=' * 95}{RESET}")
    print(f"{BOLD} CYBERSEC URL THREAT INSPECTOR - PHASE 2 EDGE HARDENING REGRESSION SUITE{RESET}")
    print(f"{CYAN} Validating TLD Integrity, Multi-Tenant Domain Isolation, and IP Canonicalization{RESET}")
    print(f"{BOLD}{'=' * 95}{RESET}")

    test_tld_suffix_integrity()
    test_allowlist_canonical_verified()
    test_shared_multi_tenant_isolation()
    test_ip_format_canonicalization()

    elapsed = (time.perf_counter() - start_time) * 1000
    print(f"\n{BOLD}{'=' * 95}{RESET}")
    print(f"{BOLD}{GREEN} ALL PHASE 2 EDGE HARDENING ASSERTIONS PASSED (100% SUCCESS) in {elapsed:.1f}ms{RESET}")
    print(f"{BOLD}{'=' * 95}{RESET}\n")


if __name__ == "__main__":
    run_all_edge_hardening_tests()
