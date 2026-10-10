"""
Final Release Certification & Regression Test Suite.

Certifies:
1. URL Shortener Detection Heuristics:
   - 'https://bit.ly/secure-login' -> Elevated to SUSPICIOUS, is_shortener: true, obfuscation notice present.
   - 'https://tinyurl.com/xyz123' -> is_shortener: true, elevated risk notice.
2. Canonical Allowlist Integrity:
   - 'https://www.wikipedia.org' -> Remains BENIGN (1.0%, allowlisted).
3. Public Suffix / TLD Gate Integrity:
   - 'https://www.wikipedia' (missing TLD) -> Rejection HTTP 400 INVALID_URL_SYNTAX.
4. Alternative IP Host Canonicalization:
   - 'http://2130706433/login' (dword integer IP) -> Flagged with has_ip_host: true.
5. Multi-test runner confirming 0 regressions across legacy test suites.
"""

import os
import subprocess
import sys
import time

# Ensure backend root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from main import app
from input_classifier import KNOWN_SHORTENERS, classify_input_string

client = TestClient(app)

# Terminal ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def test_url_shortener_heuristics():
    """Assert known shortener URLs are flagged with is_shortener=True, elevated to SUSPICIOUS, with obfuscation notice."""
    print(f"\n{BOLD}{CYAN}>>> 1. Testing URL Shortener Detection Heuristics...{RESET}")

    shortener_vectors = [
        "https://bit.ly/secure-login",
        "https://tinyurl.com/account-verify",
        "https://t.co/safe-link",
        "https://cutt.ly/login-portal",
        "https://is.gd/update",
    ]

    for url in shortener_vectors:
        # Check input classifier
        classification = classify_input_string(url)
        assert classification["is_shortener"] is True, f"Classifier failed for {url}"

        # Check full API response
        resp = client.post("/analyze", json={"url": url})
        assert resp.status_code == 200, f"Expected 200 for {url}, got {resp.status_code}"
        data = resp.json()

        forensics = data.get("forensics", {})
        assert forensics.get("is_shortener") is True, f"Expected is_shortener=True for {url}"
        assert data.get("verdict") in ("SUSPICIOUS", "MALICIOUS"), f"Expected SUSPICIOUS or MALICIOUS for {url}, got {data.get('verdict')}"
        assert data.get("threat_probability") >= 0.52, f"Expected threat_probability >= 0.52 for {url}, got {data.get('threat_probability')}"
        assert "URL shortener service detected" in (data.get("risk_summary") or ""), (
            f"Expected obfuscation risk summary for {url}, got {data.get('risk_summary')}"
        )

        print(
            f"  {GREEN}[PASS]{RESET} {BOLD}{url}{RESET} -> "
            f"Verdict: {YELLOW}{data.get('verdict')}{RESET} ({data.get('threat_probability')*100:.1f}%), "
            f"is_shortener: {forensics.get('is_shortener')}"
        )


def test_wikipedia_allowlist():
    """Assert https://www.wikipedia.org remains BENIGN (1.0%, allowlisted)."""
    print(f"\n{BOLD}{CYAN}>>> 2. Testing Wikipedia Allowlist Baseline...{RESET}")

    url = "https://www.wikipedia.org"
    resp = client.post("/analyze", json={"url": url})
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()

    assert data.get("verdict") == "BENIGN", f"Expected BENIGN, got {data.get('verdict')}"
    assert data.get("threat_probability") == 0.01, f"Expected 0.01, got {data.get('threat_probability')}"
    assert data.get("forensics", {}).get("is_allowlisted") is True, "Expected is_allowlisted=True"
    assert data.get("forensics", {}).get("is_shortener") is False, "Expected is_shortener=False"

    print(
        f"  {GREEN}[PASS]{RESET} {BOLD}{url}{RESET} -> "
        f"Verdict: {GREEN}{data.get('verdict')}{RESET} ({data.get('threat_probability')*100:.1f}%), "
        f"Allowlisted: {data.get('forensics', {}).get('is_allowlisted')}"
    )


def test_missing_tld_rejection():
    """Assert https://www.wikipedia (missing TLD) returns HTTP 400 INVALID_URL_SYNTAX."""
    print(f"\n{BOLD}{CYAN}>>> 3. Testing Missing TLD Syntax Rejection...{RESET}")

    url = "https://www.wikipedia"
    resp = client.post("/analyze", json={"url": url})
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"
    data = resp.json()

    detail = data.get("detail", {})
    assert detail.get("error_type") == "INVALID_URL_SYNTAX", f"Expected INVALID_URL_SYNTAX, got {detail.get('error_type')}"
    assert "top-level domain" in detail.get("message", "").lower(), f"Unexpected message: {detail.get('message')}"

    print(
        f"  {GREEN}[PASS]{RESET} {BOLD}{url}{RESET} -> "
        f"HTTP {resp.status_code} {RED}{detail.get('error_type')}{RESET}: {detail.get('message')}"
    )


def test_dword_ip_host():
    """Assert http://2130706433/login (dword IP) is canonicalized with has_ip_host: true."""
    print(f"\n{BOLD}{CYAN}>>> 4. Testing Alternative Dword IP Host Canonicalization...{RESET}")

    url = "http://2130706433/login"
    resp = client.post("/analyze", json={"url": url})
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()

    forensics = data.get("forensics", {})
    assert forensics.get("has_ip_host") is True, f"Expected has_ip_host=True for {url}"

    print(
        f"  {GREEN}[PASS]{RESET} {BOLD}{url}{RESET} -> "
        f"Verdict: {data.get('verdict')}, has_ip_host: {forensics.get('has_ip_host')}"
    )


def run_legacy_suites():
    """Execute all preceding regression test suites to guarantee 0 regressions."""
    print(f"\n{BOLD}{CYAN}>>> 5. Running Full Regression Test Battery...{RESET}")

    suites = [
        ("test_suite.py", "Core ML & API Test Suite"),
        ("test_edge_hardening.py", "Edge Hardening & Multi-Tenant Isolation Suite"),
        ("test_path_debiasing.py", "Path Length Debiasing & Allowlist Suite"),
    ]

    python_executable = sys.executable

    for filename, suite_name in suites:
        file_path = os.path.join(BASE_DIR, filename)
        if not os.path.exists(file_path):
            print(f"  {YELLOW}[SKIP]{RESET} {suite_name} ({filename} not found)")
            continue

        print(f"\n  {BOLD}Executing {suite_name} ({filename})...{RESET}")
        result = subprocess.run(
            [python_executable, file_path],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            print(f"  {GREEN}[PASS]{RESET} {suite_name} completed successfully.")
        else:
            print(f"  {RED}[FAIL]{RESET} {suite_name} failed with return code {result.returncode}!")
            print("--- STDOUT ---")
            print(result.stdout)
            print("--- STDERR ---")
            print(result.stderr)
            sys.exit(result.returncode)


def main():
    print(f"{BOLD}{GREEN}===================================================================={RESET}")
    print(f"{BOLD}{GREEN}    PHASE 4: FINAL RELEASE CERTIFICATION & REGRESSION SUITE        {RESET}")
    print(f"{BOLD}{GREEN}===================================================================={RESET}")

    test_url_shortener_heuristics()
    test_wikipedia_allowlist()
    test_missing_tld_rejection()
    test_dword_ip_host()
    run_legacy_suites()

    print(f"\n{BOLD}{GREEN}===================================================================={RESET}")
    print(f"{BOLD}{GREEN}    ALL RELEASE CERTIFICATION TESTS & BATTERIES PASSED (100%)       {RESET}")
    print(f"{BOLD}{GREEN}===================================================================={RESET}\n")


if __name__ == "__main__":
    main()
