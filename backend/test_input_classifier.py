"""
Automated Verification Suite for Upfront Input Classification Gateway.

Validates:
1. Syntactic classification of:
   - PLAIN_TEXT: 'paypal login', 'facebook login', '12345', 'test string' -> HTTP 400 INVALID_URL_SYNTAX.
   - DANGEROUS_SCHEME: 'javascript:alert(1)', 'data:...', 'file:...' -> MALICIOUS (99%), dangerous_protocol=True.
   - INTERNAL_HOST: 'http://localhost:8000', 'localhost', '127.0.0.1' -> INTERNAL_TARGET (10%), is_threat=False.
   - VALID_URL: 'https://www.wikipedia.org', 'example.com/path' -> Normal ML/Allowlist Pipeline.
2. Resilience against arbitrary malformed/unicode strings without 500 server crashes.
"""

import os
import sys
import time

# Ensure backend root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from main import app
from input_classifier import InputCategory, classify_input_string

client = TestClient(app)

# Terminal ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def test_classifier_unit_taxonomy():
    """Verify raw classify_input_string taxonomic assignments."""
    print(f"\n{BOLD}{CYAN}>>> 1. Testing classify_input_string() Taxonomic Precision...{RESET}")

    test_vectors = [
        # PLAIN_TEXT
        ("paypal login", InputCategory.PLAIN_TEXT),
        ("facebook login", InputCategory.PLAIN_TEXT),
        ("login to paypal", InputCategory.PLAIN_TEXT),
        ("test string", InputCategory.PLAIN_TEXT),
        ("12345", InputCategory.PLAIN_TEXT),
        ("justaword", InputCategory.PLAIN_TEXT),
        ("search query without dot", InputCategory.PLAIN_TEXT),

        # DANGEROUS_SCHEME
        ("javascript:alert(1)", InputCategory.DANGEROUS_SCHEME),
        ("JAVASCRIPT:alert(document.cookie)", InputCategory.DANGEROUS_SCHEME),
        ("data:text/html;base64,PHNjcmlwdD4=", InputCategory.DANGEROUS_SCHEME),
        ("file:///etc/passwd", InputCategory.DANGEROUS_SCHEME),
        ("blob:http://example.com/uuid", InputCategory.DANGEROUS_SCHEME),
        ("vbscript:msgbox(1)", InputCategory.DANGEROUS_SCHEME),

        # INTERNAL_HOST
        ("http://localhost:8000", InputCategory.INTERNAL_HOST),
        ("http://localhost", InputCategory.INTERNAL_HOST),
        ("localhost", InputCategory.INTERNAL_HOST),
        ("http://127.0.0.1:8000", InputCategory.INTERNAL_HOST),
        ("http://127.0.0.1", InputCategory.INTERNAL_HOST),
        ("127.0.0.1:3000", InputCategory.INTERNAL_HOST),
        ("http://[::1]:8080", InputCategory.INTERNAL_HOST),
        ("http://169.254.169.254/latest/meta-data", InputCategory.INTERNAL_HOST),
        ("http://10.0.0.1:8080", InputCategory.INTERNAL_HOST),

        # VALID_URL
        ("https://www.wikipedia.org", InputCategory.VALID_URL),
        ("https://wikipedia.org", InputCategory.VALID_URL),
        ("https://google.com/search?q=test", InputCategory.VALID_URL),
        ("example.com/path", InputCategory.VALID_URL),
        ("http://192.168.1.1/login-admin-verify-password", InputCategory.VALID_URL),
        ("//test.org?a=1&b=2", InputCategory.VALID_URL),
        ("sub.domain.co.uk:8443/auth", InputCategory.VALID_URL),
    ]

    for raw, expected_cat in test_vectors:
        res = classify_input_string(raw)
        actual_cat = res["category"]
        assert actual_cat == expected_cat, (
            f"Taxonomy mismatch for '{raw}': expected {expected_cat}, got {actual_cat}"
        )
        print(f"  {GREEN}[PASS]{RESET} {raw.ljust(48)} -> {actual_cat.value}")

    print(f"  {BOLD}{GREEN}[PASS] All {len(test_vectors)} taxonomic unit assertions passed.{RESET}")


def test_api_plain_text_gateway():
    """Verify 'paypal login' & plain text queries return HTTP 400 with structured INVALID_URL_SYNTAX."""
    print(f"\n{BOLD}{CYAN}>>> 2. Testing API Gateway: Plain-Text Search Queries (HTTP 400)...{RESET}")

    plain_cases = [
        "paypal login",
        "facebook login",
        "login to paypal",
        "12345",
        "test string query",
    ]

    for query in plain_cases:
        resp = client.post("/analyze", json={"url": query})
        assert resp.status_code == 400, (
            f"Expected HTTP 400 for '{query}', got {resp.status_code}: {resp.text}"
        )
        data = resp.json()
        assert "detail" in data, f"Missing 'detail' in 400 response: {data}"
        detail = data["detail"]
        assert isinstance(detail, dict), f"Expected dict detail, got {type(detail)}"
        assert detail.get("error_type") == "INVALID_URL_SYNTAX", (
            f"Expected error_type 'INVALID_URL_SYNTAX', got {detail.get('error_type')}"
        )
        assert "message" in detail and len(detail["message"]) > 10
        print(f"  {GREEN}[PASS]{RESET} '{query}' -> HTTP 400: [{detail['error_type']}] {detail['message'][:45]}...")

    print(f"  {BOLD}{GREEN}[PASS] Plain text gateway verified with structured 400 responses.{RESET}")


def test_api_dangerous_scheme_gateway():
    """Verify executable/dangerous URI schemes are flagged as MALICIOUS (99%)."""
    print(f"\n{BOLD}{CYAN}>>> 3. Testing API Gateway: Dangerous Schemes (MALICIOUS 99%)...{RESET}")

    dangerous_cases = [
        ("javascript:alert(1)", "javascript"),
        ("data:text/html;base64,PHNjcmlwdD4=", "data"),
        ("file:///etc/passwd", "file"),
        ("blob:http://example.com/550e8400", "blob"),
        ("vbscript:msgbox(1)", "vbscript"),
    ]

    for uri, scheme in dangerous_cases:
        resp = client.post("/analyze", json={"url": uri})
        assert resp.status_code == 200, f"Expected HTTP 200 for dangerous scheme, got {resp.status_code}"
        data = resp.json()

        assert data["verdict"] == "MALICIOUS", f"Expected MALICIOUS for {uri}, got {data['verdict']}"
        assert data["threat_probability"] >= 0.99, f"Expected >= 0.99 threat_prob for {uri}, got {data['threat_probability']}"
        assert data["is_threat"] is True
        assert data["forensics"]["dangerous_protocol"] is True
        assert "risk_summary" in data and "High-risk executable URI scheme" in data["risk_summary"]

        print(
            f"  {GREEN}[PASS]{RESET} {uri.ljust(40)} -> "
            f"Verdict: {RED}{data['verdict']}{RESET} | Score: {data['threat_probability']*100:.1f}% | "
            f"dangerous_protocol={data['forensics']['dangerous_protocol']}"
        )

    print(f"  {BOLD}{GREEN}[PASS] Dangerous scheme gateway verified.{RESET}")


def test_api_internal_host_gateway():
    """Verify 'http://localhost:8000' and internal targets resolve to INTERNAL_TARGET (10%)."""
    print(f"\n{BOLD}{CYAN}>>> 4. Testing API Gateway: Internal Targets (INTERNAL_TARGET 10%)...{RESET}")

    internal_cases = [
        "http://localhost:8000",
        "http://localhost",
        "http://127.0.0.1:8000",
        "http://[::1]:8080",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1:8080",
    ]

    for target in internal_cases:
        resp = client.post("/analyze", json={"url": target})
        assert resp.status_code == 200, f"Expected HTTP 200 for internal host, got {resp.status_code}"
        data = resp.json()

        assert data["verdict"] == "INTERNAL_TARGET", (
            f"Expected INTERNAL_TARGET for {target}, got {data['verdict']}"
        )
        assert data["threat_probability"] == 0.10, (
            f"Expected 0.10 probability for {target}, got {data['threat_probability']}"
        )
        assert data["is_threat"] is False
        assert data["forensics"]["dangerous_protocol"] is False
        assert "risk_summary" in data and "Private/Loopback infrastructure target" in data["risk_summary"]

        print(
            f"  {GREEN}[PASS]{RESET} {target.ljust(45)} -> "
            f"Verdict: {CYAN}{data['verdict']}{RESET} | Score: {data['threat_probability']*100:.1f}% | "
            f"is_threat={data['is_threat']}"
        )

    print(f"  {BOLD}{GREEN}[PASS] Internal target gateway verified.{RESET}")


def test_api_malformed_unicode_resilience():
    """Verify arbitrary unicode and malformed inputs never trigger 500 server crashes."""
    print(f"\n{BOLD}{CYAN}>>> 5. Testing Malformed & Arbitrary Unicode Resilience (Zero Crashes)...{RESET}")

    edge_cases = [
        "🔥💥🚀🎉",
        "https://\u2603.net",
        "http://[unclosed-bracket/path",
        "http://user:pass@host:99999/path",
        "///multiple/slashes/only",
        "?query=only",
        "/relative/path/only",
        "javascript:/*%00*/alert(1)",
        "   leading and trailing spaces with domain.com   ",
    ]

    for raw in edge_cases:
        resp = client.post("/analyze", json={"url": raw})
        assert resp.status_code in [200, 400, 422], (
            f"Server crashed with {resp.status_code} for input: '{raw}'"
        )
        safe_label = raw[:40].encode("ascii", "backslashreplace").decode("ascii")
        print(f"  {GREEN}[PASS]{RESET} '{safe_label}' -> HTTP {resp.status_code} (Graceful Handle)")

    print(f"  {BOLD}{GREEN}[PASS] Zero 500 crashes on arbitrary/malformed inputs.{RESET}")


def run_all_gateway_tests():
    print(f"\n{BOLD}{'=' * 90}{RESET}")
    print(f"{BOLD} CYBERSEC URL THREAT INSPECTOR - INPUT CLASSIFICATION GATEWAY SUITE{RESET}")
    print(f"{CYAN} Validating Plain-Text Detection, Dangerous Schemes, and Internal Targets{RESET}")
    print(f"{BOLD}{'=' * 90}{RESET}")

    t0 = time.perf_counter()

    test_classifier_unit_taxonomy()
    test_api_plain_text_gateway()
    test_api_dangerous_scheme_gateway()
    test_api_internal_host_gateway()
    test_api_malformed_unicode_resilience()

    elapsed = (time.perf_counter() - t0) * 1000
    print(f"\n{BOLD}{'=' * 90}{RESET}")
    print(f"{BOLD}{GREEN} ALL INPUT GATEWAY ASSERTIONS SATISFIED (100% SUCCESS) in {elapsed:.1f}ms{RESET}")
    print(f"{BOLD}{'=' * 90}{RESET}\n")


if __name__ == "__main__":
    run_all_gateway_tests()
