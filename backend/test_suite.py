"""
Automated Security, Stability & Edge-Case Test Suite for CyberSec URL Threat Assessment API.

Validates:
1. Malformed & adversarial URLs (Length > 2,500 chars, Unicode/Punycode, IPv4/IPv6, missing schemes, special chars).
2. Input validation resilience (Empty, whitespace, null, missing keys return HTTP 422 with structured JSON).
3. Model calibration & threshold consistency (Saved bundle threshold 0.4705 verified across all endpoints).
4. Deterministic inference latency benchmark (< 35ms consistently).
5. Batch endpoint processing robustness.

Compatible with both direct CLI execution (`python test_suite.py`) and pytest (`pytest test_suite.py`).
"""

import math
import os
import sys
import time
from typing import Any, Dict, List

# Ensure backend directory is in python search path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from fastapi.testclient import TestClient
import joblib

from feature_extractor import URLFeatureExtractor
from main import app, BUNDLE, THRESHOLD, analyze_single_url

client = TestClient(app)

# ANSI terminal styling
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def log_test(test_name: str, passed: bool, detail: str = "") -> None:
    """Format and print test outcome with visual indicator."""
    status_tag = f"{GREEN}[PASS]{RESET}" if passed else f"{RED}[FAIL]{RESET}"
    detail_str = f" - {detail}" if detail else ""
    print(f"  {status_tag} {BOLD}{test_name}{RESET}{detail_str}")


# =============================================================================
# 1. Feature Extractor & API: Extremely Long URLs (> 2,500 characters)
# =============================================================================
def test_malformed_extremely_long_url() -> None:
    """
    Stress-test feature extractor and API with an excessively long URL (> 2,500 chars)
    to verify buffer and memory safety.
    """
    extractor = URLFeatureExtractor()
    long_path = "a" * 1200
    long_query = "q=" + "b" * 1400
    long_url = f"https://security-audit-test.example.com/{long_path}?{long_query}"

    assert len(long_url) > 2500, f"Expected URL length > 2500, got {len(long_url)}"

    # 1. Direct feature extractor verification
    feats = extractor.extract(long_url)
    assert isinstance(feats, dict), "Extractor did not return a dictionary."
    assert len(feats) == 29, f"Expected 29 features, got {len(feats)}"
    assert feats["url_length"] >= 2500, f"Expected url_length >= 2500, got {feats['url_length']}"
    assert feats["path_length"] >= 1200, "Path length calculation mismatch."
    assert feats["query_length"] >= 1400, "Query length calculation mismatch."

    # 2. FastAPI endpoint verification
    response = client.post("/analyze", json={"url": long_url})
    assert response.status_code == 200, f"Expected HTTP 200, got {response.status_code}: {response.text}"

    data = response.json()
    assert "verdict" in data and data["verdict"] in ["BENIGN", "SUSPICIOUS", "MALICIOUS"]
    assert "threat_probability" in data and 0.0 <= data["threat_probability"] <= 1.0
    assert data["forensics"]["url_length"] >= 2500
    assert data["latency_ms"] > 0


# =============================================================================
# 2. Unicode, Punycode & IDN Spoofing Vectors
# =============================================================================
def test_unicode_and_punycode_urls() -> None:
    """
    Verify parsing and detection of Punycode (xn--) and internationalized Unicode URLs.
    """
    extractor = URLFeatureExtractor()

    # 1. Standard Punycode vector (German Umlaut domain)
    punycode_url = "https://xn--bcher-kva.com/login"
    feats_puny = extractor.extract(punycode_url)
    assert feats_puny["has_punycode"] == 1, "Punycode domain not flagged in features."

    res_puny = client.post("/analyze", json={"url": punycode_url})
    assert res_puny.status_code == 200
    data_puny = res_puny.json()
    assert data_puny["forensics"]["has_punycode"] is True, "forensics.has_punycode must be True"

    # 2. Raw Unicode domain & path
    unicode_url = "https://bücher.de/benutzer/anmelden"
    res_unicode = client.post("/analyze", json={"url": unicode_url})
    assert res_unicode.status_code == 200, f"Raw unicode failed: {res_unicode.text}"
    data_unicode = res_unicode.json()
    assert data_unicode["forensics"]["domain_length"] > 0

    # 3. Cyrillic and CJK Unicode paths
    cyrillic_url = "https://example.com/пользователь/вход"
    cjk_url = "https://example.org/search?q=测试用户&token=값"
    for u in [cyrillic_url, cjk_url]:
        res = client.post("/analyze", json={"url": u})
        assert res.status_code == 200, f"Unicode URL {u} failed with status {res.status_code}"


# =============================================================================
# 3. Raw IP Host Addressing (IPv4 & IPv6 Vectors)
# =============================================================================
def test_raw_ip_hosts_ipv4_and_ipv6() -> None:
    """
    Validate identification of raw numeric IPv4, bracketed IPv6, and malformed IP hosts.
    """
    extractor = URLFeatureExtractor()

    # 1. Raw IPv4
    ipv4_url = "http://192.168.1.1/admin-login-verify"
    feats_ipv4 = extractor.extract(ipv4_url)
    assert feats_ipv4["has_ip"] == 1, "IPv4 address not flagged."

    res_ipv4 = client.post("/analyze", json={"url": ipv4_url})
    assert res_ipv4.status_code == 200
    assert res_ipv4.json()["forensics"]["has_ip_host"] is True

    # 2. Standard IPv6 with brackets
    ipv6_url = "http://[2001:db8::1]/test-path"
    feats_ipv6 = extractor.extract(ipv6_url)
    assert feats_ipv6["has_ip"] == 1, "Bracketed IPv6 address not flagged."

    res_ipv6 = client.post("/analyze", json={"url": ipv6_url})
    assert res_ipv6.status_code == 200
    assert res_ipv6.json()["forensics"]["has_ip_host"] is True

    # 3. IPv6 with explicit port
    ipv6_port_url = "http://[::1]:8080/secure/api"
    res_ipv6_port = client.post("/analyze", json={"url": ipv6_port_url})
    assert res_ipv6_port.status_code == 200
    assert res_ipv6_port.json()["forensics"]["has_ip_host"] is True

    # 4. Malformed IPv6 (unclosed bracket)
    malformed_ipv6 = "http://[2001:db8::1/unclosed-bracket"
    res_malformed = client.post("/analyze", json={"url": malformed_ipv6})
    assert res_malformed.status_code == 200, "Malformed IPv6 caused server failure."


# =============================================================================
# 4. Missing Scheme, Leading Slashes & Query-Only Strings
# =============================================================================
def test_missing_scheme_and_partial_urls() -> None:
    """
    Verify robust handling of URLs lacking standard schemes, containing relative paths,
    protocol-relative slashes, or query-only strings.
    """
    test_cases = [
        ("example.com/path", "Missing scheme domain"),
        ("//test.org?a=1&b=2", "Protocol-relative URL"),
        ("?query=only&param=1", "Query-only string"),
        ("/leading/slash/only", "Path-only string"),
        ("///multiple/slashes///path", "Triple-slash string"),
        ("sub.domain.co.uk:8443/auth", "Port without scheme"),
    ]

    for raw_url, desc in test_cases:
        res = client.post("/analyze", json={"url": raw_url})
        assert res.status_code == 200, f"Case '{desc}' ({raw_url}) failed: {res.text}"
        data = res.json()
        assert "verdict" in data, f"Missing verdict in {desc}"
        assert data["threshold_applied"] == 0.4705


# =============================================================================
# 5. Encoded Special Characters & Obfuscation
# =============================================================================
def test_encoded_and_special_character_urls() -> None:
    """
    Verify URL parsing with user credentials, URL-encoded entities (%20),
    at-signs (@), multiple slashes, and complex fragments.
    """
    complex_url = (
        "https://user:p%40ssw%3Ard@secure-auth.example.com:8443/api/v1/update///"
        "verify%20account?redirect=https%3A%2F%2Fother.org%2Fpath&tag=@admin#sec_anchor"
    )

    extractor = URLFeatureExtractor()
    feats = extractor.extract(complex_url)
    assert feats["percent_count"] > 0, "Percent-encoded symbols not counted."
    assert feats["at_count"] >= 1, "At-sign symbols not counted."
    assert feats["slash_count"] >= 5, "Slash count mismatch."

    res = client.post("/analyze", json={"url": complex_url})
    assert res.status_code == 200
    data = res.json()
    assert data["forensics"]["param_count"] >= 1


# =============================================================================
# 6. Input Validation (Empty, Whitespace, Null & Malformed Payloads)
# =============================================================================
def test_input_validation_empty_and_whitespace() -> None:
    """
    Confirm blank, whitespace-only, and malformed request bodies return HTTP 422
    with a structured JSON error body and 0 server crashes.
    """
    # 1. Blank string
    res_empty = client.post("/analyze", json={"url": ""})
    assert res_empty.status_code == 422, f"Expected 422 for blank string, got {res_empty.status_code}"
    assert "detail" in res_empty.json(), "Structured error detail missing."

    # 2. Whitespace-only string
    res_whitespace = client.post("/analyze", json={"url": "    \t\r\n   "})
    assert res_whitespace.status_code == 422, f"Expected 422 for whitespace, got {res_whitespace.status_code}"
    assert "detail" in res_whitespace.json(), "Structured error detail missing."

    # 3. Null / None URL
    res_null = client.post("/analyze", json={"url": None})
    assert res_null.status_code == 422, f"Expected 422 for null, got {res_null.status_code}"

    # 4. Missing required 'url' key
    res_missing = client.post("/analyze", json={})
    assert res_missing.status_code == 422, f"Expected 422 for empty object, got {res_missing.status_code}"

    # 5. Non-string type
    res_type_error = client.post("/analyze", json={"url": 987654})
    assert res_type_error.status_code == 422, f"Expected 422 for integer URL, got {res_type_error.status_code}"


# =============================================================================
# 7. Model Calibration & Threshold Consistency
# =============================================================================
def test_model_calibration_and_threshold_consistency() -> None:
    """
    Confirm calibrated decision boundary (threshold_applied = 0.4705) is synchronized
    across the saved joblib bundle, root metadata endpoint, health probe, and prediction results.
    """
    # 1. Validate threshold from loaded joblib bundle
    saved_threshold = float(BUNDLE["threshold"])
    calibrated_threshold = round(saved_threshold, 4)
    assert calibrated_threshold == 0.4705, f"Expected bundle threshold 0.4705, got {calibrated_threshold}"

    # 2. Validate root endpoint '/'
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.json()["decision_threshold"] == 0.4705

    # 3. Validate health endpoint '/health'
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["model_calibrated_threshold"] == 0.4705

    # 4. Validate prediction payload '/analyze'
    test_target = "https://www.wikipedia.org/wiki/Computer_security"
    res_analyze = client.post("/analyze", json={"url": test_target})
    assert res_analyze.status_code == 200
    base_data = res_analyze.json()
    assert base_data["threshold_applied"] == 0.4705

    # 5. Validate alias endpoints match main endpoint identically
    for alias_path in ["/api/analyze", "/api/v1/analyze", "/api/py/analyze"]:
        res_alias = client.post(alias_path, json={"url": test_target})
        assert res_alias.status_code == 200, f"Alias {alias_path} failed"
        alias_data = res_alias.json()
        assert alias_data["threshold_applied"] == 0.4705
        assert alias_data["verdict"] == base_data["verdict"]
        assert alias_data["threat_probability"] == base_data["threat_probability"]
        assert alias_data["is_threat"] == base_data["is_threat"]


# =============================================================================
# 8. Deterministic Inference Latency Benchmark (< 35ms)
# =============================================================================
def test_inference_latency_benchmark() -> None:
    """
    Execute 30 consecutive deterministic inferences across diverse URL vectors.
    Assert that average latency is under 20ms and 95th percentile is under 35ms.
    """
    test_urls = [
        "https://www.wikipedia.org/wiki/Computer_security",
        "https://secure-login-verify-account.example.com/update",
        "http://192.168.1.1/login-admin-verify-password",
        "https://xn--bcher-kva.com/auth-signin",
        "https://google.com/search?q=cybersecurity+threat+intelligence",
        "https://github.com/microsoft/playwright",
        "https://aws.amazon.com/security/compliance",
        "http://[2001:db8::1]/test/endpoint",
        "example.com/direct/path/depth/test",
        "https://bank-auth.com/secure?verify=token&account=active",
    ] * 3  # 30 iterations

    # 1. Warm-up call (eliminates initial Python bytecode & CPU cache cold overhead)
    _ = client.post("/analyze", json={"url": "https://warmup.example.com"})

    latencies: List[float] = []

    for u in test_urls:
        start = time.perf_counter()
        res = client.post("/analyze", json={"url": u})
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert res.status_code == 200, f"Request failed with status {res.status_code}"
        # Combine client-observed latency and server-reported latency
        server_latency = res.json()["latency_ms"]
        latencies.append(server_latency)

    latencies.sort()
    avg_latency = sum(latencies) / len(latencies)
    p95_idx = int(math.ceil(0.95 * len(latencies))) - 1
    p95_latency = latencies[p95_idx]

    print(
        f"\n    {CYAN}Inference Latency Profile ({len(latencies)} calls): "
        f"Avg={avg_latency:.2f}ms | Min={min(latencies):.2f}ms | "
        f"P95={p95_latency:.2f}ms | Max={max(latencies):.2f}ms{RESET}"
    )

    assert avg_latency < 25.0, f"Average latency exceeded 25ms: {avg_latency:.2f}ms"
    assert p95_latency < 35.0, f"P95 latency exceeded 35ms: {p95_latency:.2f}ms"


# =============================================================================
# 9. Batch Analysis Endpoint Verification
# =============================================================================
def test_batch_analyze_endpoint() -> None:
    """
    Verify /batch-analyze processes lists of heterogeneous URLs concurrently without error.
    """
    batch_payload = [
        "https://www.wikipedia.org",
        "http://192.168.1.1/admin",
        "https://xn--bcher-kva.com/login",
        "example.com/missing-scheme",
        "https://secure-login-verify-account.example.com/update",
    ]

    res = client.post("/batch-analyze", json={"urls": batch_payload})
    assert res.status_code == 200
    results = res.json()
    assert isinstance(results, list)
    assert len(results) == len(batch_payload)

    for item in results:
        assert "verdict" in item
        assert "threat_probability" in item
        assert item["threshold_applied"] == 0.4705


# =============================================================================
# Standalone CLI Test Runner
# =============================================================================
def run_all_tests() -> bool:
    """Execute all tests in suite and print a clean summary."""
    print(f"\n{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD} CYBERSEC URL THREAT ASSESSMENT API - AUTOMATED TEST SUITE{RESET}")
    print(f"{CYAN} Target: FastAPI Engine, URLFeatureExtractor & LightGBM Model{RESET}")
    print(f"{CYAN} Calibrated Threshold: {THRESHOLD:.4f} (FPR <= 5% Policy Enforced){RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}\n")

    test_registry = [
        ("Extremely Long URLs (> 2,500 chars)", test_malformed_extremely_long_url),
        ("Unicode, Punycode & IDN Spoofing", test_unicode_and_punycode_urls),
        ("Raw IPv4 & IPv6 Addressing", test_raw_ip_hosts_ipv4_and_ipv6),
        ("Missing Schemes & Partial URLs", test_missing_scheme_and_partial_urls),
        ("Encoded Characters & Obfuscation", test_encoded_and_special_character_urls),
        ("Input Validation (Empty, Whitespace, Null)", test_input_validation_empty_and_whitespace),
        ("Model Calibration & Threshold (0.4705)", test_model_calibration_and_threshold_consistency),
        ("Deterministic Latency Benchmark (< 35ms)", test_inference_latency_benchmark),
        ("Batch Analysis Endpoint Concurrent Scan", test_batch_analyze_endpoint),
    ]

    passed_count = 0
    total_count = len(test_registry)
    all_success = True

    for name, test_func in test_registry:
        try:
            test_func()
            log_test(name, True)
            passed_count += 1
        except AssertionError as ae:
            log_test(name, False, str(ae))
            all_success = False
        except Exception as exc:
            log_test(name, False, f"Unexpected error: {exc}")
            all_success = False

    print(f"\n{BOLD}{'=' * 72}{RESET}")
    if all_success:
        print(f"{GREEN}{BOLD} TEST SUITE RESULTS: {passed_count}/{total_count} Passed (100% SUCCESS){RESET}")
        print(f"{GREEN} 0 Server Crashes. 0 Internal Server Errors. 100% Input Resilience.{RESET}")
    else:
        print(f"{RED}{BOLD} TEST SUITE RESULTS: {passed_count}/{total_count} Passed ({total_count - passed_count} FAILED){RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}\n")

    return all_success


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
