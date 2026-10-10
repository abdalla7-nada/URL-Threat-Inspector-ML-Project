"""
Automated API Integration, Concurrency Stress & Input Resilience Test Runner.

Phase 2 Test Suite for CyberSec URL Threat Assessment API:
1. Input Sanitization & Error Handling:
   - Empty JSON payload {} -> HTTP 422
   - Whitespace string {"url": "   "} -> HTTP 422
   - Invalid data types {"url": 12345} or {"url": null} -> HTTP 422
   - XSS / Injection string {"url": "<script>alert(1)</script>"} -> Safe parse, 0 crashes (HTTP 200/422)
   - Malformed scheme {"url": "http://[unclosed-bracket/path"} -> Graceful parse, 0 unhandled exceptions
2. Contract & Schema Verification:
   - GET /health -> status == 'HEALTHY', model_calibrated_threshold == 0.4705
   - POST /analyze and POST /api/analyze -> identical schema:
     ['url', 'verdict', 'is_threat', 'threat_probability', 'threshold_applied', 'latency_ms', 'forensics']
   - Forensics fields (10 metrics) and type integrity validation
3. Concurrency & High Load Stress Simulation:
   - 50 concurrent requests using concurrent.futures.ThreadPoolExecutor
   - Heterogeneous mix of Benign, Malicious, Long & Evasion URLs
   - Latency statistics (Mean, P50, P95, P99, Max)
   - Assertions: 0 HTTP 500 errors, P95 latency < 35ms, immutable threshold 0.4705
4. Structured Reporting:
   - Formatted console executive summary
   - JSON output saved to backend/qa_api_stress_report.json
"""

import concurrent.futures
import json
import math
import os
import sys
import time
from typing import Any, Dict, List, Tuple

# Ensure backend directory is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from fastapi.testclient import TestClient
from main import app, THRESHOLD

client = TestClient(app)

# ANSI terminal styling tokens
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"

REPORT_PATH = os.path.join(CURRENT_DIR, "qa_api_stress_report.json")


# =============================================================================
# Benchmark Datasets for Concurrency Stress
# =============================================================================
CONCURRENT_TEST_URLS: List[str] = [
    # Benign Enterprise
    "https://aws.amazon.com/s3/pricing/?nc2=h_ql_pr_s3#Amazon_S3_pricing",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization",
    "https://images.unsplash.com/photo-1579546929518-9e396f3cc809?auto=format&fit=crop&w=1920&q=80",
    "https://github.com/torvalds/linux/commit/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
    "https://en.wikipedia.org/wiki/Portal:Current_events",
    # Classic Phishing & Lures
    "http://192.168.1.105/secure-banking/update-wallet-verification.php",
    "http://paypal-verification-center-update.com/signin/account-review",
    "http://login.microsoftonline.com.security-auth-check.xyz/login.srf",
    "http://appleid.apple.com.manage-verify-profile.cc/id/login",
    "http://blockchain-wallet-restore-privatekey.top/restore",
    # Obfuscation & Evasion Vectors
    "https://xn--bcher-kva.example.com/login",
    "http://secure.bank@phishing-target.net/verify",
    "https://accounts.google.com-recovery-portal-2026.net/identity",
    "http://10.0.0.1:8080/path///extra//slashes/update",
    "https://netflix-subscription-renew-account-update-billing-profile.site",
    # Long, Scheme-less & Stress Vectors
    "https://test.com/" + ("sub/path/" * 25) + "?param=" + ("abc" * 25),
    "//raw-scheme-less-target.com/path",
    "domain-with-no-protocol.org/test-page",
    "https://user:password@domain.com:8443/auth?token=123#section",
    "http://[::1]/ipv6-localhost-test",
]


# =============================================================================
# Scenario 1: Input Sanitization & Error Handling
# =============================================================================
def test_input_sanitization() -> List[Dict[str, Any]]:
    """Test malformed inputs, injections, boundary types, and error handling."""
    results: List[Dict[str, Any]] = []

    test_cases: List[Dict[str, Any]] = [
        {
            "name": "Empty JSON Payload",
            "payload": {},
            "expected_status": [422],
            "description": "Assert HTTP 422 for missing required 'url' field.",
        },
        {
            "name": "Whitespace-Only String",
            "payload": {"url": "     "},
            "expected_status": [422],
            "description": "Assert HTTP 422 for whitespace string.",
        },
        {
            "name": "Invalid Integer Type",
            "payload": {"url": 12345},
            "expected_status": [422],
            "description": "Assert HTTP 422 when non-string type is provided.",
        },
        {
            "name": "Explicit Null URL",
            "payload": {"url": None},
            "expected_status": [422],
            "description": "Assert HTTP 422 when url is null.",
        },
        {
            "name": "XSS / Script Tag Injection",
            "payload": {"url": "<script>alert(1)</script>"},
            "expected_status": [200, 400, 422],
            "description": "Assert safe parse without 500 server crash or unhandled exception.",
        },
        {
            "name": "Malformed IPv6 Scheme (Unclosed Bracket)",
            "payload": {"url": "http://[unclosed-bracket/path"},
            "expected_status": [200, 400, 422],
            "description": "Assert graceful normalization without regex or parser crash.",
        },
    ]

    for tc in test_cases:
        t0 = time.perf_counter()
        resp = client.post("/analyze", json=tc["payload"])
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        status_code = resp.status_code
        passed = status_code in tc["expected_status"]
        assert passed, (
            f"Sanitization Failed for '{tc['name']}': Expected {tc['expected_status']}, "
            f"got {status_code}. Response: {resp.text}"
        )

        results.append({
            "test_case": tc["name"],
            "description": tc["description"],
            "status_code": status_code,
            "passed": passed,
            "latency_ms": elapsed_ms,
            "response_snippet": resp.text[:120],
        })

    return results


# =============================================================================
# Scenario 2: Contract & Schema Verification
# =============================================================================
def test_contract_and_schema() -> Dict[str, Any]:
    """Verify OpenAPI contracts, schema parity, and forensic field typings."""
    checkpoints: List[Dict[str, Any]] = []

    # 1. Health Probe Verification
    health_resp = client.get("/health")
    assert health_resp.status_code == 200, f"Health check failed with {health_resp.status_code}"
    health_data = health_resp.json()
    assert health_data.get("status") == "HEALTHY", f"Expected 'HEALTHY', got {health_data.get('status')}"
    assert health_data.get("model_calibrated_threshold") == 0.4705, (
        f"Expected calibrated threshold 0.4705, got {health_data.get('model_calibrated_threshold')}"
    )
    checkpoints.append({
        "check": "GET /health Verification",
        "passed": True,
        "detail": f"Status='HEALTHY', Threshold={health_data.get('model_calibrated_threshold')}",
    })

    # 2. Main vs Alias Contract Parity (/analyze vs /api/analyze)
    sample_url = "https://aws.amazon.com/s3/pricing/?nc2=h_ql_pr_s3#Amazon_S3_pricing"
    r_main = client.post("/analyze", json={"url": sample_url})
    r_alias = client.post("/api/analyze", json={"url": sample_url})

    assert r_main.status_code == 200, f"/analyze failed with {r_main.status_code}"
    assert r_alias.status_code == 200, f"/api/analyze failed with {r_alias.status_code}"

    d_main = r_main.json()
    d_alias = r_alias.json()

    # Required top-level keys
    required_keys = [
        "url",
        "verdict",
        "is_threat",
        "threat_probability",
        "threshold_applied",
        "latency_ms",
        "forensics",
    ]
    for k in required_keys:
        assert k in d_main, f"Missing '{k}' in /analyze response"
        assert k in d_alias, f"Missing '{k}' in /api/analyze response"

    # Verify identical core outputs
    assert d_main["verdict"] == d_alias["verdict"], "Verdict mismatch between /analyze and /api/analyze"
    assert d_main["is_threat"] == d_alias["is_threat"], "is_threat mismatch between aliases"
    assert d_main["threat_probability"] == d_alias["threat_probability"], "threat_probability mismatch"
    assert d_main["threshold_applied"] == 0.4705, f"Threshold applied is {d_main['threshold_applied']}"

    checkpoints.append({
        "check": "Contract Parity (/analyze vs /api/analyze)",
        "passed": True,
        "detail": f"Identical schemas validated across 7 core fields. Verdict='{d_main['verdict']}'",
    })

    # 3. Forensic Schema & Data Type Integrity (10 fields)
    forensics = d_main["forensics"]
    type_specs = {
        "url_length": int,
        "domain_length": int,
        "path_depth": int,
        "param_count": int,
        "digit_ratio": float,
        "has_ip_host": bool,
        "has_punycode": bool,
        "host_entropy": float,
        "suspicious_keywords_count": int,
        "tld": str,
    }

    assert len(type_specs) == 10, "Expected 10 forensic fields in specification."

    forensic_details = {}
    for field_name, expected_type in type_specs.items():
        assert field_name in forensics, f"Forensics missing field '{field_name}'"
        val = forensics[field_name]
        # In JSON boolean is not float/int, but in Python bool is subclass of int.
        # Strict validation:
        if expected_type is bool:
            assert isinstance(val, bool), f"Field '{field_name}' expected bool, got {type(val)}"
        elif expected_type is float:
            assert isinstance(val, (float, int)), f"Field '{field_name}' expected float, got {type(val)}"
        elif expected_type is int:
            assert isinstance(val, int) and not isinstance(val, bool), (
                f"Field '{field_name}' expected int, got {type(val)}"
            )
        elif expected_type is str:
            assert isinstance(val, str), f"Field '{field_name}' expected str, got {type(val)}"
        forensic_details[field_name] = f"{type(val).__name__} (val={val})"

    checkpoints.append({
        "check": "Forensic Structural Integrity (10 Fields)",
        "passed": True,
        "detail": f"All 10 forensic fields strictly typed: {list(type_specs.keys())}",
    })

    return {
        "status": "PASSED",
        "checkpoints": checkpoints,
        "forensic_type_mapping": forensic_details,
    }


# =============================================================================
# Scenario 3: Concurrency & High Load Stress Simulation
# =============================================================================
def test_concurrency_stress(
    num_requests: int = 50,
    max_workers: int = 5,
) -> Dict[str, Any]:
    """
    Stress-test API concurrently with 50 heterogeneous requests using ThreadPoolExecutor.
    Enforces SLA: P95 latency < 35ms, 0 HTTP 500 errors, immutable threshold.
    """
    # Pre-flight warm-up to ensure CPU caches and runtime are primed
    client.get("/health")
    client.post("/analyze", json={"url": "https://warmup-initialization.example.com"})

    # Prepare heterogeneous request list
    url_stream: List[str] = []
    while len(url_stream) < num_requests:
        url_stream.extend(CONCURRENT_TEST_URLS)
    url_stream = url_stream[:num_requests]

    def _execute_single_request(url_item: str) -> Dict[str, Any]:
        t0 = time.perf_counter()
        resp = client.post("/analyze", json={"url": url_item})
        wall_time_ms = round((time.perf_counter() - t0) * 1000, 2)

        status_code = resp.status_code
        data = resp.json() if status_code == 200 else {}

        return {
            "url": url_item[:60],
            "status_code": status_code,
            "wall_latency_ms": wall_time_ms,
            "server_latency_ms": data.get("latency_ms", wall_time_ms),
            "threshold_applied": data.get("threshold_applied"),
            "verdict": data.get("verdict"),
            "is_threat": data.get("is_threat"),
            "threat_probability": data.get("threat_probability"),
        }

    stress_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        completed_results = list(executor.map(_execute_single_request, url_stream))
    total_stress_time_ms = round((time.perf_counter() - stress_start) * 1000, 2)

    # 1. Assertions on status codes
    status_counts = {}
    for r in completed_results:
        sc = r["status_code"]
        status_counts[sc] = status_counts.get(sc, 0) + 1

    assert status_counts.get(500, 0) == 0, (
        f"Critical Failure: Encountered {status_counts.get(500)} HTTP 500 errors during stress!"
    )
    assert status_counts.get(200, 0) == num_requests, (
        f"Not all requests succeeded: {status_counts}"
    )

    # 2. Assertions on threshold immutability
    thresholds = [r["threshold_applied"] for r in completed_results]
    assert all(t == 0.4705 for t in thresholds), (
        f"Threshold mutated during concurrency: set of thresholds = {set(thresholds)}"
    )

    # 3. Latency Statistics Calculation (Server-side execution time)
    server_latencies = sorted([r["server_latency_ms"] for r in completed_results])
    wall_latencies = sorted([r["wall_latency_ms"] for r in completed_results])

    def calc_percentiles(vals: List[float]) -> Dict[str, float]:
        n = len(vals)
        return {
            "mean": round(float(sum(vals) / n), 2),
            "p50": round(float(vals[int(n * 0.50)]), 2),
            "p95": round(float(vals[min(int(math.ceil(n * 0.95)) - 1, n - 1)]), 2),
            "p99": round(float(vals[min(int(math.ceil(n * 0.99)) - 1, n - 1)]), 2),
            "max": round(float(max(vals)), 2),
            "min": round(float(min(vals)), 2),
        }

    srv_stats = calc_percentiles(server_latencies)
    wall_stats = calc_percentiles(wall_latencies)

    # Criterion: P95 latency strictly < 35ms
    assert srv_stats["p95"] < 35.0, (
        f"SLA Violation: Server P95 latency {srv_stats['p95']}ms exceeded 35.0ms threshold!"
    )

    return {
        "status": "PASSED",
        "total_requests": num_requests,
        "concurrency_workers": max_workers,
        "total_execution_time_ms": total_stress_time_ms,
        "throughput_rps": round((num_requests / (total_stress_time_ms / 1000)), 1),
        "status_distribution": status_counts,
        "server_latency_stats": srv_stats,
        "wall_latency_stats": wall_stats,
        "threshold_verified": 0.4705,
        "sample_verdicts": {
            "benign_count": sum(1 for r in completed_results if r["verdict"] == "BENIGN"),
            "suspicious_count": sum(1 for r in completed_results if r["verdict"] == "SUSPICIOUS"),
            "malicious_count": sum(1 for r in completed_results if r["verdict"] == "MALICIOUS"),
        },
    }


# =============================================================================
# Formatted Reporting & Orchestration
# =============================================================================
def print_console_report(
    sanitization_res: List[Dict[str, Any]],
    schema_res: Dict[str, Any],
    stress_res: Dict[str, Any],
) -> None:
    """Render an executive terminal dashboard."""
    print(f"\n{BOLD}{'=' * 95}{RESET}")
    print(f"{BOLD} CYBERSEC URL THREAT ASSESSMENT API - AUTOMATED QA INTEGRATION & STRESS REPORT{RESET}")
    print(f"{CYAN} Target: FastAPI Engine (`backend/main.py`) | Model Threshold: {THRESHOLD:.4f}{RESET}")
    print(f"{BOLD}{'=' * 95}{RESET}\n")

    # Section 1: Input Sanitization
    print(f"{BOLD}>>> SCENARIO 1: INPUT SANITIZATION & ERROR RESILIENCE{RESET}")
    print(f"{BOLD}{'Test Case':<36} {'Status':<10} {'Latency':<10} {'Outcome'}{RESET}")
    print(f"{DIM}{'-' * 95}{RESET}")
    for item in sanitization_res:
        tag = f"{GREEN}[PASS]{RESET}" if item["passed"] else f"{RED}[FAIL]{RESET}"
        print(
            f"  {item['test_case']:<34} HTTP {item['status_code']:<5} "
            f"{item['latency_ms']:>6.2f}ms   {tag} {DIM}{item['description']}{RESET}"
        )

    # Section 2: Schema & Contracts
    print(f"\n{BOLD}>>> SCENARIO 2: CONTRACT & FORENSIC SCHEMA INTEGRITY{RESET}")
    print(f"{DIM}{'-' * 95}{RESET}")
    for cp in schema_res["checkpoints"]:
        tag = f"{GREEN}[PASS]{RESET}" if cp["passed"] else f"{RED}[FAIL]{RESET}"
        print(f"  {tag} {BOLD}{cp['check']:<42}{RESET} | {DIM}{cp['detail']}{RESET}")

    # Section 3: Concurrency Stress
    print(f"\n{BOLD}>>> SCENARIO 3: CONCURRENCY STRESS & HIGH LOAD SIMULATION{RESET}")
    print(f"{DIM}{'-' * 95}{RESET}")
    print(
        f"  Total Requests: {BOLD}{stress_res['total_requests']}{RESET} | "
        f"Concurrency Pool: {BOLD}{stress_res['concurrency_workers']} Workers{RESET} | "
        f"Total Time: {BOLD}{stress_res['total_execution_time_ms']}ms{RESET} | "
        f"Throughput: {BOLD}{CYAN}{stress_res['throughput_rps']} Req/sec{RESET}"
    )

    srv = stress_res["server_latency_stats"]
    wall = stress_res["wall_latency_stats"]
    print(f"\n  {BOLD}Server Execution Latency Profile (In-Engine):{RESET}")
    print(
        f"    Mean: {srv['mean']:>5.2f}ms | P50: {srv['p50']:>5.2f}ms | "
        f"P95: {BOLD}{GREEN}{srv['p95']:>5.2f}ms{RESET} (SLA < 35.0ms) | "
        f"P99: {srv['p99']:>5.2f}ms | Max: {srv['max']:>5.2f}ms"
    )
    print(f"  {BOLD}Client Wall-Clock Round-Trip Profile:{RESET}")
    print(
        f"    Mean: {wall['mean']:>5.2f}ms | P50: {wall['p50']:>5.2f}ms | "
        f"P95: {wall['p95']:>5.2f}ms | P99: {wall['p99']:>5.2f}ms | Max: {wall['max']:>5.2f}ms"
    )

    # Assertions summary
    print(f"\n{BOLD}{'=' * 95}{RESET}")
    print(f"{BOLD} CHECKPOINT VERIFICATION & SYSTEM STATUS{RESET}")
    print(f"{BOLD}{'=' * 95}{RESET}")
    print(f"  {GREEN}[PASS]{RESET} 100% Sanitization checks passed (0 Server Crashes).")
    print(f"  {GREEN}[PASS]{RESET} 100% Contract & Forensic schemas verified (10 Fields strictly typed).")
    print(f"  {GREEN}[PASS]{RESET} 0 HTTP 500 Internal Server Errors under concurrent execution.")
    print(f"  {GREEN}[PASS]{RESET} P95 Server Latency ({srv['p95']}ms) strictly below 35ms SLA.")
    print(f"  {GREEN}[PASS]{RESET} Calibrated Decision Threshold (0.4705) immutable across all responses.")
    print(f"\n{GREEN}{BOLD} ALL 4 SCENARIOS SATISFIED. 100% SUCCESS. REPORT EXPORTED TO:{RESET}")
    print(f" {REPORT_PATH}\n")


def main() -> None:
    """Main automated test runner."""
    print(f"\n{CYAN}Initiating Phase 2 Automated API Stress & Resilience Testing...{RESET}")

    # 1. Input Sanitization
    sanitization_results = test_input_sanitization()

    # 2. Contract & Schema Verification
    schema_results = test_contract_and_schema()

    # 3. Concurrency Stress Simulation
    stress_results = test_concurrency_stress(num_requests=50, max_workers=5)

    # Assemble report payload
    report_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_service": "CyberSec URL Threat Assessment API",
        "api_endpoint": "/analyze",
        "calibrated_threshold": 0.4705,
        "scenarios": {
            "input_sanitization": {
                "total_tests": len(sanitization_results),
                "passed": sum(1 for r in sanitization_results if r["passed"]),
                "details": sanitization_results,
            },
            "contract_and_schema": schema_results,
            "concurrency_stress": stress_results,
        },
        "overall_status": "100% SUCCESS",
    }

    # Save to JSON
    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report_data, fh, indent=2)

    # Print executive report
    print_console_report(sanitization_results, schema_results, stress_results)


if __name__ == "__main__":
    main()
