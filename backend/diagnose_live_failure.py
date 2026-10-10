"""
Forensic Diagnostic Script for Live Production Inspection Engine Failure.

Diagnoses why 'https://xn--bcher-kva.com/auth-signin' resulted in:
'INSPECTION ENGINE ERROR: The inspection backend is initializing (cold start). Please retry in a moment.'
on production https://url-threat-inspector.vercel.app.
"""

import json
import os
import sys
import time
import traceback
import urllib.request
import urllib.error

# Ensure backend root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def print_header(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_1_local_pipeline():
    print_header("TEST 1: Local Python Logic Stress-Test (Punycode & IDN)")
    target_url = "https://xn--bcher-kva.com/auth-signin"
    print(f"Target URL: {target_url}\n")

    try:
        from input_classifier import classify_input_string, InputCategory
        from feature_extractor import URLFeatureExtractor
        from allowlist import is_allowlisted_domain
        import main
        from main import MODEL, FEATURE_NAMES, CATEGORIES, analyze_single_url
        import pandas as pd

        print("[Step 1.1] Executing classify_input_string...")
        classification = classify_input_string(target_url)
        print(f"  -> Result: {classification}")

        print("\n[Step 1.2] Executing URLFeatureExtractor.extract...")
        extractor = URLFeatureExtractor()
        features = extractor.extract(target_url)
        print(f"  -> Extracted {len(features)} features.")
        print(f"  -> has_punycode: {features.get('has_punycode')}")
        print(f"  -> host_entropy: {features.get('host_entropy')}")
        print(f"  -> tld: {features.get('tld')}")
        print(f"  -> domain_name: {features.get('domain_name')}")

        print("\n[Step 1.3] Executing is_allowlisted_domain...")
        domain_info = extractor.extract_domain_info(target_url)
        is_allow = is_allowlisted_domain(domain_info.get("registered_domain", ""))
        print(f"  -> Domain Info: {domain_info}")
        print(f"  -> Allowlisted: {is_allow}")

        print("\n[Step 1.4] Executing Model Inference...")
        df_input = pd.DataFrame([features])[FEATURE_NAMES]
        df_input["tld"] = pd.Categorical(df_input["tld"], categories=CATEGORIES)
        if hasattr(MODEL, "booster_"):
            proba = float(MODEL.booster_.predict(df_input, num_threads=1)[0])
        else:
            proba = float(MODEL.predict_proba(df_input)[0, 1])
        print(f"  -> Threat Probability: {proba:.4f}")

        print("\n[Step 1.5] Executing full analyze_single_url pipeline...")
        full_res = analyze_single_url(target_url)
        print(f"  -> Verdict: {full_res.verdict}")
        print(f"  -> Threat Probability: {full_res.threat_probability}")
        print(f"  -> Forensics: has_punycode={full_res.forensics.has_punycode}, is_shortener={full_res.forensics.is_shortener}")
        print(f"  -> Risk Summary: {full_res.risk_summary}")
        print("\n>>> TEST 1 RESULT: LOCAL PIPELINE PASSED CLEANLY (Zero exceptions)")
        return True, None

    except Exception as e:
        tb = traceback.format_exc()
        print(f"\n>>> TEST 1 FAILED WITH EXCEPTION:\n{tb}")
        return False, tb


def send_http_request(url: str, payload: dict, headers: dict = None, timeout: float = 15.0):
    headers = headers or {}
    data = json.dumps(payload).encode("utf-8")
    headers["Content-Type"] = "application/json"
    headers["User-Agent"] = "CyberSec-Diagnostics/1.0"

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    start_t = time.perf_counter()

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = time.perf_counter() - start_t
            resp_headers = dict(resp.headers)
            body = resp.read().decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "headers": resp_headers,
                "body": body,
                "latency_sec": elapsed,
                "error": None,
            }
    except urllib.error.HTTPError as e:
        elapsed = time.perf_counter() - start_t
        resp_headers = dict(e.headers)
        body = e.read().decode("utf-8", errors="replace")
        return {
            "status": e.code,
            "headers": resp_headers,
            "body": body,
            "latency_sec": elapsed,
            "error": f"HTTPError {e.code}: {e.reason}",
        }
    except Exception as e:
        elapsed = time.perf_counter() - start_t
        return {
            "status": 0,
            "headers": {},
            "body": str(e),
            "latency_sec": elapsed,
            "error": f"{type(e).__name__}: {str(e)}",
        }


def test_2_backend_probes():
    print_header("TEST 2: Direct Probe to Production Backend API")
    backend_url = "https://url-threat-inspector-ml-project.vercel.app/analyze"
    target_url = "https://xn--bcher-kva.com/auth-signin"

    # Probe A: Without X-Internal-Secret
    print("\n--- Probe A: Without X-Internal-Secret ---")
    res_a = send_http_request(backend_url, {"url": target_url})
    print(f"Status Code:    {res_a['status']}")
    print(f"Latency:        {res_a['latency_sec']:.3f}s")
    print(f"Content-Type:   {res_a['headers'].get('content-type', 'N/A')}")
    print(f"x-vercel-error: {res_a['headers'].get('x-vercel-error', 'None')}")
    print(f"Raw Body (first 500 chars):\n{res_a['body'][:500]}")

    # Probe B: With X-Internal-Secret: soc-secure-key-prod
    print("\n--- Probe B: With X-Internal-Secret: soc-secure-key-prod ---")
    res_b = send_http_request(
        backend_url,
        {"url": target_url},
        headers={"X-Internal-Secret": "soc-secure-key-prod"},
    )
    print(f"Status Code:    {res_b['status']}")
    print(f"Latency:        {res_b['latency_sec']:.3f}s")
    print(f"Content-Type:   {res_b['headers'].get('content-type', 'N/A')}")
    print(f"x-vercel-error: {res_b['headers'].get('x-vercel-error', 'None')}")
    print(f"Raw Body (first 500 chars):\n{res_b['body'][:500]}")

    return res_a, res_b


def test_3_proxy_probe():
    print_header("TEST 3: Production Frontend Proxy Probe")
    proxy_url = "https://url-threat-inspector.vercel.app/api/analyze"
    target_url = "https://xn--bcher-kva.com/auth-signin"

    print(f"Sending POST to {proxy_url}...")
    res = send_http_request(proxy_url, {"url": target_url})
    print(f"Status Code:    {res['status']}")
    print(f"Latency:        {res['latency_sec']:.3f}s")
    print(f"Content-Type:   {res['headers'].get('content-type', 'N/A')}")
    print(f"x-vercel-error: {res['headers'].get('x-vercel-error', 'None')}")
    print(f"Raw Body (first 500 chars):\n{res['body'][:500]}")

    return res


def test_4_comparative_control():
    print_header("TEST 4: Comparative Target Benchmark (Control: https://www.wikipedia.org)")
    control_url = "https://www.wikipedia.org"
    backend_url = "https://url-threat-inspector-ml-project.vercel.app/analyze"
    proxy_url = "https://url-threat-inspector.vercel.app/api/analyze"

    print("\n--- Control on Backend with Secret ---")
    res_back = send_http_request(
        backend_url,
        {"url": control_url},
        headers={"X-Internal-Secret": "soc-secure-key-prod"},
    )
    print(f"Backend Status:  {res_back['status']}")
    print(f"Backend Latency: {res_back['latency_sec']:.3f}s")
    print(f"Backend Body:\n{res_back['body'][:300]}")

    print("\n--- Control on Frontend Proxy ---")
    res_proxy = send_http_request(proxy_url, {"url": control_url})
    print(f"Proxy Status:    {res_proxy['status']}")
    print(f"Proxy Latency:   {res_proxy['latency_sec']:.3f}s")
    print(f"Proxy Body:\n{res_proxy['body'][:300]}")

    return res_back, res_proxy


def main():
    print("# FORENSIC DIAGNOSTIC SUITE: LIVE VERCEL PRODUCTION ENGINE FAILURE")
    local_ok, local_tb = test_1_local_pipeline()
    res_a, res_b = test_2_backend_probes()
    res_proxy = test_3_proxy_probe()
    ctrl_back, ctrl_proxy = test_4_comparative_control()

    print_header("DIAGNOSTIC SUMMARY & ROOT CAUSE IDENTIFICATION")
    print(f"1. Local Punycode Pipeline: {'PASSED (No code crash)' if local_ok else 'CRASHED'}")
    print(f"2. Backend Direct Probe A (No Secret):   HTTP {res_a['status']} ({res_a['latency_sec']:.3f}s)")
    print(f"3. Backend Direct Probe B (With Secret): HTTP {res_b['status']} ({res_b['latency_sec']:.3f}s)")
    print(f"4. Frontend Proxy Probe:                 HTTP {res_proxy['status']} ({res_proxy['latency_sec']:.3f}s)")
    print(f"5. Control Benchmark (wikipedia.org):")
    print(f"   - Backend: HTTP {ctrl_back['status']} ({ctrl_back['latency_sec']:.3f}s)")
    print(f"   - Proxy:   HTTP {ctrl_proxy['status']} ({ctrl_proxy['latency_sec']:.3f}s)")


if __name__ == "__main__":
    main()
