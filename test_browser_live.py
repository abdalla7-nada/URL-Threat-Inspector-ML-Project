"""
Automated Visual Browser E2E Test Suite for CyberSec URL Threat Assessment.

Launches Microsoft Edge in live non-headless mode (headless=False)
with human-observable slow_mo pacing (800ms). Executes live UI interactions across:
1. Scenario 1: Homepage Initial Idle State
2. Scenario 2: Preset Chip 1 - Safe Enterprise (Benign Verdict)
3. Scenario 3: Preset Chip 2 - Raw IP Host (Malicious Verdict & Forensics Verification)
4. Scenario 4: Preset Chip 3 - Phishing Lure (Suspicious Verdict)
5. Scenario 5: Manual Custom URL Input (https://github.com/torvalds/linux)
6. Scenario 6: Canonical Brand Allowlist Alias (https://www.wikipedia.com)
7. Scenario 7: Plain Text Input / Syntax Notice (paypal login)
8. Scenario 8: Internal Host Infrastructure (http://localhost:8000)
9. Scenario 9: Dangerous Protocol / Script Injection (javascript:alert(1))

Saves 9 high-resolution visual audit screenshots to url_project/screenshots/.
"""

import os
import sys
import time
from typing import Optional

from playwright.sync_api import sync_playwright, Browser, Page

# ANSI formatting tokens
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"

WORKSPACE_ROOT = os.path.dirname(os.path.abspath(__file__))
SCREENSHOTS_DIR = os.path.join(WORKSPACE_ROOT, "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

TARGET_URL = "http://localhost:3000"


def launch_system_browser(playwright_instance) -> Browser:
    """Launch Microsoft Edge in non-headless mode with slow_mo=800ms."""
    channels = ["msedge", "chrome"]
    for ch in channels:
        try:
            print(f"{CYAN}Attempting to launch browser via channel='{ch}' (headless=False, slow_mo=800ms)...{RESET}")
            browser = playwright_instance.chromium.launch(
                channel=ch,
                headless=False,
                slow_mo=800,  # 800ms human-observable pacing between interactions
                args=["--start-maximized"],
            )
            print(f"{GREEN}Successfully launched system browser using channel: '{ch}'{RESET}")
            return browser
        except Exception as exc:
            print(f"{YELLOW}Channel '{ch}' failed: {exc}{RESET}")

    # Fallback to default chromium if channels fail
    print(f"{YELLOW}Channels failed. Falling back to default chromium launcher...{RESET}")
    return playwright_instance.chromium.launch(headless=False, slow_mo=800)


def run_live_browser_tests():
    """Execute end-to-end browser scenarios with screenshots and assertions."""
    print(f"\n{BOLD}{'=' * 95}{RESET}")
    print(f"{BOLD} CYBERSEC URL THREAT INSPECTOR - LIVE BROWSER VISUAL QA CERTIFICATION{RESET}")
    print(f"{CYAN} Target: {TARGET_URL} | Viewport: 1280x800 | Screenshots: {SCREENSHOTS_DIR}{RESET}")
    print(f"{BOLD}{'=' * 95}{RESET}\n")

    saved_screenshots = []

    with sync_playwright() as p:
        browser = launch_system_browser(p)
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            device_scale_factor=1.0,
        )
        page = context.new_page()

        try:
            # -----------------------------------------------------------------
            # Scenario 1: Homepage Idle State
            # -----------------------------------------------------------------
            print(f"\n{BOLD}>>> Scenario 1: Navigating to Homepage & Verifying Idle State...{RESET}")
            page.goto(TARGET_URL, wait_until="networkidle", timeout=15000)

            # Wait for header and title
            page.wait_for_selector("h1:has-text('URL SECURITY & THREAT INSPECTOR')", timeout=10000)
            page.wait_for_selector("input[placeholder*='Enter URL to inspect']", timeout=5000)

            time.sleep(1.0)
            shot1 = os.path.join(SCREENSHOTS_DIR, "01_homepage_idle.png")
            page.screenshot(path=shot1, full_page=True)
            saved_screenshots.append(shot1)
            print(f"  {GREEN}[PASS]{RESET} Scenario 1 Complete. Screenshot: {shot1}")

            # -----------------------------------------------------------------
            # Scenario 2: Preset Chip 1 - Safe Enterprise
            # -----------------------------------------------------------------
            print(f"\n{BOLD}>>> Scenario 2: Testing Preset Chip 1 - Safe Enterprise...{RESET}")
            safe_btn = page.locator("button:has-text('Safe Enterprise')")
            safe_btn.wait_for(state="visible", timeout=5000)
            safe_btn.click()

            page.wait_for_selector("text=BENIGN", timeout=10000)
            page.wait_for_selector("text=VERIFIED SAFE", timeout=5000)

            verdict_text = page.locator("text=BENIGN / VERIFIED SAFE").first
            assert verdict_text.is_visible(), "Expected 'BENIGN / VERIFIED SAFE' banner to be visible."

            time.sleep(1.0)
            shot2 = os.path.join(SCREENSHOTS_DIR, "02_benign_result.png")
            page.screenshot(path=shot2, full_page=True)
            saved_screenshots.append(shot2)
            print(f"  {GREEN}[PASS]{RESET} Scenario 2 Complete (BENIGN Verified). Screenshot: {shot2}")

            # -----------------------------------------------------------------
            # Scenario 3: Preset Chip 2 - Raw IP Host
            # -----------------------------------------------------------------
            print(f"\n{BOLD}>>> Scenario 3: Testing Preset Chip 2 - Raw IP Host...{RESET}")
            ip_btn = page.locator("button:has-text('Raw IP Host')")
            ip_btn.wait_for(state="visible", timeout=5000)
            ip_btn.click()

            page.wait_for_selector("text=MALICIOUS", timeout=10000)
            page.wait_for_selector("text=HIGH SEVERITY THREAT", timeout=5000)

            mal_text = page.locator("text=MALICIOUS / HIGH SEVERITY THREAT").first
            assert mal_text.is_visible(), "Expected 'MALICIOUS / HIGH SEVERITY THREAT' to be visible."

            ip_card = page.locator("text=RAW IP ADDRESS").first
            assert ip_card.is_visible(), "Expected 'RAW IP ADDRESS' card in Forensics Grid."

            time.sleep(1.0)
            shot3 = os.path.join(SCREENSHOTS_DIR, "03_malicious_result.png")
            page.screenshot(path=shot3, full_page=True)
            saved_screenshots.append(shot3)
            print(f"  {GREEN}[PASS]{RESET} Scenario 3 Complete (MALICIOUS & Raw IP Verified). Screenshot: {shot3}")

            # -----------------------------------------------------------------
            # Scenario 4: Preset Chip 3 - Phishing Lure
            # -----------------------------------------------------------------
            print(f"\n{BOLD}>>> Scenario 4: Testing Preset Chip 3 - Phishing Lure...{RESET}")
            phish_btn = page.locator("button:has-text('Phishing Lure')")
            phish_btn.wait_for(state="visible", timeout=5000)
            phish_btn.click()

            page.wait_for_selector("text=SUSPICIOUS", timeout=10000)
            page.wait_for_selector("text=ELEVATED RISK", timeout=5000)

            susp_text = page.locator("text=SUSPICIOUS / ELEVATED RISK").first
            assert susp_text.is_visible(), "Expected 'SUSPICIOUS / ELEVATED RISK' to be visible."

            time.sleep(1.0)
            shot4 = os.path.join(SCREENSHOTS_DIR, "04_suspicious_result.png")
            page.screenshot(path=shot4, full_page=True)
            saved_screenshots.append(shot4)
            print(f"  {GREEN}[PASS]{RESET} Scenario 4 Complete (SUSPICIOUS Verified). Screenshot: {shot4}")

            # -----------------------------------------------------------------
            # Scenario 5: Manual Custom URL Input
            # -----------------------------------------------------------------
            print(f"\n{BOLD}>>> Scenario 5: Testing Manual Custom Input (https://github.com/torvalds/linux)...{RESET}")
            input_box = page.locator("input[placeholder*='Enter URL to inspect']")
            input_box.wait_for(state="visible", timeout=5000)

            input_box.fill("")
            input_box.fill("https://github.com/torvalds/linux")

            analyze_btn = page.locator("button:has-text('Analyze URL')")
            analyze_btn.click()

            page.wait_for_selector("text=BENIGN / VERIFIED SAFE", timeout=10000)
            custom_benign = page.locator("text=BENIGN / VERIFIED SAFE").first
            assert custom_benign.is_visible(), "Expected Custom URL to resolve to 'BENIGN / VERIFIED SAFE'."

            time.sleep(1.0)
            shot5 = os.path.join(SCREENSHOTS_DIR, "05_custom_scan_result.png")
            page.screenshot(path=shot5, full_page=True)
            saved_screenshots.append(shot5)
            print(f"  {GREEN}[PASS]{RESET} Scenario 5 Complete (Custom Benign Verified). Screenshot: {shot5}")

            # -----------------------------------------------------------------
            # Scenario 6: Bare Root Domain Allowlist Alias (https://www.wikipedia.com)
            # -----------------------------------------------------------------
            print(f"\n{BOLD}>>> Scenario 6: Testing Canonical Alias (https://www.wikipedia.com)...{RESET}")
            input_box.fill("")
            input_box.fill("https://www.wikipedia.com")
            analyze_btn.click()

            page.wait_for_selector("text=BENIGN / VERIFIED SAFE", timeout=10000)
            page.wait_for_selector("text=ALLOWLIST VERIFIED", timeout=5000)
            wiki_score = page.locator("text=1.0%").first
            assert wiki_score.is_visible(), "Expected https://www.wikipedia.com to resolve to 1.0% allowlist baseline."

            time.sleep(1.0)
            shot6 = os.path.join(SCREENSHOTS_DIR, "06_wikipedia_allowlist_result.png")
            page.screenshot(path=shot6, full_page=True)
            saved_screenshots.append(shot6)
            print(f"  {GREEN}[PASS]{RESET} Scenario 6 Complete (Wikipedia Alias 1.0% Verified). Screenshot: {shot6}")

            # -----------------------------------------------------------------
            # Scenario 7: Plain Text Input / Syntax Notice (paypal login)
            # -----------------------------------------------------------------
            print(f"\n{BOLD}>>> Scenario 7: Testing Plain Text Input ('paypal login')...{RESET}")
            input_box.fill("")
            input_box.fill("paypal login")

            # Verify client-side hint
            hint_el = page.locator("text=Hint: Enter a resolvable domain or full URL")
            assert hint_el.is_visible(), "Expected format awareness hint to appear when typing plain words."

            analyze_btn.click()

            page.wait_for_selector("text=INVALID INPUT SYNTAX", timeout=10000)
            page.wait_for_selector("text=Please ensure your input contains a valid top-level domain", timeout=5000)

            syntax_banner = page.locator("text=INVALID INPUT SYNTAX").first
            assert syntax_banner.is_visible(), "Expected Syntax Notice banner for plain words input."

            time.sleep(1.0)
            shot7 = os.path.join(SCREENSHOTS_DIR, "07_syntax_notice_banner.png")
            page.screenshot(path=shot7, full_page=True)
            saved_screenshots.append(shot7)
            print(f"  {GREEN}[PASS]{RESET} Scenario 7 Complete (Syntax Notice Verified). Screenshot: {shot7}")

            # -----------------------------------------------------------------
            # Scenario 8: Internal Host Infrastructure (http://localhost:8000)
            # -----------------------------------------------------------------
            print(f"\n{BOLD}>>> Scenario 8: Testing Internal Host Infrastructure (http://localhost:8000)...{RESET}")
            input_box.fill("")
            input_box.fill("http://localhost:8000")
            analyze_btn.click()

            page.wait_for_selector("text=INTERNAL / PRIVATE HOST", timeout=10000)
            page.wait_for_selector("text=Informational Baseline", timeout=5000)
            internal_score = page.locator("text=10.0%").first
            assert internal_score.is_visible(), "Expected internal target to display 10.0% baseline."

            time.sleep(1.0)
            shot8 = os.path.join(SCREENSHOTS_DIR, "08_internal_host_notice.png")
            page.screenshot(path=shot8, full_page=True)
            saved_screenshots.append(shot8)
            print(f"  {GREEN}[PASS]{RESET} Scenario 8 Complete (Internal Host Verified). Screenshot: {shot8}")

            # -----------------------------------------------------------------
            # Scenario 9: Dangerous Protocol / Script Injection (javascript:alert(1))
            # -----------------------------------------------------------------
            print(f"\n{BOLD}>>> Scenario 9: Testing Dangerous Protocol (javascript:alert(1))...{RESET}")
            input_box.fill("")
            input_box.fill("javascript:alert(1)")
            analyze_btn.click()

            page.wait_for_selector("text=CRITICAL: SCRIPT/URI INJECTION", timeout=10000)
            page.wait_for_selector("text=99.9%", timeout=5000)

            danger_card = page.locator("text=CRITICAL: SCRIPT/URI INJECTION").first
            assert danger_card.is_visible(), "Expected 'CRITICAL: SCRIPT/URI INJECTION' badge for javascript scheme."

            time.sleep(1.0)
            shot9 = os.path.join(SCREENSHOTS_DIR, "09_dangerous_scheme_notice.png")
            page.screenshot(path=shot9, full_page=True)
            saved_screenshots.append(shot9)
            print(f"  {GREEN}[PASS]{RESET} Scenario 9 Complete (Dangerous Protocol Verified). Screenshot: {shot9}")

        finally:
            print(f"\n{CYAN}Closing browser session cleanly...{RESET}")
            context.close()
            browser.close()

    # Final Summary Report
    print(f"\n{BOLD}{'=' * 95}{RESET}")
    print(f"{BOLD} LIVE BROWSER VISUAL QA AUDIT - SUMMARY REPORT{RESET}")
    print(f"{BOLD}{'=' * 95}{RESET}")
    print(f"  {GREEN}[PASS]{RESET} Scenario 1: Initial Idle State Loaded & Captured")
    print(f"  {GREEN}[PASS]{RESET} Scenario 2: Preset Chip 1 'Safe Enterprise' -> BENIGN Verified")
    print(f"  {GREEN}[PASS]{RESET} Scenario 3: Preset Chip 2 'Raw IP Host' -> MALICIOUS & Raw IP Forensics Verified")
    print(f"  {GREEN}[PASS]{RESET} Scenario 4: Preset Chip 3 'Phishing Lure' -> SUSPICIOUS Verified")
    print(f"  {GREEN}[PASS]{RESET} Scenario 5: Custom Input 'https://github.com/torvalds/linux' -> BENIGN Verified")
    print(f"  {GREEN}[PASS]{RESET} Scenario 6: Canonical Alias 'https://www.wikipedia.com' -> BENIGN (1.0%) Allowlist Verified")
    print(f"  {GREEN}[PASS]{RESET} Scenario 7: Plain Text 'paypal login' -> Syntax Notice Banner Verified")
    print(f"  {GREEN}[PASS]{RESET} Scenario 8: Internal Host 'http://localhost:8000' -> INTERNAL / PRIVATE HOST (10.0%) Verified")
    print(f"  {GREEN}[PASS]{RESET} Scenario 9: Script Injection 'javascript:alert(1)' -> CRITICAL: SCRIPT/URI INJECTION (99.9%) Verified")
    print(f"\n{BOLD}Captured Screenshots ({len(saved_screenshots)}/9):{RESET}")
    for pth in saved_screenshots:
        print(f"  - {GREEN}{pth}{RESET}")

    print(f"\n{GREEN}{BOLD} ALL 9 VISUAL STATES TESTED & VERIFIED WITH ZERO ERRORS.{RESET}\n")


if __name__ == "__main__":
    run_live_browser_tests()
