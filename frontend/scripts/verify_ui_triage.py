"""
Playwright automated UI verification for Phase 3 UI State Triage and Alert Components.
Asserts:
1. Format awareness helper hint appears when typing plain words without domain.
2. Submitting 'paypal login' renders the accessible SyntaxNoticeBanner (HTTP 400).
3. Submitting 'http://localhost:8000' renders the INTERNAL / PRIVATE HOST notice.
4. Submitting 'https://www.wikipedia.com' renders the BENIGN ALLOWLIST VERIFIED banner.
5. Submitting 'javascript:alert(1)' renders the CRITICAL: SCRIPT/URI INJECTION badge.
"""

import sys
import time
from playwright.sync_api import sync_playwright

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"


def main():
    print(f"\n{CYAN}>>> Launching Playwright UI State Verification on http://localhost:3000...{RESET}")

    with sync_playwright() as p:
        browser = None
        for ch in ["msedge", "chrome"]:
            try:
                browser = p.chromium.launch(channel=ch, headless=True)
                break
            except Exception:
                continue

        if not browser:
            browser = p.chromium.launch(headless=True)

        page = browser.new_page()
        page.set_viewport_size({"width": 1440, "height": 900})

        # Navigate to application
        page.goto("http://localhost:3000", wait_until="networkidle")
        print(f"  {GREEN}[PASS]{RESET} Connected to Next.js UI on http://localhost:3000")

        # 1. Real-time helper text test
        input_box = page.locator("input[type='text']")
        input_box.fill("paypal login")
        time.sleep(0.3)

        hint = page.locator("text=Hint: Enter a resolvable domain or full URL")
        assert hint.is_visible(), "Helper hint text not visible when typing plain words!"
        print(f"  {GREEN}[PASS]{RESET} Real-time format awareness hint displayed beneath search bar")

        # 2. Submit 'paypal login' -> Syntax Notice Banner
        page.keyboard.press("Enter")
        page.wait_for_selector("text=INVALID INPUT SYNTAX", timeout=5000)
        notice_desc = page.locator("text=Input is plain text or an incomplete query")
        assert notice_desc.is_visible(), "Syntax error description missing!"
        notice_rec = page.locator("text=Recommendation:")
        assert notice_rec.is_visible(), "Syntax recommendation missing!"
        print(f"  {GREEN}[PASS]{RESET} 'paypal login' triggered accessible SyntaxNoticeBanner (HTTP 400)")

        # 3. Submit 'http://localhost:8000' -> Internal Host
        input_box.fill("http://localhost:8000")
        page.keyboard.press("Enter")
        page.wait_for_selector("text=INTERNAL / PRIVATE HOST", timeout=5000)
        assert page.locator("text=10.0%").first.is_visible(), "Internal host baseline score not locked at 10.0%!"
        assert page.locator("text=Non-Routable Baseline").first.is_visible(), "Baseline description missing!"
        print(f"  {GREEN}[PASS]{RESET} 'http://localhost:8000' rendered Internal Network Card (10.0% baseline)")

        # 4. Submit 'https://www.wikipedia.com' -> Benign Allowlist
        input_box.fill("https://www.wikipedia.com")
        page.keyboard.press("Enter")
        page.wait_for_selector("text=ALLOWLIST VERIFIED", timeout=5000)
        assert page.locator("text=BENIGN / VERIFIED SAFE").first.is_visible(), "Benign headline missing!"
        assert page.locator("text=1.0%").first.is_visible(), "Threat score 1.0% missing!"
        print(f"  {GREEN}[PASS]{RESET} 'https://www.wikipedia.com' rendered Benign Allowlist Card (1.0%)")

        # 5. Submit 'javascript:alert(1)' -> Critical Injection
        input_box.fill("javascript:alert(1)")
        page.keyboard.press("Enter")
        page.wait_for_selector("text=CRITICAL: SCRIPT/URI INJECTION", timeout=5000)
        assert page.locator("text=99.0%").first.is_visible(), "Threat score 99.0% missing!"
        print(f"  {GREEN}[PASS]{RESET} 'javascript:alert(1)' rendered CRITICAL: SCRIPT/URI INJECTION Card (99.0%)")

        browser.close()

    print(f"\n{GREEN}ALL 5 UI STATE & COMPONENT TRIAGE CHECKS PASSED (100% SUCCESS){RESET}\n")


if __name__ == "__main__":
    main()
