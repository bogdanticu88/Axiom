"""Browser check of a fresh Compose installation: the UI is served, sign-in goes through the local Keycloak, and an
authorised user completes a representative workflow while an unauthorised one is refused by the server.

    python scripts/verify/compose_ui_check.py BASE_URL        # e.g. http://127.0.0.1:18010
Environment: AXIOM_DEMO_PASSWORD (the synthetic users' password), optional AXIOM_UI_SHOTS (screenshot directory).
Prints one "ok ..." line per step and exits non-zero on the first failure.
"""
from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

from playwright.sync_api import sync_playwright

BASE = sys.argv[1].rstrip("/")
PASSWORD = os.environ["AXIOM_DEMO_PASSWORD"]
SHOTS = os.environ.get("AXIOM_UI_SHOTS")
TIMEOUT = 30_000


def ok(msg: str) -> None:
    print(f"ok   {msg}", flush=True)


def shot(page, name: str) -> None:
    if SHOTS:
        page.screenshot(path=os.path.join(SHOTS, f"{name}.png"), full_page=True)


def sign_in(browser, user: str, path: str = "/ui/"):
    ctx = browser.new_context()
    page = ctx.new_page()
    page.set_default_timeout(TIMEOUT)
    page.goto(BASE + path)
    page.get_by_test_id("sign-in").click()
    page.fill("#username", user)
    page.fill("#password", PASSWORD)
    page.click("#kc-login")
    page.wait_for_url(f"{BASE}/ui/**")
    page.get_by_test_id("sign-out").wait_for()
    return page


def main() -> int:
    with urllib.request.urlopen(f"{BASE}/ui/", timeout=10) as r:
        csp = r.headers.get("Content-Security-Policy", "")
        assert r.status == 200 and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp, csp
    ok("UI served by the API at /ui with a restrictive Content-Security-Policy")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            return run_checks(browser)
        except Exception:
            describe_pages(browser)
            raise


def run_checks(browser) -> int:
    alice = sign_in(browser, "alice", "/ui/cases")
    ok("alice signed in through the local Keycloak login page")
    alice.get_by_test_id("case-queue").wait_for()
    alice.get_by_test_id("workflow-filter").select_option("received")
    alice.get_by_test_id("case-queue").locator("a").first.wait_for()
    links = alice.get_by_test_id("case-queue").locator("a")
    n = links.count()
    assert n >= 2, f"expected imported cases, found {n}"
    first, second = links.nth(0).get_attribute("href"), links.nth(1).get_attribute("href")
    ok(f"case queue lists imported cases ({n} received)")
    shot(alice, "compose-01-queue")
    alice.goto(f"{BASE}/ui{first.removeprefix('/ui')}/assessment")
    alice.get_by_test_id("start-case-investigation").click()
    alice.locator("[data-state='ok']", has_text="Investigation started.").wait_for()
    alice.get_by_test_id("case-workflow").filter(has_text="investigating").wait_for()
    ok("alice moved a case to investigating through the UI; the page shows the new workflow")
    print(f"CASE {first.rstrip('/').split('/')[-1]}", flush=True)
    shot(alice, "compose-02-investigating")

    audrey = sign_in(browser, "audrey", f"/ui{second.removeprefix('/ui')}/assessment")
    audrey.get_by_test_id("start-case-investigation").click()
    audrey.locator("[data-testid='error-code']").first.wait_for()
    code = audrey.locator("[data-testid='error-code']").first.inner_text()
    assert "permission_denied" in code, code
    assert audrey.get_by_test_id("case-workflow").inner_text() == "received"
    ok("audrey (auditor) was refused by the server: permission_denied; the case did not change")

    session = [c["value"] for c in alice.context.cookies(BASE) if c["name"] == "axiom_session"][0]
    with alice.expect_navigation(url="**/protocol/openid-connect/logout*"):
        alice.get_by_test_id("sign-out").click()
    # replay the old session cookie directly: the server must refuse it (revoked, not merely deleted)
    req = urllib.request.Request(f"{BASE}/auth/session", headers={"Cookie": f"axiom_session={session}"})
    try:
        urllib.request.urlopen(req, timeout=10)
        raise AssertionError("revoked session still accepted")
    except urllib.error.HTTPError as err:
        assert err.code == 401, err.code
    ok("sign-out revoked the platform session server-side (old cookie replayed: 401)")
    browser.close()
    return 0


def describe_pages(browser) -> None:
    """On failure, print what each open page shows: its URL and any status, error or alert text."""
    for ctx in browser.contexts:
        for page in ctx.pages:
            print(f"page {page.url}", flush=True)
            for loc in ("[data-state]", "[data-testid='error-code']", "[role='alert']", "[data-testid='case-workflow']"):
                for el in page.locator(loc).all():
                    try:
                        print(f"  {loc}: {el.get_attribute('data-state') or ''} {el.inner_text(timeout=1000)[:300]!r}",
                              flush=True)
                    except Exception:  # noqa: BLE001 - diagnostics only
                        pass


if __name__ == "__main__":
    sys.exit(main())
