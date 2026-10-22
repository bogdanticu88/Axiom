"""Checkpoint-7 browser tests (Chromium, local Keycloak, real API and database).

* The change-report form: success operated by keyboard only, and the server's refusals (permission, stale page).
* Focused accessibility checks on the screens changed in checkpoints 6 and 7 (verification and closure, risk
  acceptance, action proposals and approvals): every form control has an accessible name, refusals are announced
  (role=alert) and successes are polite status messages (role=status), keyboard focus is visible and moves in
  document order. This is **not** an accessibility audit: no screen reader, contrast, zoom or WCAG review was done.
* Worker-recorded verification is labelled differently from a person's, with the check endpoint marked
  fixture-tested; the endpoint here is the local TLS fixture (tests/integration/check_target.py).
"""
from __future__ import annotations

import re

import pytest

from .oidc_support import keycloak  # noqa: F401
from .test_analyst_ui import browser, shot, sign_in  # noqa: F401
from .test_analyst_ui_workflows import DIGEST_NEW, error_code, wui  # noqa: F401
from .investigation_support import inv  # noqa: F401
from .test_ingestion import importer, ingest  # noqa: F401
from .test_verification_worker import setup, target  # noqa: F401
from .test_cases import advance_to_verification, scenario  # noqa: F401

pytestmark = pytest.mark.db

# Collects form controls without an accessible name: no aria-label/aria-labelledby, no wrapping <label>, no
# <label for>. Hidden controls are ignored.
UNLABELLED = """() => [...document.querySelectorAll('main input, main select, main textarea, main button')]
  .filter(el => el.offsetParent !== null && el.type !== 'hidden')
  .filter(el => {
    if (el.getAttribute('aria-label') || el.getAttribute('aria-labelledby')) return false;
    if (el.tagName === 'BUTTON') return !el.textContent.trim();
    if (el.closest('label')) return !el.closest('label').textContent.trim();
    return !(el.id && document.querySelector(`label[for="${el.id}"]`));
  }).map(el => el.outerHTML.slice(0, 120))"""


def to_remediating(world, run, ctx_for, scenario):  # noqa: F811
    """Fixture people move the scenario case to remediating (version 4)."""
    from .test_cases import advance_to_review
    analyst, owner = ctx_for("analyst"), ctx_for("owner")
    cid = scenario["case"]["id"]
    advance_to_review(run, analyst, cid, scenario["evidence"]["id"])
    run(analyst, lambda s: s.cases.plan_remediation(cid, 2, owner_principal_id=world["owner"], rationale="patch"))
    run(owner, lambda s: s.cases.record_external_work(cid, 3, external_reference="JIRA-1", rationale="ticket"))
    return cid


def focused(page) -> str:
    return page.evaluate("""() => { const el = document.activeElement;
        const label = el.closest('label'); return (label ? label.querySelector('span').textContent : '') + '|' +
        (el.tagName) + '|' + (el.textContent || '').trim().slice(0, 40); }""")


def test_change_report_form_keyboard_success_and_server_refusals(browser, wui, keycloak, world, run, ctx_for,  # noqa: F811
                                                                 scenario):  # noqa: F811
    cid = to_remediating(world, run, ctx_for, scenario)
    url = f"/ui/cases/{cid}/verification"

    # an auditor sees the form (the UI does not hide it) but the server refuses
    mallory = sign_in(browser, wui, keycloak, "mallory", path=url, tenant=world.a.slug)
    mallory.get_by_label("Rationale (required for every decision)").fill("deployed")
    mallory.get_by_label("Fixed deployment").select_option(label=f"{DIGEST_NEW} (manually recorded)")
    mallory.get_by_label("Change reference").fill("deploy 42")
    mallory.get_by_test_id("report-change").click()
    assert error_code(mallory) == "permission_denied"
    alert = mallory.get_by_role("alert")
    assert alert.count() == 1 and "permission_denied" in alert.inner_text()
    shot(mallory, "20-change-report-refused")

    # alice reports the change using the keyboard only
    alice = sign_in(browser, wui, keycloak, "alice", path=url, tenant=world.a.slug)
    rationale = alice.get_by_label("Rationale (required for every decision)")
    rationale.focus()
    alice.keyboard.type("rolled out to production")
    alice.keyboard.press("Tab")
    assert focused(alice).startswith("Fixed deployment|SELECT")
    alice.get_by_label("Fixed deployment").select_option(label=f"{DIGEST_NEW} (manually recorded)")   # select value; focus stays on it
    alice.keyboard.press("Tab")
    assert focused(alice).startswith("Change reference|INPUT")
    alice.keyboard.type("deploy 42")
    alice.keyboard.press("Tab")
    assert focused(alice).endswith("|BUTTON|Report change deployed")
    outline = alice.evaluate("() => getComputedStyle(document.activeElement).outlineStyle")
    assert outline not in ("none", "")                                          # focus is visible
    alice.keyboard.press("Enter")
    status = alice.get_by_role("status").filter(has_text="Change reported.")
    status.wait_for()
    alice.get_by_test_id("case-workflow").filter(has_text=re.compile(r"^awaiting_verification$")).wait_for()
    report = run(ctx_for("analyst"), lambda s: s.conn.execute(
        "SELECT reported_by, change_reference FROM axiom.remediation_reports WHERE case_id = %s", (cid,)).fetchone())
    assert (report["reported_by"], report["change_reference"]) == (wui.ids["alice"], "deploy 42")
    shot(alice, "21-change-report-keyboard")


def test_change_report_on_a_stale_page_is_refused(browser, wui, keycloak, world, run, ctx_for, scenario):  # noqa: F811
    cid = to_remediating(world, run, ctx_for, scenario)
    alice = sign_in(browser, wui, keycloak, "alice", path=f"/ui/cases/{cid}/verification", tenant=world.a.slug)
    alice.get_by_test_id("report-change").wait_for()
    # after alice loaded the page, the owner reports the change (fixture person through the service)
    run(ctx_for("owner"), lambda s: s.cases.report_change(cid, 4, target_asset_version_id=scenario["new"]["id"],
                                                          change_reference="deploy 41", rationale="rolled out"))
    alice.get_by_label("Rationale (required for every decision)").fill("rolled out")
    alice.get_by_label("Fixed deployment").select_option(label=f"{DIGEST_NEW} (manually recorded)")
    alice.get_by_label("Change reference").fill("deploy 42")
    alice.get_by_test_id("report-change").click()
    assert error_code(alice) == "stale_version"
    alice.locator("[data-state='stale']").wait_for()
    reports = run(ctx_for("analyst"), lambda s: s.conn.execute(
        "SELECT change_reference FROM axiom.remediation_reports WHERE case_id = %s", (cid,)).fetchall())
    assert [r["change_reference"] for r in reports] == ["deploy 41"]          # nothing overwritten


def test_worker_recorded_verification_is_labelled_and_the_changed_screens_have_named_controls(
        browser, wui, keycloak, world, run, ctx_for, scenario, setup, target):  # noqa: F811
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    setup.worker.run_once(only_tenants={world.a.id})                # the local fixture endpoint reports absent
    alice = sign_in(browser, wui, keycloak, "alice", path=f"/ui/cases/{cid}/verification", tenant=world.a.slug)
    row = alice.get_by_test_id("verifications").locator("tr[data-recorder='workload']")
    row.wait_for()
    text = row.inner_text()
    assert "automated check (worker)" in text and "Fixture-tested integration" in text
    assert "recorded by a person" not in text
    obs = row.get_by_test_id("observation").inner_text()
    assert target.base_url in obs and "condition_absent" in obs
    shot(alice, "22-verification-by-worker")
    for path in ("verification", "risk", "actions"):
        alice.goto(wui.base + f"/ui/cases/{cid}/{path}")
        alice.locator("main").wait_for()
        alice.wait_for_load_state("networkidle")
        assert alice.locator("main input, main select, main textarea, main button").count() > 0, path
        assert alice.evaluate(UNLABELLED) == [], path
    # the check itself detects an unnamed control
    alice.evaluate("() => document.querySelector('main').appendChild(document.createElement('select'))")
    assert len(alice.evaluate(UNLABELLED)) == 1
