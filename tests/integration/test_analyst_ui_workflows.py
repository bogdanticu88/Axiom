"""Browser tests (Chromium) for the approval, verification, report and risk-acceptance screens against the real API,
a real database and a local Keycloak.

Users sign in through Keycloak's login page. Set-up steps that are not under test (importing, moving a case to the
right state, a concurrent change by someone else) are done through the services as fixture people, and each test says
so. External effects go to a local Jira-style **fake**; the UI labels that integration fixture-tested.

Each refusal is asserted by the server's error code shown in the UI, not only by the absence of a change.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from axiom.access import Authorizer
from axiom.domains.actions.service import ActionService
from axiom.domains.cases.risk import RiskService
from axiom.domains.cases.service import EvidenceRef, expire_risk_acceptances

from .investigation_support import inv, trivy_doc  # noqa: F401
from .oidc_support import keycloak, provision  # noqa: F401
from .test_actions import PAYLOAD, Env
from .test_analyst_ui import DIST, browser, shot, sign_in  # noqa: F401
from .test_ingestion import importer, ingest  # noqa: F401

pytestmark = pytest.mark.db
DIGEST_OLD = "sha256:" + "a" * 64
DIGEST_NEW = "sha256:" + "b" * 64


@pytest.fixture()
def wui(keycloak, dbinfo, db, object_store, issuer, world, inv):  # noqa: F811
    """Live API serving the UI. In tenant A: alice is an analyst and approver, bob an approver and risk owner, mallory an auditor
    (tenant root). Nobody else is signed in through the browser."""
    from axiom.api.app import create_app
    from axiom.config import Settings
    from .oidc_support import CLIENT_ID, LiveServer
    settings = Settings(env="test", database_dsn=dbinfo.app_dsn, trusted_issuers_json=json.dumps(
        [{"issuer": issuer.issuer, "audience": issuer.audience, "jwks": issuer.jwks()}]),
        oidc_issuer=keycloak.issuer, oidc_client_id=CLIENT_ID,
        oidc_client_secret_ref=f"secretref:env/{keycloak.client_secret_env}",
        oidc_redirect_uri=keycloak.redirect_uri, ui_cookie_secure=False, ui_dist_dir=str(DIST),
        oidc_post_logout_redirect_uri=f"http://127.0.0.1:{keycloak.api_port}/ui/")
    ids = provision(dbinfo, world, keycloak, who={
        "alice": ("a", [("analyst", "project"), ("approver", "project")]),   # can approve, but not her own proposal
        "bob": ("a", [("approver", "project"), ("risk_owner", "project")]),
        "mallory": ("a", [("auditor", "root")]),
    })
    with LiveServer(create_app(settings, db=db, store=object_store), keycloak.api_port) as live:
        live.ids = ids
        yield live


def error_code(page) -> str:
    page.locator("[data-testid='error-code']").first.wait_for()
    return page.locator("[data-testid='error-code']").first.inner_text().replace("Code: ", "").strip()


# ------------------------------------------------------------------------------------------------- approvals
def test_proposal_approval_execution_and_rejections(browser, wui, keycloak, world, db, ctx_for, dbinfo, run,  # noqa: F811
                                                    admin_conn):
    env = Env(db, world, ctx_for, dbinfo, run)        # fixture: Jira-style connection (local fake) and a case
    case_url = f"/ui/cases/{env.case['id']}/actions"
    alice = sign_in(browser, wui, keycloak, "alice", path=case_url, tenant=world.a.slug)
    assert "Fixture-tested integration" in alice.locator("form").first.inner_text()
    alice.get_by_test_id("propose").click()
    alice.get_by_test_id("proposal").first.wait_for()
    [p] = env.svc("analyst", lambda s: [s.get(r["id"]) for r in s.conn.execute(
        "SELECT id FROM axiom.action_proposals WHERE case_id = %s", (env.case["id"],))])
    assert p["created_by"] == wui.ids["alice"]
    # the proposer cannot approve their own proposal (server: separation of duties)
    alice.get_by_label("decision rationale").fill("looks right to me")
    alice.get_by_test_id("approve").click()
    assert error_code(alice) == "separation_of_duties"
    shot(alice, "11-approval-self-refused")

    bob = sign_in(browser, wui, keycloak, "bob", path=case_url, tenant=world.a.slug)
    bob.get_by_test_id("proposal").first.wait_for()
    # someone revises the proposal after bob loaded it (fixture analyst through the service)
    env.svc("analyst", lambda s: s.revise(p["id"], 1, payload={**PAYLOAD, "summary": "Upgrade openssl now"},
                                          verification_criteria="ticket exists", expires_at=datetime.now(timezone.utc)
                                          + timedelta(days=5)))
    bob.get_by_label("decision rationale").fill("approve the ticket")
    bob.get_by_test_id("approve").click()
    bob.locator("[data-state='stale']").wait_for()
    assert error_code(bob) == "stale_version"
    bob.reload()
    bob.get_by_test_id("proposal").first.wait_for()
    assert "Upgrade openssl now" in bob.get_by_test_id("approved-payload").inner_text()   # the exact payload approved
    bob.get_by_label("decision rationale").fill("approve version 2")
    bob.get_by_test_id("approve").click()
    bob.get_by_test_id("approvals").locator("text=approved by").wait_for()      # the list reloads after success
    approvals = env.svc("analyst", lambda s: s.get(p["id"])["approvals"])
    assert [(a["decision"], a["approver_principal_id"]) for a in approvals] == [("approved", wui.ids["bob"])]

    alice.reload()
    alice.get_by_test_id("execute").click()
    alice.get_by_test_id("execution").first.wait_for()
    e = env.svc("analyst", lambda s: s.get(p["id"])["executions"][0])
    env.drive(admin_conn, e["job_id"])                # the worker creates the ticket in the local fake tracker
    alice.reload()
    row = alice.get_by_test_id("execution").first
    row.wait_for()
    assert "succeeded" in row.inner_text() and env.fake.issues               # the fake recorded one ticket
    assert len(env.fake.issues) == 1
    shot(alice, "12-approval-executed")


# ---------------------------------------------------------------------------------------------- verification
def build_awaiting_verification(world, run, ctx_for, upload):
    """Fixture people move a case to awaiting_verification: owner reports the change to the new digest."""
    analyst, owner = ctx_for("analyst"), ctx_for("owner")
    now = datetime.now(timezone.utc)

    def setup(s):
        asset = s.assets.create_asset(scope_id=world.a.project, kind="container_image", display_name="payments-api")
        old = s.assets.record_version(asset_id=asset["id"], observed_at=now, deployment_digest=DIGEST_OLD)
        new = s.assets.record_version(asset_id=asset["id"], observed_at=now, deployment_digest=DIGEST_NEW)
        occ = s.assets.record_occurrence(source_system="trivy", source_finding_id="f-1", asset_version_id=old["id"],
                                         component_locator="openssl@3.0.1", vulnerability_ref="CVE-2099-0001")
        case = s.cases.create(scope_id=world.a.project, title="openssl in payments-api", occurrence_ids=[occ["id"]])
        return {"case": case, "new": new}
    d = run(analyst, setup)
    cid = d["case"]["id"]
    ev = upload(analyst, world.a.project, b"trivy report: openssl 3.0.1 vulnerable")
    run(analyst, lambda s: s.cases.start_investigation(cid, 0, "triage"))
    run(analyst, lambda s: s.cases.record_assessment(cid, 1, assessment="supported", rationale="scanner agrees",
                                                      limitations="none identified", evidence=[EvidenceRef(ev["id"])]))
    run(analyst, lambda s: s.cases.plan_remediation(cid, 2, owner_principal_id=world["owner"], rationale="patch"))
    run(owner, lambda s: s.cases.record_external_work(cid, 3, external_reference="JIRA-1", rationale="ticket"))
    run(owner, lambda s: s.cases.report_change(cid, 4, target_asset_version_id=d["new"]["id"],
                                               change_reference="deploy 42", rationale="rolled out"))
    return cid


def test_verification_recorded_by_a_person_then_closure(browser, wui, keycloak, world, run, ctx_for, upload):  # noqa: F811
    cid = build_awaiting_verification(world, run, ctx_for, upload)
    check = upload(ctx_for("analyst"), world.a.project, b"rescan: openssl 3.0.15 on sha256:bbbb")
    url = f"/ui/cases/{cid}/verification"
    # an auditor can see the case but cannot record a verification (server refuses)
    mallory = sign_in(browser, wui, keycloak, "mallory", path=url, tenant=world.a.slug)
    mallory.get_by_test_id("verify-rationale").fill("looks fixed")
    mallory.get_by_test_id("record-verification").click()
    assert error_code(mallory) == "permission_denied"

    alice = sign_in(browser, wui, keycloak, "alice", path=url, tenant=world.a.slug)
    alice.get_by_test_id("verify-rationale").wait_for()
    # a stale page: the case changes after alice loaded it (fixture: another analyst records a partial check)
    run(ctx_for("analyst2"), lambda s: s.cases.record_verification(
        cid, 5, claimed_result="passed", coverage="partial", criteria={"check": "partial rescan"},
        observed_deployment_digest=DIGEST_NEW, rationale="partial rescan only"))     # -> inconclusive, back to review
    alice.get_by_test_id("verify-rationale").fill("rescan clean")
    alice.get_by_test_id("verify-evidence").fill(str(check["id"]))
    alice.get_by_test_id("record-verification").click()
    assert error_code(alice) == "stale_version"
    alice.reload()
    alice.get_by_test_id("verifications").locator("tr[data-outcome]").first.wait_for()
    assert alice.get_by_test_id("case-workflow").inner_text() == "review_required"
    rows = alice.get_by_test_id("verifications").locator("tr[data-outcome]")
    assert rows.count() == 1 and "inconclusive" in rows.first.inner_text()
    assert "recorded by a person" in rows.first.inner_text() and "coverage partial" in rows.first.inner_text()
    shot(alice, "13-verification-inconclusive")


def test_complete_verification_and_closure_in_the_ui(browser, wui, keycloak, world, run, ctx_for, upload):  # noqa: F811
    cid = build_awaiting_verification(world, run, ctx_for, upload)
    check = upload(ctx_for("analyst"), world.a.project, b"rescan: openssl 3.0.15 on sha256:bbbb")
    alice = sign_in(browser, wui, keycloak, "alice", path=f"/ui/cases/{cid}/verification", tenant=world.a.slug)
    alice.get_by_test_id("verify-rationale").fill("rescan of the deployed digest is clean")
    alice.get_by_test_id("verify-observed").select_option(label=DIGEST_NEW)
    alice.get_by_test_id("verify-evidence").fill(str(check["id"]))
    alice.get_by_test_id("record-verification").click()
    alice.locator("text=Verification recorded.").wait_for()
    row = alice.get_by_test_id("verifications").locator("tr[data-outcome='passed']")
    row.wait_for()
    assert "recorded by a person" in row.inner_text()
    alice.get_by_test_id("verify-rationale").fill("verified on the deployed digest")
    alice.get_by_test_id("close-verified").click()
    alice.locator("text=Case closed.").wait_for()
    assert alice.get_by_test_id("case-workflow").inner_text() == "closed"
    run_row = run(ctx_for("analyst"), lambda s: s.conn.execute(
        "SELECT outcome, recorded_by FROM axiom.verification_runs WHERE case_id = %s", (cid,)).fetchone())
    assert run_row["outcome"] == "passed" and run_row["recorded_by"] == wui.ids["alice"]
    shot(alice, "14-verification-closed")


# --------------------------------------------------------------------------------------------------- reports
def test_reports_generation_export_and_package(browser, wui, keycloak, world, inv, run, ctx_for, upload):  # noqa: F811
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    package_case = review_case_for_risk(world, run, ctx_for, upload)   # its assessment cites internal evidence
    alice = sign_in(browser, wui, keycloak, "alice", path="/ui/reports", tenant=world.a.slug)
    alice.get_by_test_id("generate-report").click()
    alice.get_by_test_id("report-snapshot").wait_for()
    alice.get_by_test_id("export-json").click()
    assert error_code(alice) == "permission_denied"                   # analysts may generate, not export
    status = alice.evaluate("""async (args) => {
        const csrf = document.cookie.match(/axiom_csrf=([^;]+)/)[1];
        const r = await fetch('/api/v1/reports/snapshots/' + args.id + '/exports', {method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(csrf), 'X-Axiom-Tenant': args.t},
          body: JSON.stringify({format: 'json'})});
        return r.status; }""", {"id": alice.get_by_test_id("report-snapshot").get_attribute("data-snapshot-id"),
                                 "t": world.a.slug})
    assert status == 403                                               # the API refuses, not only the screen

    mallory = sign_in(browser, wui, keycloak, "mallory", path="/ui/reports", tenant=world.a.slug)
    mallory.get_by_test_id("generate-report").click()
    mallory.get_by_test_id("report-snapshot").wait_for()
    mallory.get_by_test_id("export-csv").click()
    mallory.locator("text=CSV export stored.").wait_for()
    with mallory.expect_download() as dl:
        mallory.get_by_test_id("exports").get_by_role("button", name="Download").first.click()
    mallory.get_by_test_id("exports").locator("text=server digest matches").wait_for()
    import hashlib
    body = open(dl.value.path(), "rb").read()
    stored = run(ctx_for("auditor"), lambda s: s.conn.execute(
        "SELECT sha256 FROM axiom.report_exports ORDER BY created_at DESC LIMIT 1").fetchone())
    assert hashlib.sha256(body).hexdigest() == stored["sha256"]       # the browser saved exactly the stored export
    mallory.get_by_test_id("package-case").fill(str(package_case))
    mallory.get_by_test_id("build-package").click()
    mallory.get_by_test_id("package").wait_for()
    assert int(mallory.get_by_test_id("withheld-evidence").inner_text()) >= 1   # auditor: no evidence content
    shot(mallory, "15-reports-auditor")


# ------------------------------------------------------------------------------------------- risk acceptance
def review_case_for_risk(world, run, ctx_for, upload):
    analyst = ctx_for("analyst")
    case = run(analyst, lambda s: s.cases.create(scope_id=world.a.project, title="exposed admin panel"))
    ev = upload(analyst, world.a.project, b"scan: admin panel reachable")
    run(analyst, lambda s: s.cases.start_investigation(case["id"], 0, "triage"))
    run(analyst, lambda s: s.cases.record_assessment(case["id"], 1, assessment="supported", rationale="confirmed",
                                                      limitations="none", evidence=[EvidenceRef(ev["id"])]))
    return case["id"]


def test_risk_acceptance_request_rules_expiry_and_history(browser, wui, keycloak, world, run, ctx_for, upload,  # noqa: F811
                                                          admin_conn, db, dbinfo):
    from axiom.provisioning import Provisioner
    cid = review_case_for_risk(world, run, ctx_for, upload)
    admin = ctx_for("admin")
    run(admin, lambda s: s.tenancy.set_delegation_limit(principal_id=wui.ids["bob"], action_class="risk.accept",
                                                        scope_id=world.a.project, max_priority="urgent",
                                                        max_duration_days=90))
    url = f"/ui/cases/{cid}/risk"
    bob = sign_in(browser, wui, keycloak, "bob", path=url, tenant=world.a.slug)
    bob.get_by_test_id("risk-rationale").fill("compensated by WAF rule 17 until the vendor ships a fix")
    bob.get_by_test_id("risk-controls").fill("WAF rule 17; access limited to VPN")
    bob.get_by_test_id("risk-request").click()
    bob.locator("text=Request recorded.").wait_for()
    req = bob.get_by_test_id("risk-requests").locator("tr[data-status='pending']")
    req.wait_for()
    assert "independent authoriser required" in req.inner_text()       # priority pending: policy requires it
    bob.get_by_test_id("risk-decide").get_by_label("decision rationale").fill("I accept")
    bob.get_by_test_id("risk-authorise").click()
    assert error_code(bob) == "independent_authorisation_required"
    assert bob.get_by_test_id("risk-audit-withheld").is_visible()      # bob has no audit.read
    shot(bob, "16-risk-independence-refused")

    alice = sign_in(browser, wui, keycloak, "alice", path=url, tenant=world.a.slug)
    alice.get_by_test_id("risk-decide").get_by_label("decision rationale").fill("ok")
    alice.get_by_test_id("risk-authorise").click()
    assert error_code(alice) == "permission_denied"                    # analysts cannot accept risk

    # an independent risk owner (fixture person with a delegation limit) authorises through the service
    run(admin, lambda s: s.tenancy.set_delegation_limit(principal_id=world["risk_owner"], action_class="risk.accept",
                                                        scope_id=world.a.project, max_priority="urgent",
                                                        max_duration_days=90))
    owner = ctx_for("risk_owner")
    req_id = run(owner, lambda s: s.conn.execute("SELECT id FROM axiom.risk_acceptance_requests WHERE case_id = %s",
                                                 (cid,)).fetchone()["id"])
    run(owner, lambda s: RiskService(s.conn, owner, s.authz).authorise(req_id, rationale="independent review"))
    bob.reload()
    bob.get_by_test_id("active-acceptance").wait_for()
    assert bob.get_by_test_id("case-workflow").inner_text() == "closed"

    # expiry: fault injection moves the acceptance into the past; the system sweep reopens the case
    admin_conn.execute("SET session_replication_role = replica")
    try:
        admin_conn.execute("""UPDATE axiom.risk_acceptances SET starts_at = clock_timestamp() - interval '2 days',
                                     expires_at = clock_timestamp() - interval '1 minute' WHERE case_id = %s""", (cid,))
    finally:
        admin_conn.execute("SET session_replication_role = origin")
    system = ctx_for("system")
    with db.tenant_tx(system) as conn:
        expired = expire_risk_acceptances(conn, system, Authorizer(conn, system))
    assert len(expired) == 1
    mallory = sign_in(browser, wui, keycloak, "mallory", path=url, tenant=world.a.slug)
    mallory.get_by_test_id("risk-audit").wait_for()                    # auditor: audit trail visible
    audit = mallory.get_by_test_id("risk-audit").inner_text()
    for action in ("risk_acceptance.requested", "risk_acceptance.authorised", "risk_acceptance.expired"):
        assert action in audit
    assert "(workload)" in audit                                       # expiry recorded by the system principal
    history = mallory.get_by_test_id("risk-decisions").inner_text()
    assert "reopen acceptance_expiry" in history and "system result (expiry)" in history
    assert mallory.get_by_test_id("case-workflow").inner_text() == "investigating"
    assert "expired" in mallory.get_by_test_id("risk-acceptances").inner_text()
    shot(mallory, "17-risk-expired-history")
