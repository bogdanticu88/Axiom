"""Browser tests of the analyst UI (Chromium via Playwright) against the real API, a real database and a local
Keycloak. Users sign in through the identity provider's own login page; nothing is mocked except where a test says
it injects a failure (the dependency-failure and loading states).

Covers: sign-in, labels for the fake model and fixture-tested integrations, the case workspace (context, snapshots,
investigation progress and claims, claim review), cross-tenant access, restricted evidence metadata, stale-version
handling, denied/empty/loading/dependency-failure states, the read-only policy preview, and sign-out.

Not covered: Microsoft Entra ID or any hosted IdP; accessibility audit; browsers other than Chromium.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from axiom.access import Authorizer
from axiom.api.app import create_app
from axiom.config import Settings
from axiom.domains.cases import priority as prio
from axiom.domains.policies.service import DEFAULTS, PolicyService

from .investigation_support import inv, trivy_doc  # noqa: F401
from .oidc_support import CLIENT_ID, LiveServer, keycloak, provision  # noqa: F401
from .test_ingestion import importer, ingest  # noqa: F401
from .test_investigation import snapshot

pytestmark = pytest.mark.db

DIST = Path(os.environ.get("AXIOM_UI_DIST", Path(__file__).resolve().parents[2] / "frontend" / "dist"))
TIMEOUT = 15_000
SHOTS = os.environ.get("AXIOM_UI_SHOTS")        # optional directory for review screenshots (not part of assertions)


def shot(page, name: str) -> None:
    if SHOTS:
        page.screenshot(path=str(Path(SHOTS) / f"{name}.png"), full_page=True)


@pytest.fixture(scope="module")
def browser():
    required = os.environ.get("AXIOM_REQUIRE_UI") == "1"          # CI: a missing build or browser is a failure
    if not (DIST / "index.html").is_file():
        (pytest.fail if required else pytest.skip)(f"analyst UI is not built at {DIST} (npm run build in frontend/)")
    try:
        from playwright import sync_api
    except ImportError:
        (pytest.fail if required else pytest.skip)("playwright is not installed")
    with sync_api.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture()
def ui(keycloak, dbinfo, db, object_store, issuer, world, inv):  # noqa: F811
    settings = Settings(env="test", database_dsn=dbinfo.app_dsn, trusted_issuers_json=json.dumps(
        [{"issuer": issuer.issuer, "audience": issuer.audience, "jwks": issuer.jwks()}]),
        oidc_issuer=keycloak.issuer, oidc_client_id=CLIENT_ID,
        oidc_client_secret_ref=f"secretref:env/{keycloak.client_secret_env}",
        oidc_redirect_uri=keycloak.redirect_uri, ui_cookie_secure=False, ui_dist_dir=str(DIST),
        oidc_post_logout_redirect_uri=f"http://127.0.0.1:{keycloak.api_port}/ui/")
    ids = provision(dbinfo, world, keycloak, who={
        "alice": ("a", [("analyst", "project")]),
        "mallory": ("a", [("auditor", "project")]),        # same email as alice; a separate principal
        "bob": ("b", [("analyst", "project")]),
    })
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    with LiveServer(create_app(settings, db=db, store=object_store), keycloak.api_port) as live:
        live.ids = ids
        yield live


def sign_in(browser, ui, keycloak, username, path="/ui/", tenant=None):  # noqa: F811
    """Sign in through Keycloak's login page. The IdP users outlive each test's tenants, so a user may hold
    memberships in earlier tests' tenants; ``tenant`` pre-selects this test's tenant as the remembered choice."""
    ctx = browser.new_context()
    if tenant:
        ctx.add_init_script(f"try {{ localStorage.setItem('axiom.tenant', {json.dumps(tenant)}) }} catch (e) {{}}")
    page = ctx.new_page()
    page.set_default_timeout(TIMEOUT)
    errors: list[str] = []
    page.on("console", lambda m: m.type == "error" and errors.append(m.text))
    page.goto(ui.base + path)
    page.get_by_test_id("sign-in").click()
    u = keycloak.users[username]
    page.fill("#username", u.username)
    page.fill("#password", u.password)
    page.click("#kc-login")
    page.wait_for_url(f"{ui.base}{path}*")
    page.get_by_test_id("sign-out").wait_for()            # the session has loaded
    page.console_errors = errors
    return page


def test_case_workspace_with_labels_progress_and_claim_review(browser, ui, keycloak, inv, world):  # noqa: F811
    case = inv.case_for()
    route = inv.route()                                    # approved deterministic-fake route
    page = sign_in(browser, ui, keycloak, "alice", tenant=world.a.slug)
    page.get_by_test_id("sources").wait_for()
    shot(page, "01-coverage")
    assert "A successful synchronisation does not prove complete coverage" in page.content()

    page.get_by_role("link", name="Model routes").click()
    row = page.locator(f"tr[data-provider='deterministic_fake']").first
    assert "Fake model (not a language model)" in row.inner_text()
    shot(page, "02-model-routes")

    page.goto(f"{ui.base}/ui/cases/{case['id']}/context")
    page.get_by_test_id("occurrences").wait_for()
    assert case["vulnerability_ref"] in page.get_by_test_id("occurrences").inner_text()
    assert "Observed in an imported report" in page.get_by_test_id("asset-versions").inner_text()
    shot(page, "03-case-context")

    page.get_by_test_id("tab-investigations").click()
    assert "FAKE MODEL" in page.get_by_test_id("route").inner_text()
    page.get_by_test_id("start-investigation").click()
    page.get_by_test_id("run-status").wait_for()
    [run] = inv.svc("analyst", lambda s: s.list_for_case(case["id"]))
    assert "In progress" in page.content() or run["status"] != "queued"
    inv.drive(run["id"])                                   # the worker runs the investigation; the page polls
    page.locator("[data-testid='run-status'] >> text=completed").wait_for()
    assert "Fake model (not a language model)" in page.get_by_test_id("run-status").inner_text()
    page.locator("[data-testid='runs'] >> text=completed").wait_for()      # the run list refreshes on completion
    claims = page.get_by_test_id("claim")
    assert claims.count() >= 1
    assert "references checked, reasoning not verified" in page.content()
    first = claims.first
    first.get_by_label("review note").fill("checked the cited scanner record")
    first.get_by_role("button", name="Record review").click()
    first.get_by_test_id("review").wait_for()
    assert "reviewed: confirmed" in first.inner_text()
    shot(page, "04-investigation-claims")
    assert ui.ids["alice"]
    stored = inv.get(run["id"])["claims"][0]["reviews"]
    assert stored and str(stored[0]["reviewer"]) == str(ui.ids["alice"])
    assert not [e for e in page.console_errors if "Content Security Policy" in e]


def test_cross_tenant_access_is_refused_in_the_ui(browser, ui, keycloak, inv, world):  # noqa: F811
    case = inv.case_for()
    page = sign_in(browser, ui, keycloak, "bob")
    values = page.get_by_test_id("tenant").locator("option").evaluate_all("os => os.map(o => o.value)")
    # the IdP user outlives each test's tenants, so earlier tests' tenant-B memberships may also be listed
    assert world.b.slug in values and world.a.slug not in values
    page.get_by_test_id("tenant").select_option(world.b.slug)        # remembered for the next page load
    page.goto(f"{ui.base}/ui/cases/{case['id']}")
    state = page.locator("[data-state='not_found'], [data-state='denied']").first
    state.wait_for()
    shot(page, "10-cross-tenant")
    assert case["title"] not in page.content()
    # forcing the other tenant's header from the page is refused by the server, not just hidden by the UI
    status = page.evaluate("""async ([slug, id]) => {
        const r = await fetch('/api/v1/cases/' + id, {headers: {'X-Axiom-Tenant': slug}});
        return r.status; }""", [world.a.slug, str(case["id"])])
    assert status == 403
    # and a remembered tenant the user is not a member of is ignored
    page.evaluate("s => localStorage.setItem('axiom.tenant', s)", world.a.slug)
    page.goto(f"{ui.base}/ui/cases")
    page.get_by_test_id("case-queue").or_(page.locator("[data-state='empty']")).first.wait_for()
    assert case["title"] not in page.content()


def test_restricted_evidence_metadata_is_withheld_in_the_ui(browser, ui, keycloak, inv, dbinfo, world):  # noqa: F811
    case = inv.case_for()
    snap = snapshot(inv, case["id"])
    page = sign_in(browser, ui, keycloak, "mallory", path=f"/ui/cases/{case['id']}/evidence",
                   tenant=world.a.slug)
    page.get_by_test_id("snapshots").get_by_role("button", name="Open").first.click()
    members = page.get_by_test_id("members")
    members.wait_for()
    text = members.inner_text()
    assert "metadata withheld" in text and "content withheld" in text
    shot(page, "05-restricted-evidence")
    ev = [m for m in snap["members"] if m["kind"] == "evidence_object"][0]
    row = members.locator("tr", has_text=ev["member_key"]).inner_text()
    assert "metadata withheld" in row and "file " not in row and "digest " not in row   # no filename or digest shown
    assert "source text (untrusted)" not in text
    from axiom.provisioning import Provisioner
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, ui.ids["mallory"], "evidence_metadata_reader",
                                                     world.a.project, "metadata for audit")
    page.reload()
    page.get_by_test_id("snapshots").get_by_role("button", name="Open").first.click()
    page.get_by_test_id("members").wait_for()
    row = page.get_by_test_id("members").locator("tr", has_text=ev["member_key"]).inner_text()
    assert f"file {ev['attributes']['original_filename']}" in row and "digest " in row and "metadata withheld" not in row


def test_stale_version_denied_empty_loading_and_dependency_states(browser, ui, keycloak, inv):  # noqa: F811
    case = inv.case_for()
    page = sign_in(browser, ui, keycloak, "alice", path=f"/ui/cases/{case['id']}/priority",
                   tenant=inv.world.a.slug)
    page.get_by_test_id("priority-rationale").fill("apply the policy")
    # someone else changes the case after the page loaded it
    analyst = inv.ctx_for("analyst")
    inv.run(analyst, lambda s: prio.apply(s.cases, case["id"], case["record_version"], rationale="concurrent"))
    page.get_by_test_id("apply-policy").click()
    stale = page.locator("[data-state='stale']")
    stale.wait_for()
    assert "Someone changed this record" in stale.inner_text()
    shot(page, "06-stale-version")
    stale.get_by_role("button", name="Reload").click()
    page.get_by_test_id("priority-decisions").wait_for()
    assert "concurrent" in page.get_by_test_id("priority-decisions").inner_text()

    page.goto(f"{ui.base}/ui/policies")                    # analysts cannot list policy versions
    page.locator("[data-state='denied']").wait_for()
    shot(page, "07-denied")

    page.goto(f"{ui.base}/ui/cases")
    page.get_by_test_id("case-queue").wait_for()
    page.get_by_test_id("workflow-filter").select_option("closed")
    page.locator("text=No cases match.").wait_for()

    page.route("**/api/v1/cases?*", lambda r: r.abort())
    page.reload()
    dep = page.locator("[data-state='dependency']").first
    dep.wait_for()
    assert "Nothing was changed by this request" in dep.inner_text()
    shot(page, "08-dependency-failure")
    page.unroute("**/api/v1/cases?*")

    held = []
    page.route("**/api/v1/cases?*", lambda r: held.append(r))   # never answered: the loading state stays visible
    page.reload()
    page.locator("[data-state='loading']").first.wait_for()
    for r in held:
        r.abort()


def test_policy_preview_is_read_only_in_the_ui(browser, ui, keycloak, inv, dbinfo, world):  # noqa: F811
    from axiom.provisioning import Provisioner
    case = inv.case_for()
    analyst = inv.ctx_for("analyst")
    inv.run(analyst, lambda s: prio.apply(s.cases, case["id"], case["record_version"], rationale="policy"))
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, ui.ids["alice"], "policy_admin", world.a.root,
                                                     "ui preview test")
    urgent = {**DEFAULTS["priority"], "matrix": {s: {c: "urgent" for c in ("critical", "high", "medium", "low")}
                                                 for s in ("critical", "high", "medium", "low", "info")}}
    ctx = inv.ctx_for("admin")
    with inv.db.tenant_tx(ctx) as conn:
        draft = PolicyService(conn, ctx, Authorizer(conn, ctx)).draft(kind="priority", definition=urgent,
                                                                     rationale="what if")

    def state():
        return inv.run(analyst, lambda s: s.conn.execute(
            """SELECT (SELECT count(*) FROM axiom.case_events) AS ev, (SELECT count(*) FROM axiom.decisions) AS d,
                      (SELECT string_agg(priority || record_version::text, ',' ORDER BY id) FROM axiom.finding_cases) AS c
            """).fetchone())
    before = state()
    page = sign_in(browser, ui, keycloak, "alice", path="/ui/policies", tenant=world.a.slug)
    page.get_by_test_id(f"preview-{draft['version']}").click()
    page.get_by_test_id("preview").wait_for()
    assert "Read-only: nothing was changed" in page.get_by_test_id("preview-note").inner_text()
    assert case["title"] in page.get_by_test_id("preview").inner_text()
    assert int(page.get_by_test_id("preview-counts").locator("strong").nth(1).inner_text()) >= 1
    shot(page, "09-policy-preview")
    assert state() == before


def test_sign_out_ends_the_session(browser, ui, keycloak, world):  # noqa: F811
    page = sign_in(browser, ui, keycloak, "alice", tenant=world.a.slug)
    page.get_by_test_id("sources").or_(page.locator("[data-state]")).first.wait_for()
    with page.expect_navigation(url="**/protocol/openid-connect/logout*"):
        page.get_by_test_id("sign-out").click()
    # The platform session is already revoked. The platform sends no id_token_hint (it does not keep ID tokens), so
    # Keycloak asks the user to confirm ending the IdP session before returning to the post-logout URI.
    page.locator("#kc-logout").click()
    page.wait_for_url(f"{ui.base}/ui/*")
    page.get_by_test_id("sign-in").wait_for()
    assert page.evaluate("async () => (await fetch('/auth/session')).status") == 401


def test_start_investigation_records_the_decision_and_its_confirmation_stays(browser, ui, keycloak, inv, world,  # noqa: F811
                                                                             admin_conn):
    """The confirmation of a successful start must still be visible after the page has reloaded the case. Before the
    fix it was rendered inside the "Start investigation" section, which is shown only while the case is `received`, so
    it disappeared as soon as the reload completed; a check that waited for it passed only if it looked in time."""
    case = inv.case_for()
    assert case["workflow"] == "received"
    page = sign_in(browser, ui, keycloak, "alice", path=f"/ui/cases/{case['id']}/assessment", tenant=world.a.slug)
    page.get_by_test_id("start-case-investigation").click()
    page.get_by_test_id("case-workflow").filter(has_text="investigating").wait_for()   # the case has been reloaded
    status = page.get_by_role("status").filter(has_text="Investigation started.")
    assert status.is_visible(), "the success confirmation disappeared when the case reloaded"
    assert page.get_by_test_id("start-case-investigation").count() == 0                 # nothing left to repeat
    rows = admin_conn.execute(
        "SELECT d.actor_principal_id, c.workflow FROM axiom.decisions d JOIN axiom.finding_cases c"
        " ON c.id = d.case_id AND c.tenant_id = d.tenant_id WHERE d.case_id = %s AND d.kind = 'investigation_start'",
        (case["id"],)).fetchall()
    assert [(str(r["actor_principal_id"]), r["workflow"]) for r in rows] == [(str(ui.ids["alice"]), "investigating")]
    page.reload()                                                                       # what the server now returns
    assert page.get_by_test_id("case-workflow").inner_text() == "investigating"
