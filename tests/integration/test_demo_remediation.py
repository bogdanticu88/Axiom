"""Reproducible remediation demonstration against a local lab (docs/DEMO.md; run with scripts/demo/run.sh).

Opt-in: set AXIOM_DEMO=1 after `python scripts/demo/lab.py up`. It needs Docker, the lab's registry and two demo
services, the Trivy image and its cached database, the local Keycloak and Chromium used by the UI tests.

Every step is labelled, and the labels are written to $AXIOM_DEMO_OUT/results.json:
  real      production code path: API, database, job worker, policies, verification worker, UI
  scanner   a real Trivy scan of an image the lab built and is running
  lab       local infrastructure the demonstration controls: building, pushing and deploying the demo images
  fake      a stand-in: the deterministic fake model (no language model is called) and the Jira-style tracker fake
  manual    a value a person supplies through a supported command
  test-read a read-only query used to pick an object or check a binding; not part of the product flow

Negative controls run through the same verification connection, worker and check service:
  A  the deployment was never changed, but a change is reported against it  -> must fail (condition present)
  B  a fixed image was built and reported, but never deployed               -> must not pass (different deployment)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from axiom.domains.actions.jobs import ActionExecuteHandler
from axiom.domains.evidence.service import EvidenceService
from axiom.domains.policies.service import DEFAULTS
from axiom.ingestion.pipeline import IngestionService
from axiom.ingestion.sync import SyncService
from axiom.integrations.jira_style import JiraStyleClient, JiraStyleTicketAdapter
from axiom.jobs import WorkerConfig
from axiom.provisioning import Provisioner
from axiom.secretrefs import SecretRefResolver
from axiom.verification import checks
from axiom.verification.worker import VerificationCheckHandler
from axiom.workers.jobs import build_worker

from .check_target import _pki
from .investigation_support import inv  # noqa: F401
from .jira_fake import JiraStyleFake
from .oidc_support import keycloak  # noqa: F401
from .test_analyst_ui import browser, sign_in  # noqa: F401
from .test_analyst_ui_workflows import wui  # noqa: F401
from .test_api import as_, client  # noqa: F401
from .test_ingestion import importer, ingest  # noqa: F401

pytestmark = [pytest.mark.db, pytest.mark.skipif(os.environ.get("AXIOM_DEMO") != "1",
                                                 reason="demonstration: run scripts/demo/run.sh")]
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "demo"))
import lab  # noqa: E402

VULN = "CVE-2024-22195"          # Jinja2 < 3.1.3 (the demonstrated case)
CONTROL_B_VULN = "CVE-2024-34064"
STEPS: list[dict] = []
OUT = Path(os.environ.get("AXIOM_DEMO_OUT", "demo-out"))
CHECK_PORT = 18443


def step(label: str, what: str, **detail):
    assert label in ("real", "scanner", "lab", "fake", "manual", "test-read")
    STEPS.append({"n": len(STEPS) + 1, "label": label, "step": what, **detail})


def ok(r, code=200):
    assert r.status_code == code, r.text
    return r.json()


def upload_evidence(client, headers, scope, content: bytes, name: str):
    r = client.post("/api/v1/evidence", headers=headers, json={
        "scope_id": str(scope), "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
        "media_type": "application/json", "classification": "internal", "filename": name})
    eid = ok(r, 201)["id"]
    assert client.put(f"/api/v1/evidence/{eid}/content", headers=headers, content=content).status_code == 200
    assert ok(client.post(f"/api/v1/evidence/{eid}/finalise", headers=headers))["status"] == "verified"
    return eid


def shot(page, name: str) -> None:
    (OUT / "screenshots").mkdir(parents=True, exist_ok=True)
    page.wait_for_load_state("networkidle")
    page.screenshot(path=str(OUT / "screenshots" / f"{name}.png"), full_page=True)


@pytest.fixture()
def check_service(tmp_path):
    """The demo check service (scripts/demo/check_service.py) on https://localhost:18443 with a throwaway CA."""
    ca, cert, key = _pki(tmp_path, ("localhost",))
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    token = hashlib.sha256(os.urandom(32)).hexdigest()
    (secrets / "check-token").write_text(token + "\n")
    log = open(OUT / "check-service.log", "w")
    proc = subprocess.Popen([sys.executable, str(ROOT / "scripts" / "demo" / "check_service.py"), "--port",
                             str(CHECK_PORT), "--cert", str(cert), "--key", str(key),
                             "--token-file", str(secrets / "check-token")], stdout=log, stderr=subprocess.STDOUT)
    for _ in range(50):
        if "listening" in (OUT / "check-service.log").read_text():
            break
        time.sleep(0.1)
    try:
        yield {"ca": ca, "secrets": secrets, "token": token, "base_url": f"https://localhost:{CHECK_PORT}"}
    finally:
        proc.terminate()
        proc.wait(10)
        log.close()


def cases_for(run, ctx_for, repo: str, vuln: str):
    return run(ctx_for("analyst"), lambda s: s.conn.execute(
        """SELECT c.id, c.record_version, av.id AS version_id, av.asset_id, av.deployment_digest, o.component_locator
             FROM axiom.finding_cases c JOIN axiom.case_occurrence_links l ON l.case_id = c.id
             JOIN axiom.finding_occurrences o ON o.id = l.occurrence_id
             JOIN axiom.asset_versions av ON av.id = o.asset_version_id JOIN axiom.assets a ON a.id = av.asset_id
            WHERE a.display_name = %s AND o.vulnerability_ref = %s""", (repo, vuln)).fetchall())


def test_remediation_demonstration(client, as_, world, db, dbinfo, object_store, run, ctx_for,  # noqa: F811
                                   browser, wui, keycloak, check_service):  # noqa: F811
    STEPS.clear()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "scans").mkdir(exist_ok=True)
    analyst, analyst2, owner, admin, auditor = (as_(n) for n in ("analyst", "analyst2", "owner", "admin", "auditor"))
    project = world.a.project
    ingestion = IngestionService(db, object_store, page_size=200, lease_seconds=60)
    sync = SyncService(db, ingestion, EvidenceService(db, object_store, max_bytes=10**8))
    tracker = JiraStyleFake()
    tracker_adapter = lambda *_: JiraStyleTicketAdapter(JiraStyleClient(            # noqa: E731
        "https://tracker.test.invalid", lambda: ("bot", "t"), transport=tracker.transport()))

    def client_factory(conn, secrets, clock, policy):
        ref = conn["credential_ref"]
        return checks.CheckEndpointClient(conn["base_url"], lambda: secrets.resolve(ref), policy=policy,
                                          verify=ssl.create_default_context(cafile=str(check_service["ca"])),
                                          clock=clock, timeout=180)
    verification = VerificationCheckHandler(
        sync.evidence, secrets=SecretRefResolver(env="test", file_dirs=(str(check_service["secrets"]),)),
        policy=checks.DestinationPolicy.from_settings(check_service["base_url"], "127.0.0.1/32"),
        client_factory=client_factory)
    worker = build_worker(db, ingestion, sync, worker_id="demo",
                          config=WorkerConfig(lease_seconds=60, step_timeout_seconds=300),
                          action_handler=ActionExecuteHandler(tracker_adapter), verification=verification)

    def drain(rounds=40):
        for _ in range(rounds):
            if worker.run_once(only_tenants={world.a.id}) == 0:
                return
        raise AssertionError("worker did not settle")

    # 1. scan the running deployments with the real scanner -------------------------------------------------
    deployed = {s: lab.running(s) for s in lab.SERVICES}
    scans = {}
    for service, digest in deployed.items():
        ref = f"{lab.repository(service)}@{digest}"
        scans[service] = lab.scan(ref)
        (OUT / "scans" / f"{service}-vulnerable.json").write_bytes(scans[service])
        doc = json.loads(scans[service])
        step("scanner", f"Trivy scan of the running {service} image", image=ref, trivy=doc.get("Trivy", {}).get("Version")
             if isinstance(doc.get("Trivy"), dict) else None,
             vulnerabilities=sum(len(r.get("Vulnerabilities") or []) for r in doc.get("Results") or []))

    # 2. import and bind to the actual deployment ---------------------------------------------------------------
    imports = {}
    for service, body in scans.items():
        ev = upload_evidence(client, analyst, project, body, f"{service}-trivy.json")
        queued = ok(client.post("/api/v1/imports", headers=analyst, json={
            "evidence_id": ev, "adapter": "trivy_json", "scope_id": str(project)}), 202)
        drain()
        imports[service] = {**ok(client.get(f"/api/v1/ingestion-runs/{queued['id']}", headers=analyst)), "evidence": ev}
        assert (imports[service]["status"], imports[service]["coverage"]) == ("completed", "complete")
        step("real", f"import the {service} scan through POST /imports and the job worker", run=queued["id"],
             counts=imports[service]["counts"], evidence=ev)
    [orders] = cases_for(run, ctx_for, lab.repository("orders-api"), VULN)
    [control_a] = cases_for(run, ctx_for, lab.repository("reports-api"), VULN)
    [control_b] = cases_for(run, ctx_for, lab.repository("reports-api"), CONTROL_B_VULN)
    for case, service in ((orders, "orders-api"), (control_a, "reports-api")):
        assert case["deployment_digest"] == deployed[service] == lab.running(service)
    step("test-read", "each imported finding is bound to the asset version whose digest Docker reports for the "
         "running container", orders_case=str(orders["id"]), digest=orders["deployment_digest"],
         component=orders["component_locator"])
    cid = str(orders["id"])

    # 3. investigate and prioritise -----------------------------------------------------------------------------
    ok(client.post(f"/api/v1/assets/{orders['asset_id']}/business-context", headers=analyst, json={
        "rationale": "demo service catalogue entry", "owner_ref": "orders-team", "criticality": "high",
        "environment": "production"}), 201)
    step("manual", "business context for orders-api (owner_ref, criticality high, production)")
    route = ok(client.post("/api/v1/model-routes", headers=admin, json={
        "name": "demo-fake", "provider": "deterministic_fake", "model": "fake-rules-v1", "endpoint": "fake://demo",
        "region": "local", "max_classification": "internal", "rationale": "demonstration route (deterministic fake)"}),
        201)
    ok(client.post(f"/api/v1/model-routes/{route['id']}/approve", headers=auditor, json={"rationale": "reviewed"}))
    started = ok(client.post(f"/api/v1/cases/{cid}/investigations", headers={**analyst, "Idempotency-Key": "demo-inv"},
                             json={"questions": ["Is the reported Jinja2 version present in the deployed image?"],
                                   "route": "demo-fake"}), 202)
    drain()
    inv_run = ok(client.get(f"/api/v1/investigations/{started['id']}", headers=analyst))
    assert inv_run["status"] == "completed", inv_run["outcome_reason"]
    step("fake", "investigation through the model gateway with the DETERMINISTIC FAKE model; no language model "
         "was called", run=inv_run["id"], claims=len(inv_run["claims"]), model_calls=inv_run["model_calls"])
    ok(client.post(f"/api/v1/cases/{cid}/commands/start-investigation", headers=analyst,
                   json={"expected_version": 0, "rationale": "medium-severity library advisory in a production image"}))
    for cl in inv_run["claims"]:
        if cl["validation"] != "rejected":
            ok(client.post(f"/api/v1/investigation-claims/{cl['id']}/reviews", headers=analyst2, json={
                "verdict": "confirmed", "note": "checked against the cited scan observation"}), 201)
    step("manual", "a second analyst reviews every non-rejected claim")
    evidence = [{"evidence_id": imports["orders-api"]["evidence"]}]
    assessed = ok(client.post(f"/api/v1/cases/{cid}/commands/record-assessment", headers=analyst, json={
        "expected_version": 1, "assessment": "supported", "rationale": "scan and reviewed investigation agree",
        "limitations": "reachability not analysed; scanner data only; the model was the deterministic fake",
        "evidence": evidence, "investigation_run_id": inv_run["id"]}))
    pol = ok(client.post("/api/v1/policies", headers=admin, json={
        "kind": "priority", "definition": DEFAULTS["priority"], "rationale": "adopt provisional matrix"}), 201)
    ok(client.post(f"/api/v1/policies/{pol['id']}/publish", headers=auditor, json={"rationale": "reviewed"}))
    prioritised = ok(client.post(f"/api/v1/cases/{cid}/commands/apply-priority-policy", headers=analyst, json={
        "expected_version": assessed["record_version"], "rationale": "apply the published policy"}))
    step("real", "human assessment citing the reviewed run; priority from the published policy",
         priority=prioritised["priority"], policy=pol["id"])

    # 4. human approval through the action protocol, then the controlled remediation ---------------------------
    planned = ok(client.post(f"/api/v1/cases/{cid}/commands/plan-remediation", headers=analyst, json={
        "expected_version": prioritised["record_version"], "rationale": "upgrade Jinja2 to 3.1.6",
        "owner_principal_id": str(world["owner"])}))
    conn = ok(client.post("/api/v1/connections", headers=admin, json={
        "adapter": "jira_style", "scope_id": str(project), "display_name": "tracker (local fake)",
        "base_url": "https://tracker.test.invalid", "credential_ref": "secretref:test/tracker", "config": {}}), 201)
    proposal = ok(client.post("/api/v1/action-proposals", headers={**analyst, "Idempotency-Key": "demo-prop"}, json={
        "case_id": cid, "effect_class": "ticket.create", "connection_id": conn["id"],
        "payload": {"project_key": "SEC", "summary": f"orders-api: upgrade Jinja2 ({VULN})",
                    "description": "Rebuild with requirements-fixed.txt and redeploy.", "labels": ["security"]},
        "verification_criteria": "ticket exists in SEC",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()}), 201)
    bob = sign_in(browser, wui, keycloak, "bob", path=f"/ui/cases/{cid}/actions", tenant=world.a.slug)
    bob.get_by_test_id("proposal").first.wait_for()
    bob.get_by_label("decision rationale").fill("approved: dependency upgrade, no functional change expected")
    bob.get_by_test_id("approve").click()
    bob.get_by_test_id("approvals").locator("text=approved by").wait_for()
    shot(bob, "02-approval-recorded-in-the-ui")
    [approval] = [a for a in ok(client.get(f"/api/v1/action-proposals/{proposal['id']}", headers=analyst))["approvals"]]
    assert approval["approver_principal_id"] == str(wui.ids["bob"])
    step("real", "approval recorded in the browser by a different person (bob, approver) than the proposer",
         approval=approval["id"])
    execution = ok(client.post(f"/api/v1/action-proposals/{proposal['id']}/versions/1/executions",
                               headers={**analyst, "Idempotency-Key": "demo-exec"},
                               json={"approval_id": approval["id"]}), 202)
    drain()
    done = ok(client.get(f"/api/v1/action-executions/{execution['id']}", headers=analyst))
    assert done["state"] == "succeeded"
    step("fake", "ticket created in the Jira-style FAKE tracker through the effect gate", ticket=done["external_ref"])
    working = ok(client.post(f"/api/v1/cases/{cid}/commands/record-external-work", headers=owner, json={
        "expected_version": planned["record_version"], "rationale": f"tracked in {done['external_ref']}",
        "external_reference": done["external_ref"]}))
    fixed = lab.build("orders-api", "fixed")
    lab.deploy("orders-api", fixed)
    assert lab.running("orders-api") == fixed != deployed["orders-api"]
    step("lab", "rebuild orders-api with Jinja2 3.1.6, push to the local registry and replace the running container",
         digest=fixed)
    new_version = ok(client.post(f"/api/v1/assets/{orders['asset_id']}/versions", headers=analyst, json={
        "observed_at": datetime.now(timezone.utc).isoformat(), "deployment_digest": fixed}), 201)
    step("manual", "analyst records the redeployed digest as a new asset version (no deployment integration)")

    # 5. verification by the worker against the deployment ------------------------------------------------------
    ok(client.post("/api/v1/connections", headers=admin, json={
        "adapter": "verification_check", "scope_id": str(project), "display_name": "demo check service (Trivy rescan)",
        "base_url": check_service["base_url"], "credential_ref": f"secretref:file{check_service['secrets']}/check-token",
        "config": {"max_observation_age_seconds": 900}}), 201)
    Provisioner(dbinfo.admin_cli_dsn).create_verification_identity(world.a.id)
    step("real", "check endpoint connection (operator-configured, allow-listed origin) and a verification identity")
    reported = ok(client.post(f"/api/v1/cases/{cid}/commands/report-change", headers=owner, json={
        "expected_version": working["record_version"], "rationale": "redeployed with Jinja2 3.1.6",
        "target_asset_version_id": new_version["id"], "change_reference": f"{done['external_ref']} redeploy"}))
    assert reported["workflow"] == "awaiting_verification"
    drain()
    history = ok(client.get(f"/api/v1/cases/{cid}/history", headers=analyst))
    [vrun] = history["verifications"]
    assert vrun["outcome"] == "passed", vrun
    step("real", "verification worker asked the check service, which rescanned the running container; recorded "
         "passed for the reported digest", run=vrun["id"], outcome=vrun["outcome"])

    # 6. negative controls through the same connection, worker and check service --------------------------------
    controls = {}
    for name, case, vuln in (("A", control_a, VULN), ("B", control_b, CONTROL_B_VULN)):
        ccid = str(case["id"])
        ok(client.post(f"/api/v1/cases/{ccid}/commands/start-investigation", headers=analyst,
                       json={"expected_version": 0, "rationale": "control case"}))
        a = ok(client.post(f"/api/v1/cases/{ccid}/commands/record-assessment", headers=analyst, json={
            "expected_version": 1, "assessment": "supported", "rationale": "scanner finding", "limitations": "scanner only",
            "evidence": [{"evidence_id": imports["reports-api"]["evidence"]}]}))
        p = ok(client.post(f"/api/v1/cases/{ccid}/commands/plan-remediation", headers=analyst, json={
            "expected_version": a["record_version"], "rationale": "upgrade Jinja2",
            "owner_principal_id": str(world["owner"])}))
        w = ok(client.post(f"/api/v1/cases/{ccid}/commands/record-external-work", headers=owner, json={
            "expected_version": p["record_version"], "rationale": "tracked", "external_reference": f"CONTROL-{name}"}))
        if name == "A":
            target = case["version_id"]                       # the unchanged, still running vulnerable deployment
            step("manual", "control A: a change is reported against the unchanged vulnerable deployment",
                 digest=case["deployment_digest"])
        else:
            built = lab.build("reports-api", "fixed")          # built and pushed, never deployed
            assert lab.running("reports-api") == deployed["reports-api"] != built
            target = ok(client.post(f"/api/v1/assets/{case['asset_id']}/versions", headers=analyst, json={
                "observed_at": datetime.now(timezone.utc).isoformat(), "deployment_digest": built}), 201)["id"]
            step("lab", "control B: a fixed reports-api image is built and pushed but NOT deployed", digest=built)
            step("manual", "control B: a change is reported against the undeployed fixed image")
        ok(client.post(f"/api/v1/cases/{ccid}/commands/report-change", headers=owner, json={
            "expected_version": w["record_version"], "rationale": "reported as fixed",
            "target_asset_version_id": str(target), "change_reference": f"control {name}"}))
        drain()
        h = ok(client.get(f"/api/v1/cases/{ccid}/history", headers=analyst))
        [r] = h["verifications"]
        state = ok(client.get(f"/api/v1/cases/{ccid}", headers=analyst))["workflow"]
        controls[name] = {"case": ccid, "outcome": r["outcome"], "workflow": state, "run": r["id"]}
        assert r["outcome"] != "passed" and state not in ("awaiting_verification", "closed")
    observed = run(ctx_for("analyst"), lambda s: {str(r["case_id"]): dict(r) for r in s.conn.execute(
        """SELECT o.case_id, o.rule, o.observed_deployment_digest, o.connected_address FROM axiom.verification_observations o
             JOIN axiom.verification_runs v ON v.id = o.verification_run_id""").fetchall()})
    assert controls["A"]["outcome"] == "failed" and observed[controls["A"]["case"]]["rule"] == "condition_present"
    assert controls["B"]["outcome"] == "inconclusive"
    assert observed[controls["B"]["case"]]["rule"] == "different_deployment"
    assert observed[cid]["rule"] == "condition_absent" and observed[cid]["observed_deployment_digest"] == fixed
    step("real", "control A: verification FAILED (condition present on the unchanged deployment); case is not "
         "closable", **controls["A"], rule="condition_present")
    step("real", "control B: verification INCONCLUSIVE (the service examined the running digest, not the reported "
         "one); case is not closable", **controls["B"], rule="different_deployment")

    # 7. close through the authorised human workflow and export the evidence history -------------------------
    alice = sign_in(browser, wui, keycloak, "alice", path=f"/ui/cases/{cid}/verification", tenant=world.a.slug)
    alice.get_by_test_id("verifications").locator("tr[data-outcome='passed']").wait_for()
    shot(alice, "03-worker-verification-passed")
    alice.get_by_test_id("verify-rationale").fill("worker rescan of the redeployed digest is clean; closing")
    alice.get_by_test_id("close-verified").click()
    alice.locator("text=Case closed.").wait_for()
    alice.get_by_test_id("case-workflow").filter(has_text=re.compile(r"^closed$")).wait_for()
    shot(alice, "04-case-closed-in-the-ui")
    step("real", "case closed as verified remediated in the browser by alice (analyst)")
    for name in ("A", "B"):
        page = sign_in(browser, wui, keycloak, "alice", path=f"/ui/cases/{controls[name]['case']}/verification",
                       tenant=world.a.slug)
        page.get_by_test_id("verifications").locator("tr[data-outcome]").first.wait_for()
        assert page.get_by_test_id("observed-digest").first.get_attribute("title") == deployed["reports-api"]
        shot(page, f"05-control-{name}-not-passed")
    investigations = sign_in(browser, wui, keycloak, "alice", path=f"/ui/cases/{cid}/investigations",
                             tenant=world.a.slug)
    investigations.get_by_test_id("runs").get_by_role("button", name="Open").first.click()
    investigations.get_by_test_id("run-status").wait_for()
    investigations.get_by_test_id("claim").first.wait_for()
    shot(investigations, "01-investigation-with-the-fake-model")
    with db.tenant_tx(ctx_for("system")) as c:              # the scheduled sweep runs every 15 minutes; run it now
        from axiom.domains.cases.sla import sla_sweep
        sla_sweep(c, ctx_for("system"))
    case_page = sign_in(browser, wui, keycloak, "alice", path=f"/ui/cases/{cid}", tenant=world.a.slug)
    shot(case_page, "06-decision-history-after-closure")
    history = ok(client.get(f"/api/v1/cases/{cid}/history", headers=analyst))
    package = ok(client.post(f"/api/v1/cases/{cid}/evidence-package", headers=auditor), 201)
    (OUT / "case-history.json").write_text(json.dumps(history, indent=2, default=str))
    (OUT / "evidence-package.json").write_text(json.dumps(package, indent=2, default=str))
    final = ok(client.get(f"/api/v1/cases/{cid}", headers=analyst))
    assert final["workflow"] == "closed"
    step("real", "case history and auditor evidence package exported", package=package["snapshot"]["id"],
         decisions=len(history["decisions"]))

    results = {"tested_commit": os.environ.get("AXIOM_DEMO_COMMIT"), "finished_at": datetime.now(timezone.utc).isoformat(),
               "vulnerability": VULN, "deployed_before": deployed, "orders_fixed_digest": fixed,
               "orders_case": {"id": cid, "verification": vrun["outcome"], "rule": observed[cid]["rule"],
                               "workflow": final["workflow"]},
               "controls": {k: {**v, "rule": observed[v["case"]]["rule"],
                                "observed_digest": observed[v["case"]]["observed_deployment_digest"]}
                            for k, v in controls.items()},
               "steps": STEPS}
    (OUT / "results.json").write_text(json.dumps(results, indent=2, default=str))
