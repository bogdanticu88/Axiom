"""End-to-end product journey over HTTP (real tokens, live PostgreSQL, job worker), with every step labelled.

Labels used in STEPS (also written to $AXIOM_JOURNEY_LOG as JSON when set):
  real      - production code path with no stand-in (API, database, worker, policies, reports)
  fixture   - recorded real scanner output (tests/fixtures/trivy: real Trivy 0.76.1 output, see PROVENANCE.md)
  fake      - an in-process stand-in for an external system (the Jira-style tracker; fixture-tested only, never live)
  manual    - a value a person supplies through a supported command (business context, a redeploy, rescan evidence)
  test-read - a read-only database query the test uses to pick an object; not part of the product flow

Known limits shown by this journey (see REQUIREMENTS and HANDOFF): the investigation uses the deterministic fake model
(no language model was called); there is no UI; the case is moved to "remediating" by recording the ticket key (an
approved ticket does not advance the case); the redeploy and the rescan are supplied manually because no deployment or
rescanning integration exists; and the tracker is a fake.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from axiom.domains.actions.jobs import ActionExecuteHandler
from axiom.domains.actions.sync import TicketSyncHandler
from axiom.domains.evidence.service import EvidenceService
from axiom.domains.policies.service import DEFAULTS
from axiom.ingestion.pipeline import IngestionService
from axiom.ingestion.sync import SyncService
from axiom.integrations.jira_style import JiraStyleClient, JiraStyleTicketAdapter
from axiom.jobs import WorkerConfig
from axiom.workers.jobs import build_worker

from .jira_fake import JiraStyleFake
from .test_api import as_, client  # noqa: F401 - fixtures
from .test_ingestion import TRIVY

pytestmark = pytest.mark.db
STEPS: list[dict] = []


def step(label: str, what: str, **detail):
    assert label in ("real", "fixture", "fake", "manual", "test-read")
    STEPS.append({"n": len(STEPS) + 1, "label": label, "step": what, **detail})


def upload(client, headers, scope, content: bytes, media_type="application/json", classification="internal"):
    r = client.post("/api/v1/evidence", headers=headers, json={
        "scope_id": str(scope), "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
        "media_type": media_type, "classification": classification, "filename": "upload.json"})
    assert r.status_code == 201, r.text
    eid = r.json()["id"]
    assert client.put(f"/api/v1/evidence/{eid}/content", headers=headers, content=content).status_code == 200
    assert client.post(f"/api/v1/evidence/{eid}/finalise", headers=headers).json()["status"] == "verified"
    return eid


def ok(r, code=200):
    assert r.status_code == code, r.text
    return r.json()


def test_import_to_verified_closure_and_report(client, as_, world, db, dbinfo, object_store, run, ctx_for):  # noqa: F811
    STEPS.clear()
    from axiom.provisioning import Provisioner
    prov = Provisioner(dbinfo.admin_cli_dsn)
    for who in ("admin", "auditor"):                     # two policy administrators: drafting and publishing differ
        prov.bootstrap_role(world.a.id, world[who], "policy_admin", world.a.root, "journey: policy administration")
    analyst, analyst2, owner, approver = as_("analyst"), as_("analyst2"), as_("owner"), as_("approver")
    admin, auditor = as_("admin"), as_("auditor")
    project = world.a.project
    ingestion = IngestionService(db, object_store, page_size=50, lease_seconds=60)
    sync = SyncService(db, ingestion, EvidenceService(db, object_store, max_bytes=10**7))
    fake = JiraStyleFake()
    tracker = lambda *_: JiraStyleTicketAdapter(JiraStyleClient(            # noqa: E731
        "https://tracker.test.invalid", lambda: ("bot", "t"), transport=fake.transport()))
    def drain(rounds=20):
        for _ in range(rounds):
            if worker.run_once(only_tenants={world.a.id}) == 0:
                return
        raise AssertionError("worker did not settle")

    worker = build_worker(db, ingestion, sync, worker_id="journey", config=WorkerConfig(lease_seconds=5),
                          action_handler=ActionExecuteHandler(tracker), ticket_sync=TicketSyncHandler(tracker))

    # 1. import a representative finding --------------------------------------------------------------------
    report = TRIVY.read_bytes()
    ev_scan = upload(client, analyst, project, report)
    queued = ok(client.post("/api/v1/imports", headers=analyst, json={
        "evidence_id": ev_scan, "adapter": "trivy_json", "scope_id": str(project)}), 202)
    drain()
    run_row = ok(client.get(f"/api/v1/ingestion-runs/{queued['id']}", headers=analyst))
    assert (run_row["status"], run_row["coverage"]) == ("completed", "complete")
    step("fixture", "upload real Trivy 0.76.1 report (debian bullseye subset) as evidence", sha256=hashlib.sha256(report).hexdigest())
    step("real", "import through POST /imports and the job worker", run_id=run_row["id"], coverage=run_row["coverage"],
         counts=run_row["counts"])
    picked = run(ctx_for("analyst"), lambda s: s.conn.execute(
        """SELECT c.id, c.title, o.vulnerability_ref, o.source_severity, av.asset_id, av.deployment_digest
             FROM axiom.finding_cases c JOIN axiom.case_occurrence_links l ON l.case_id = c.id
             JOIN axiom.finding_occurrences o ON o.id = l.occurrence_id JOIN axiom.asset_versions av ON av.id = o.asset_version_id
            WHERE o.source_severity IN ('CRITICAL', 'HIGH') ORDER BY o.source_severity, o.vulnerability_ref LIMIT 1"""
    ).fetchone())
    cid, asset_id = str(picked["id"]), str(picked["asset_id"])
    step("test-read", "pick one imported high/critical case", case=cid, vuln=picked["vulnerability_ref"],
         severity=picked["source_severity"])

    # 2. asset and ownership context ------------------------------------------------------------------------
    ok(client.post(f"/api/v1/assets/{asset_id}/business-context", headers=analyst, json={
        "rationale": "service catalogue entry reviewed with the payments lead", "owner_ref": "payments-team",
        "criticality": "high", "environment": "production"}), 201)
    step("manual", "assert business context for the image (owner_ref, criticality, environment)")
    rules = {"rules": [{"id": "payments", "match": {"owner_ref": "payments-team"},
                        "owner_principal_id": str(world["owner"])}]}
    pol_own = ok(client.post("/api/v1/policies", headers=admin, json={
        "kind": "ownership", "definition": rules, "rationale": "route payments images"}), 201)
    ok(client.post(f"/api/v1/policies/{pol_own['id']}/publish", headers=auditor, json={"rationale": "reviewed"}))
    routed = ok(client.post(f"/api/v1/cases/{cid}/ownership/route", headers=analyst))
    assert routed["basis"] == "rule" and routed["owner_principal_id"] == str(world["owner"])
    step("real", "versioned ownership policy drafted, published by a second person, case routed by rule",
         policy=pol_own["id"], rule=routed["rule_id"])

    # 3. investigate (snapshot, AI-assisted run, human review) and record uncertainty ------------------------
    route = ok(client.post("/api/v1/model-routes", headers=admin, json={
        "name": "ci-fake", "provider": "deterministic_fake", "model": "fake-rules-v1", "endpoint": "fake://ci-fake",
        "region": "local", "max_classification": "internal", "rationale": "CI route (deterministic fake)"}), 201)
    ok(client.post(f"/api/v1/model-routes/{route['id']}/approve", headers=auditor, json={"rationale": "reviewed"}))
    started_run = ok(client.post(f"/api/v1/cases/{cid}/investigations", headers={**analyst, "Idempotency-Key": "jr-inv-1"},
                                 json={"questions": ["Is the reported vulnerability present in the deployed image?"],
                                       "route": "ci-fake"}), 202)
    drain()
    inv_run = ok(client.get(f"/api/v1/investigations/{started_run['id']}", headers=analyst))
    assert inv_run["status"] == "completed", inv_run["outcome_reason"]
    snapshot = ok(client.get(f"/api/v1/evidence-snapshots/{inv_run['snapshot_id']}", headers=analyst))
    assert snapshot["digest_verified"] and snapshot["member_count"] == len(snapshot["members"])
    step("real", "evidence snapshot frozen (observations, run coverage and freshness, asset version, gaps)",
         snapshot=snapshot["id"], members=snapshot["member_count"], gaps=[g["kind"] for g in snapshot["gaps"]])
    step("fake", "investigation run through the model gateway with the deterministic fake model (not a language "
         "model); claims validated against the snapshot", run=inv_run["id"], claims=len(inv_run["claims"]),
         model_calls=inv_run["model_calls"], tool_calls=inv_run["tool_calls"])
    early = client.post(f"/api/v1/cases/{cid}/commands/start-investigation", headers=analyst,
                        json={"expected_version": 0, "rationale": "imported high-severity package vulnerability"})
    ok(early)
    blocked = client.post(f"/api/v1/cases/{cid}/commands/record-assessment", headers=analyst, json={
        "expected_version": 1, "assessment": "supported", "rationale": "x", "limitations": "x",
        "evidence": [{"evidence_id": ev_scan}], "investigation_run_id": inv_run["id"]})
    assert blocked.status_code == 409 and blocked.json()["error"]["code"] == "claims_not_reviewed"
    for cl in inv_run["claims"]:
        if cl["validation"] != "rejected":
            ok(client.post(f"/api/v1/investigation-claims/{cl['id']}/reviews", headers=analyst2, json={
                "verdict": "confirmed", "note": "checked the cited observation and run coverage"}), 201)
    step("manual", "a second analyst reviews each claim (confirmed after checking the cited members)")
    assessed = ok(client.post(f"/api/v1/cases/{cid}/commands/record-assessment", headers=analyst, json={
        "expected_version": 1, "assessment": "supported", "rationale": "investigation and scan agree; reviewed",
        "limitations": "reachability not analysed; no runtime evidence; scanner data only",
        "evidence": [{"evidence_id": ev_scan}], "investigation_run_id": inv_run["id"]}))
    history = ok(client.get(f"/api/v1/cases/{cid}/history", headers=analyst))
    adec = [d for d in history["decisions"] if d["kind"] == "assessment"][0]
    assert adec["investigation_run_id"] == inv_run["id"] and adec["evidence_snapshot_id"] == snapshot["id"]
    step("real", "human assessment cites the reviewed run and its snapshot; limitations include the run's and "
         "the snapshot's gaps")

    # 4. versioned priority policy --------------------------------------------------------------------------
    pol_prio = ok(client.post("/api/v1/policies", headers=admin, json={
        "kind": "priority", "definition": DEFAULTS["priority"], "rationale": "adopt provisional matrix"}), 201)
    ok(client.post(f"/api/v1/policies/{pol_prio['id']}/publish", headers=auditor, json={"rationale": "reviewed"}))
    prioritised = ok(client.post(f"/api/v1/cases/{cid}/commands/apply-priority-policy", headers=analyst, json={
        "expected_version": assessed["record_version"], "rationale": "apply published policy"}))
    sev = picked["source_severity"].lower()
    assert prioritised["priority"] == DEFAULTS["priority"]["matrix"][sev]["high"]
    history = ok(client.get(f"/api/v1/cases/{cid}/history", headers=analyst))
    pdec = [d for d in history["decisions"] if d["kind"] == "prioritisation"][0]
    assert pdec["policy_version_id"] == pol_prio["id"]
    step("real", "priority from published policy and asserted criticality (no direct database injection)",
         priority=prioritised["priority"], policy=pol_prio["id"], provisional=True)

    # 5. approve a remediation ticket -----------------------------------------------------------------------
    planned = ok(client.post(f"/api/v1/cases/{cid}/commands/plan-remediation", headers=analyst, json={
        "expected_version": prioritised["record_version"], "rationale": "upgrade base image",
        "owner_principal_id": str(world["owner"])}))
    conn = ok(client.post("/api/v1/connections", headers=admin, json={
        "adapter": "jira_style", "scope_id": str(project), "display_name": "tracker (fake)",
        "base_url": "https://tracker.test.invalid", "credential_ref": "secretref:test/tracker", "config": {}}), 201)
    expires = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    proposal = ok(client.post("/api/v1/action-proposals", headers={**analyst, "Idempotency-Key": "journey-prop-1"}, json={
        "case_id": cid, "effect_class": "ticket.create", "connection_id": conn["id"],
        "payload": {"project_key": "SEC", "summary": f"Upgrade image: {picked['vulnerability_ref']}",
                    "description": "see case", "labels": ["security"]},
        "verification_criteria": "ticket exists in SEC", "expires_at": expires}), 201)
    approval = ok(client.post(f"/api/v1/action-proposals/{proposal['id']}/versions/1/decisions", headers=approver,
                              json={"decision": "approved", "rationale": "in policy", "max_uses": 1}), 201)
    execution = ok(client.post(f"/api/v1/action-proposals/{proposal['id']}/versions/1/executions",
                               headers={**analyst, "Idempotency-Key": "journey-exec-1"},
                               json={"approval_id": approval["id"]}), 202)
    drain()
    done = ok(client.get(f"/api/v1/action-executions/{execution['id']}", headers=analyst))
    assert done["state"] == "succeeded" and done["external_ref"] == "SEC-1" and len(fake.issues) == 1
    step("real", "proposal approved by a different person; execution through the effect gate")
    step("fake", "ticket created in the in-process Jira-style fake (fixture-tested adapter, no live tracker)",
         ticket=done["external_ref"])
    started = ok(client.post(f"/api/v1/cases/{cid}/commands/record-external-work", headers=owner, json={
        "expected_version": planned["record_version"], "rationale": "work tracked in SEC-1",
        "external_reference": done["external_ref"]}))
    step("manual", "owner records the ticket as the external work (an approved ticket does not advance the case)")

    # 6. synchronise external status ------------------------------------------------------------------------
    fake.set_status("SEC-1", "Done", "done")
    with db.tenant_tx(ctx_for("system")) as c:
        from axiom.jobs import enqueue
        enqueue(c, ctx_for("system"), kind="actions.ticket_sync", version=1, payload={})
    drain()
    ref_id = done["external_references"][0]["id"]
    states = ok(client.get(f"/api/v1/external-references/{ref_id}/states", headers=analyst))["states"]
    assert states[-1]["status_category"] == "done"
    still = ok(client.get(f"/api/v1/cases/{cid}", headers=analyst))
    assert still["workflow"] == "remediating"                # a closed ticket never closes or advances the case
    step("fake", "tracker marks SEC-1 Done; inbound sync records it; case is not moved by it")

    # 7. verify the affected deployment ---------------------------------------------------------------------
    new_digest = "sha256:" + hashlib.sha256(b"journey rebuilt image").hexdigest()
    new_version = ok(client.post(f"/api/v1/assets/{asset_id}/versions", headers=analyst, json={
        "observed_at": datetime.now(timezone.utc).isoformat(), "deployment_digest": new_digest}), 201)
    step("manual", "analyst records the redeployed image as a new asset version (no deployment integration)", digest=new_digest)
    reported = ok(client.post(f"/api/v1/cases/{cid}/commands/report-change", headers=owner, json={
        "expected_version": started["record_version"], "rationale": "rebuilt on patched base",
        "target_asset_version_id": new_version["id"], "change_reference": "SEC-1 deploy"}))
    doc = json.loads(report)
    doc["Results"][0]["Vulnerabilities"] = [v for v in doc["Results"][0]["Vulnerabilities"]
                                            if v["VulnerabilityID"] != picked["vulnerability_ref"]]
    doc["Metadata"]["ImageID"] = new_digest
    rescan = upload(client, analyst2, project, json.dumps(doc).encode())
    step("manual", "rescan evidence: the Trivy fixture with the finding removed (synthetic, not scanner output)")
    verified = ok(client.post(f"/api/v1/cases/{cid}/commands/record-verification", headers=analyst2, json={
        "expected_version": reported["record_version"], "rationale": "rescan of the deployed digest is clean",
        "claimed_result": "passed", "coverage": "complete", "criteria": {"vulnerability": picked["vulnerability_ref"],
                                                                        "deployment_digest": new_digest},
        "observed_deployment_digest": new_digest, "evidence_id": rescan}))
    assert verified["workflow"] == "awaiting_verification"
    run_id = ok(client.get(f"/api/v1/cases/{cid}/history", headers=analyst2))["verifications"][-1]["id"]
    step("real", "independent verifier (not the reporter) records a passed verification bound to the deployed digest")

    # 8. close with evidence --------------------------------------------------------------------------------
    closed = ok(client.post(f"/api/v1/cases/{cid}/commands/close-verified", headers=analyst2, json={
        "expected_version": verified["record_version"], "rationale": "verified remediated",
        "verification_run_id": run_id}))
    assert closed["workflow"] == "closed"
    step("real", "closed as verified remediated with the verification run and its evidence")

    # 9. report the result and coverage limitations ---------------------------------------------------------
    with db.tenant_tx(ctx_for("system")) as c:              # the schedule runs these every 15 minutes; enqueue now
        from axiom.jobs import enqueue
        enqueue(c, ctx_for("system"), kind="cases.ownership_sweep", version=1, payload={})
    drain()
    with db.tenant_tx(ctx_for("system")) as c:
        from axiom.domains.cases.sla import sla_sweep
        sla_sweep(c, ctx_for("system"))
    sla = ok(client.get(f"/api/v1/cases/{cid}/sla", headers=analyst))["items"]
    assert {(t["kind"], t["status"]) for t in sla} >= {("triage", "met"), ("remediation", "met")}
    snap = ok(client.post("/api/v1/reports/snapshots", headers=auditor, json={
        "kind": "exposure_summary", "scope_id": str(project)}), 201)
    content = snap["content"]
    assert content["closed_by_reason"] == {"verified_remediated": 1}
    [src] = content["coverage_by_source"]
    assert (src["source"], src["completeness"], src["freshness"]) == ("file_import:trivy_json", "complete", "fresh")
    assert content["unknowns"]["unprioritised_open_cases"] == content["denominators"]["cases"]["open"] > 0
    assert content["freshness_policy"]["provisional"] is True
    # the scheduled sweep re-routed the other cases once the policy and context existed (same image, same owner)
    assert content["unknowns"]["open_cases_without_resolved_owner"] == 0
    queue = ok(client.get("/api/v1/ownership/unresolved", headers=analyst))
    assert queue["items"] == []
    pkg = ok(client.post(f"/api/v1/cases/{cid}/evidence-package", headers=auditor), 201)
    body = pkg["snapshot"]["content"]
    assert {p["kind"] for p in body["policy_versions"]} == {"priority"}
    assert body["withheld_evidence"] == 2 and body["withheld_metadata"] == 2   # no evidence.read/metadata grants
    step("real", "ownership sweep job (enqueued by the test instead of waiting 15 minutes) re-routed the other "
         "unresolved cases after the policy and context appeared")
    step("real", "snapshot shows verified closure, per-source coverage and the open unprioritised remainder",
         closed=content["closed_by_reason"], open=content["denominators"]["cases"]["open"],
         unprioritised=content["unknowns"]["unprioritised_open_cases"], source=src["source"],
         completeness=src["completeness"], freshness=src["freshness"])
    step("real", "auditor evidence package; evidence content withheld for lack of classification access",
         withheld=body["withheld_evidence"])
    labels = {s["label"] for s in STEPS}
    assert labels == {"real", "fixture", "fake", "manual", "test-read"}
    assert not any("assessment with explicit limitations (no investigation" in x["step"] for x in STEPS)
    if os.environ.get("AXIOM_JOURNEY_LOG"):
        with open(os.environ["AXIOM_JOURNEY_LOG"], "w") as fh:
            json.dump(STEPS, fh, indent=2, default=str)
