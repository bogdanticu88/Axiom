"""HTTP journeys for actions, risk requests and job operations (real tokens, live PostgreSQL, fake tracker)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from axiom.db import TenantContext
from axiom.domains.actions.jobs import ActionExecuteHandler
from axiom.integrations.jira_style import JiraStyleClient, JiraStyleTicketAdapter
from axiom.jobs import Worker, WorkerConfig

from .jira_fake import JiraStyleFake
from .test_api import as_, client, upload  # noqa: F401 - pytest fixtures and helper

pytestmark = pytest.mark.db
PAYLOAD = {"project_key": "SEC", "summary": "Patch the admin panel", "description": "details", "labels": []}


def iso(**kw):
    return (datetime.now(timezone.utc) + timedelta(**kw)).isoformat()


@pytest.fixture()
def setup(client, as_, world, dbinfo):  # noqa: F811
    from axiom.provisioning import Provisioner
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["admin"], "policy_admin", world.a.root,
                                                     "api tests")
    analyst = as_("analyst")
    case = client.post("/api/v1/cases", headers=analyst, json={"scope_id": str(world.a.project),
                                                               "title": "admin panel"}).json()
    conn = client.post("/api/v1/connections", headers=as_("admin"), json={
        "adapter": "jira_style", "scope_id": str(world.a.project), "display_name": "tracker",
        "base_url": "https://tracker.test.invalid", "credential_ref": "secretref:test/tracker", "config": {}})
    assert conn.status_code == 201, conn.text
    return case, conn.json()


def run_worker(db, world, fake):
    def factory(*_):
        return JiraStyleTicketAdapter(JiraStyleClient("https://tracker.test.invalid", lambda: ("bot", "t"),
                                                      transport=fake.transport()))
    Worker(db, [ActionExecuteHandler(factory)], config=WorkerConfig(lease_seconds=1, step_timeout_seconds=2)
           ).run_once(only_tenants={world.a.id})


def test_action_journey_with_idempotent_execution(client, as_, world, setup, db):  # noqa: F811
    case, connection = setup
    analyst, approver = as_("analyst"), as_("approver")
    r = client.post("/api/v1/action-proposals", headers={**analyst, "Idempotency-Key": "prop-0001"}, json={
        "case_id": case["id"], "effect_class": "ticket.create", "connection_id": connection["id"],
        "payload": PAYLOAD, "verification_criteria": "ticket exists", "expires_at": iso(days=5)})
    assert r.status_code == 201, r.text
    proposal = r.json()
    again = client.post("/api/v1/action-proposals", headers={**analyst, "Idempotency-Key": "prop-0001"}, json={
        "case_id": case["id"], "effect_class": "ticket.create", "connection_id": connection["id"],
        "payload": PAYLOAD, "verification_criteria": "ticket exists", "expires_at": proposal["version"]["expires_at"]})
    # same key, different expires_at text -> different arguments -> rejected
    assert again.status_code == 422 and again.json()["error"]["code"] == "idempotency_key_reused"
    r = client.post(f"/api/v1/action-proposals/{proposal['id']}/versions/1/decisions", headers=approver,
                    json={"decision": "approved", "rationale": "fine", "max_uses": 1})
    assert r.status_code == 201, r.text
    approval = r.json()
    path = f"/api/v1/action-proposals/{proposal['id']}/versions/1/executions"
    missing = client.post(path, headers=analyst, json={"approval_id": approval["id"]})
    assert missing.status_code == 422 and missing.json()["error"]["code"] == "idempotency_key_required"
    first = client.post(path, headers={**analyst, "Idempotency-Key": "exec-0001"}, json={"approval_id": approval["id"]})
    replay = client.post(path, headers={**analyst, "Idempotency-Key": "exec-0001"},
                         json={"approval_id": approval["id"]})
    assert first.status_code == replay.status_code == 202
    assert first.json()["id"] == replay.json()["id"] and replay.headers["Idempotent-Replayed"] == "true"
    fake = JiraStyleFake()
    run_worker(db, world, fake)
    got = client.get(f"/api/v1/action-executions/{first.json()['id']}", headers=analyst).json()
    assert got["state"] == "succeeded" and got["external_ref"] == "SEC-1" and len(fake.issues) == 1
    exhausted = client.post(path, headers={**analyst, "Idempotency-Key": "exec-0002"},
                            json={"approval_id": approval["id"]})
    assert exhausted.status_code == 409 and exhausted.json()["error"]["code"] == "approval_exhausted"


def test_parked_execution_reconciled_through_the_api(client, as_, world, setup, db):  # noqa: F811
    case, connection = setup
    analyst, approver, admin = as_("analyst"), as_("approver"), as_("admin")
    proposal = client.post("/api/v1/action-proposals", headers=analyst, json={
        "case_id": case["id"], "effect_class": "ticket.create", "connection_id": connection["id"],
        "payload": PAYLOAD, "verification_criteria": "ticket exists", "expires_at": iso(days=5)}).json()
    approval = client.post(f"/api/v1/action-proposals/{proposal['id']}/versions/1/decisions", headers=approver,
                           json={"decision": "approved", "rationale": "fine"}).json()
    e = client.post(f"/api/v1/action-proposals/{proposal['id']}/versions/1/executions",
                    headers={**analyst, "Idempotency-Key": "exec-park-1"}, json={"approval_id": approval["id"]}).json()
    fake = JiraStyleFake(search_lag=3600)
    fake.lose_ack = 1
    run_worker(db, world, fake)
    with db.tenant_tx(TenantContext(world.a.id, world.a.system, "workload", "t")) as conn:
        conn.execute("UPDATE axiom.jobs SET due_at = clock_timestamp(), record_version = record_version + 1 "
                     "WHERE id = %s", (e["job_id"],))
    run_worker(db, world, fake)
    attention = client.get("/api/v1/jobs/attention", headers=admin).json()["items"]
    assert any(j["id"] == e["job_id"] for j in attention)
    assert client.get("/api/v1/jobs/attention", headers=analyst).status_code == 403
    denied = client.post(f"/api/v1/action-executions/{e['id']}/reconcile", headers=analyst,
                         json={"resolution": "adopt", "rationale": "x", "external_ref": "SEC-1"})
    assert denied.status_code == 403
    r = client.post(f"/api/v1/action-executions/{e['id']}/reconcile", headers=admin,
                    json={"resolution": "adopt", "rationale": "found SEC-1 with our label", "external_ref": "SEC-1"})
    assert r.status_code == 200, r.text
    run_worker(db, world, fake)
    got = client.get(f"/api/v1/action-executions/{e['id']}", headers=analyst).json()
    assert got["state"] == "succeeded" and len(fake.issues) == 1
    metrics = client.get("/api/v1/jobs/metrics", headers=admin).json()
    assert metrics["last_hour"].get("effect_needs_operator", 0) >= 1
    job = client.get(f"/api/v1/jobs/{e['job_id']}", headers=admin).json()
    assert [i["state"] for i in job["intents"]] == ["reconciled"]


def test_risk_request_and_authorise_over_http(client, as_, world, setup):  # noqa: F811
    case, _ = setup
    analyst, risk_owner, admin = as_("analyst"), as_("risk_owner"), as_("admin")
    eid = upload(client, analyst, world.a.project, b'{"finding": "admin panel"}')
    assert client.post(f"/api/v1/cases/{case['id']}/commands/start-investigation", headers=analyst,
                       json={"expected_version": 0, "rationale": "triage"}).status_code == 200
    assert client.post(f"/api/v1/cases/{case['id']}/commands/record-assessment", headers=analyst, json={
        "expected_version": 1, "rationale": "confirmed", "assessment": "supported", "limitations": "none",
        "evidence": [{"evidence_id": eid}]}).status_code == 200
    client.post("/api/v1/delegation-limits", headers=admin, json={
        "principal_id": str(world["risk_owner"]), "action_class": "risk.accept", "scope_id": str(world.a.project),
        "max_priority": "urgent", "max_duration_days": 90})
    r = client.post(f"/api/v1/cases/{case['id']}/risk-acceptance-requests", headers=analyst, json={
        "expected_version": 2, "expires_at": iso(days=30), "rationale": "compensating WAF rule"})
    assert r.status_code == 201, r.text
    req = r.json()
    assert req["independent_required"] is True
    r = client.post(f"/api/v1/risk-acceptance-requests/{req['id']}/authorise", headers=risk_owner,
                    json={"rationale": "accepted for 30 days"})
    assert r.status_code == 200, r.text
    assert r.json()["case"]["workflow"] == "closed"


def test_job_retry_requires_operate_permission_and_is_audited(client, as_, world, db, dbinfo):  # noqa: F811
    from axiom.db import TenantContext
    from axiom.jobs import Retry, enqueue
    from axiom.provisioning import Provisioner
    ctx = TenantContext(world.a.id, world.a.system, "workload", "t")
    with db.tenant_tx(ctx) as conn:
        job = enqueue(conn, ctx, kind="test.flaky", version=1, payload={}, max_attempts=1)

    class Flaky:
        kind, versions, current_version = "test.flaky", frozenset({1}), 1

        def step(self, jc):
            return Retry("boom")
    Worker(db, [Flaky()], config=WorkerConfig()).run_once(only_tenants={world.a.id})
    assert client.get(f"/api/v1/jobs/{job['id']}", headers=as_("analyst")).status_code == 403   # project scope only
    assert client.get(f"/api/v1/jobs/{job['id']}", headers=as_("auditor")).json()["state"] == "dead_lettered"
    denied = client.post(f"/api/v1/jobs/{job['id']}/retry", headers=as_("analyst"), json={"rationale": "x"})
    assert denied.status_code == 403
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["admin"], "policy_admin", world.a.root,
                                                     "operate jobs")
    r = client.post(f"/api/v1/jobs/{job['id']}/retry", headers=as_("admin"),
                    json={"rationale": "dependency fixed", "extra_attempts": 2})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "queued" and r.json()["operator_retries"] == 1 and r.json()["max_attempts"] == 3
    audit = client.get("/api/v1/audit-events", headers=as_("auditor"), params={"resource_id": job["id"]})
    assert audit.status_code == 200
    assert "job.retry" in [e["action"] for e in audit.json()]
