"""End-to-end API journeys through HTTP (FastAPI TestClient), real tokens, live PostgreSQL."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from axiom.api.app import create_app
from axiom.config import Settings

pytestmark = pytest.mark.db


@pytest.fixture()
def client(dbinfo, db, issuer, object_store):
    settings = Settings(env="test", database_dsn=dbinfo.app_dsn, trusted_issuers_json=json.dumps(
        [{"issuer": issuer.issuer, "audience": issuer.audience, "jwks": issuer.jwks()}]))
    with TestClient(create_app(settings, db=db, store=object_store)) as c:
        yield c


@pytest.fixture()
def as_(world, issuer):
    def headers(name: str, tenant: str | None = "a") -> dict:
        h = {"Authorization": f"Bearer {issuer.token(world.subjects[name])}"}
        if tenant:
            h["X-Axiom-Tenant"] = (world.a if tenant == "a" else world.b).slug
        return h
    return headers


def upload(client, headers, scope, content: bytes) -> str:
    r = client.post("/api/v1/evidence", headers=headers, json={
        "scope_id": str(scope), "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
        "media_type": "application/json", "classification": "internal", "filename": "scan.json"})
    assert r.status_code == 201, r.text
    eid = r.json()["id"]
    assert client.put(f"/api/v1/evidence/{eid}/content", headers=headers, content=content).status_code == 200
    r = client.post(f"/api/v1/evidence/{eid}/finalise", headers=headers)
    assert r.json()["status"] == "verified", r.text
    return eid


def cmd(client, headers, case_id, name, **body):
    return client.post(f"/api/v1/cases/{case_id}/commands/{name}", headers=headers, json=body)


def test_analyst_journey_to_verified_closure(client, as_, world):
    analyst, owner, analyst2 = as_("analyst"), as_("owner"), as_("analyst2")
    now = datetime.now(timezone.utc).isoformat()
    asset = client.post("/api/v1/assets", headers=analyst, json={
        "scope_id": str(world.a.project), "kind": "container_image", "display_name": "api"}).json()
    old = client.post(f"/api/v1/assets/{asset['id']}/versions", headers=analyst, json={
        "observed_at": now, "deployment_digest": "sha256:" + "1" * 64}).json()
    new = client.post(f"/api/v1/assets/{asset['id']}/versions", headers=analyst, json={
        "observed_at": now, "deployment_digest": "sha256:" + "2" * 64}).json()
    occ = client.post("/api/v1/occurrences", headers=analyst, json={
        "source_system": "trivy", "source_finding_id": "x1", "asset_version_id": old["id"],
        "vulnerability_ref": "CVE-2099-1"}).json()
    r = client.post("/api/v1/cases", headers=analyst, json={
        "scope_id": str(world.a.project), "title": "CVE-2099-1 in api", "occurrence_ids": [occ["id"]]})
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    ev = upload(client, analyst, world.a.project, b'{"finding":"CVE-2099-1"}')
    steps = [
        (analyst, "start-investigation", {}),
        (analyst, "record-assessment", {"assessment": "supported", "limitations": "no runtime trace",
                                        "evidence": [{"evidence_id": ev}]}),
        (analyst, "plan-remediation", {"owner_principal_id": str(world["owner"])}),
        (owner, "record-external-work", {"external_reference": "JIRA-9"}),
        (owner, "report-change", {"target_asset_version_id": new["id"], "change_reference": "deploy 9"}),
    ]
    for version, (who, name, body) in enumerate(steps):
        r = cmd(client, who, cid, name, expected_version=version, rationale=f"step {name}", **body)
        assert r.status_code == 200, (name, r.text)
    check = upload(client, analyst2, world.a.project, b'{"rescan":"clean"}')
    r = cmd(client, analyst2, cid, "record-verification", expected_version=5, rationale="rescan",
            claimed_result="passed", coverage="complete", criteria={"cve": "CVE-2099-1"},
            observed_deployment_digest="sha256:" + "2" * 64, evidence_id=check)
    assert r.status_code == 200 and r.json()["workflow"] == "awaiting_verification", r.text
    history = client.get(f"/api/v1/cases/{cid}/history", headers=analyst2).json()
    run_id = history["verifications"][0]["id"]
    r = cmd(client, analyst2, cid, "close-verified", expected_version=6, rationale="verified",
            verification_run_id=run_id)
    assert r.status_code == 200 and r.json()["workflow"] == "closed", r.text
    # Every material decision links to evidence the analyst can follow (journey: analyst follows conclusions).
    decisions = client.get(f"/api/v1/cases/{cid}/history", headers=analyst).json()["decisions"]
    assessment = next(d for d in decisions if d["kind"] == "assessment")
    assert assessment["evidence"][0]["evidence_id"] == ev
    content = client.get(f"/api/v1/evidence/{ev}/content", headers=analyst, params={"purpose": "review"})
    assert content.status_code == 200 and content.content == b'{"finding":"CVE-2099-1"}'


def test_conflicts_and_structured_errors(client, as_, world):
    analyst = as_("analyst")
    cid = client.post("/api/v1/cases", headers=analyst, json={"scope_id": str(world.a.project), "title": "t"}).json()["id"]
    assert cmd(client, analyst, cid, "start-investigation", expected_version=0, rationale="go").status_code == 200
    r = cmd(client, analyst, cid, "start-investigation", expected_version=0, rationale="again")
    assert r.status_code == 409
    err = r.json()["error"]
    assert err["code"] == "stale_version" and err["correlation_id"] and err["retryable"] is False
    r = cmd(client, analyst, cid, "dismiss", expected_version=1, rationale="skip review")
    assert r.status_code in (403, 409)


def test_client_cannot_assert_authority_or_tenant(client, as_, world):
    analyst = as_("analyst")
    r = client.post("/api/v1/cases", headers=analyst, json={
        "scope_id": str(world.a.project), "title": "t", "tenant_id": str(world.b.id)})
    assert r.status_code == 422
    cid = client.post("/api/v1/cases", headers=analyst, json={"scope_id": str(world.a.project), "title": "t"}).json()["id"]
    r = cmd(client, analyst, cid, "start-investigation", expected_version=0, rationale="go", verified=True)
    assert r.status_code == 422
    assert client.patch(f"/api/v1/cases/{cid}", headers=analyst, json={"workflow": "closed"}).status_code in (404, 405)


def test_authentication_and_tenant_selection(client, as_, world, issuer):
    assert client.get("/api/v1/cases").status_code == 401
    assert client.get("/api/v1/cases", headers={"Authorization": "Bearer junk", "X-Axiom-Tenant": world.a.slug}).status_code == 401
    assert client.get("/api/v1/cases", headers=as_("analyst", tenant=None)).status_code == 403
    r = client.get("/api/v1/cases", headers=as_("analyst", tenant="b"))
    assert r.status_code == 403 and r.json()["error"]["code"] == "tenant_not_available"
    me = client.get("/api/v1/me", headers=as_("consultant", tenant=None)).json()
    assert {t["slug"] for t in me["tenants"]} == {world.a.slug, world.b.slug}
    op = client.get("/api/v1/me", headers=as_("operator", tenant=None)).json()
    assert op["installation_roles"] == ["installation_operator"] and op["tenants"] == []
    assert client.get("/api/v1/cases", headers=as_("operator")).status_code == 403


def test_cross_tenant_access_through_api_is_denied(client, as_, world):
    """A13 via API: case, history, evidence metadata/content and audit paths."""
    analyst = as_("analyst")
    cid = client.post("/api/v1/cases", headers=analyst, json={"scope_id": str(world.a.project), "title": "a"}).json()["id"]
    ev = upload(client, analyst, world.a.project, b"tenant a evidence")
    b = as_("consultant", tenant="b")
    for path in (f"/api/v1/cases/{cid}", f"/api/v1/cases/{cid}/history", f"/api/v1/evidence/{ev}",
                 f"/api/v1/evidence/{ev}/content?purpose=x"):
        assert client.get(path, headers=b).status_code == 404, path
    assert cmd(client, b, cid, "start-investigation", expected_version=0, rationale="x").status_code == 404
    listed = client.get("/api/v1/cases", headers=b).json()["items"]
    assert all(item["tenant_id"] == str(world.b.id) for item in listed)


def test_audit_read_requires_explicit_permission(client, as_, world):
    assert client.get("/api/v1/audit-events", headers=as_("admin")).status_code == 403
    r = client.get("/api/v1/audit-events", headers=as_("auditor"))
    assert r.status_code == 200 and r.json()


def test_pagination(client, as_, world):
    analyst = as_("analyst")
    for i in range(5):
        client.post("/api/v1/cases", headers=analyst, json={"scope_id": str(world.a.project), "title": f"p{i}"})
    page1 = client.get("/api/v1/cases", headers=analyst, params={"limit": 3}).json()
    page2 = client.get("/api/v1/cases", headers=analyst, params={"limit": 3, "cursor": page1["next_cursor"]}).json()
    ids = [c["id"] for c in page1["items"] + page2["items"]]
    assert len(ids) == len(set(ids)) == 5


def test_ingestion_journey_through_api(client, as_, world, db, object_store):
    """Operator/analyst journey: upload a real Trivy report, import it, inspect run, cases and asset."""
    from pathlib import Path
    from axiom.domains.evidence.service import EvidenceService
    from axiom.ingestion.pipeline import IngestionService
    from axiom.ingestion.sync import SyncService
    from axiom.workers.jobs import build_worker
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    analyst = as_("analyst")
    report = (fixtures / "trivy/debian-bullseye-20230612-slim.subset.json").read_bytes()
    ev = upload(client, analyst, world.a.project, report)
    r = client.post("/api/v1/imports", headers=analyst, json={"evidence_id": ev, "adapter": "trivy_json",
                                                             "scope_id": str(world.a.project)})
    assert r.status_code == 202 and r.json()["status"] == "queued", r.text
    run_id = r.json()["id"]
    ingestion = IngestionService(db, object_store)
    worker = build_worker(db, ingestion, SyncService(db, ingestion, EvidenceService(db, object_store, max_bytes=10**7)),
                          worker_id="api-test-worker")
    assert worker.run_once(only_tenants={world.a.id}) >= 1     # the job created with the import runs it
    got = client.get(f"/api/v1/ingestion-runs/{run_id}", headers=analyst).json()
    assert got["status"] == "completed" and got["coverage"] == "complete" and got["quarantined"] == []
    listed = client.get("/api/v1/ingestion-runs", headers=as_("viewer")).json()["items"]
    assert any(i["id"] == run_id for i in listed)
    cases = client.get("/api/v1/cases", headers=analyst, params={"limit": 200}).json()["items"]
    assert cases and all(c["workflow"] == "received" for c in cases)
    history = client.get(f"/api/v1/cases/{cases[0]['id']}/history", headers=analyst).json()
    assert history["events"][0]["event_type"] == "case.created"
    adapters = {a["name"]: a["support_level"] for a in client.get("/api/v1/adapters", headers=analyst).json()["items"]}
    assert adapters["trivy_json"] == "fixture-tested" and adapters["jira"] == "planned"
    # Unknown adapter and a body smuggling a tenant are rejected.
    assert client.post("/api/v1/imports", headers=analyst, json={"evidence_id": ev, "adapter": "nessus_xml",
                                                                "scope_id": str(world.a.project)}).status_code == 422
    assert client.post("/api/v1/imports", headers=analyst, json={"evidence_id": ev, "adapter": "trivy_json",
                       "scope_id": str(world.a.project), "tenant_id": str(world.b.id)}).status_code == 422


def test_identity_candidate_review_through_api(client, as_, world, db, object_store):
    from pathlib import Path
    from axiom.ingestion.pipeline import IngestionService
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    analyst = as_("analyst")
    ev = upload(client, analyst, world.a.project, (fixtures / "tenable/synthetic-vulns-chunk-1.json").read_bytes())
    run_id = client.post("/api/v1/imports", headers=analyst, json={
        "evidence_id": ev, "adapter": "tenable_vm", "scope_id": str(world.a.project)}).json()["id"]
    IngestionService(db, object_store).execute(world.a.id, world.a.system, __import__("uuid").UUID(run_id),
                                               worker_id="api-test")
    run = client.get(f"/api/v1/ingestion-runs/{run_id}", headers=analyst).json()
    assert run["coverage"] == "partial" and run["quarantined"][0]["reason_code"] == "missing_asset_uuid"
    cands = client.get("/api/v1/identity-candidates", headers=analyst).json()["items"]
    assert len(cands) == 1 and len(cands[0]["assets"]) == 2
    cid = cands[0]["id"]
    assert client.post(f"/api/v1/identity-candidates/{cid}/resolve", headers=as_("viewer"), json={
        "expected_version": 0, "outcome": "confirmed_same", "rationale": "x"}).status_code == 403
    r = client.post(f"/api/v1/identity-candidates/{cid}/resolve", headers=analyst, json={
        "expected_version": 0, "outcome": "confirmed_distinct", "rationale": "different VMs behind one DNS name"})
    assert r.status_code == 200 and r.json()["status"] == "confirmed_distinct"
    assert client.post(f"/api/v1/identity-candidates/{cid}/resolve", headers=analyst, json={
        "expected_version": 0, "outcome": "dismissed", "rationale": "again"}).status_code == 409
    asset = client.get(f"/api/v1/assets/{cands[0]['assets'][0]['id']}", headers=analyst).json()
    assert {i["strength"] for i in asset["identifiers"]} == {"strong", "weak"}
    assert client.get(f"/api/v1/assets/{cands[0]['assets'][0]['id']}", headers=as_("consultant", tenant="b")).status_code == 404
