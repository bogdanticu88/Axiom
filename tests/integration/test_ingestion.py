"""Phase B ingestion pipeline against live PostgreSQL (runtime role, RLS) and the filesystem object store."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest

from axiom.access import PermissionDenied
from axiom.domains.cases.service import EvidenceRef
from axiom.errors import NotFound
from axiom.ingestion.pipeline import IngestionService, LeaseLost

pytestmark = pytest.mark.db
FIX = Path(__file__).resolve().parent.parent / "fixtures"
TRIVY = FIX / "trivy/debian-bullseye-20230612-slim.subset.json"
DIGEST = "sha256:924df86f8aad741a0134b2de7d8e70c5c6863f839caadef62609c1be1340daf5"


@pytest.fixture()
def ingest(db, object_store):
    return IngestionService(db, object_store, page_size=7, lease_seconds=60)


@pytest.fixture()
def importer(world, ctx_for, upload, ingest):
    """Upload bytes as evidence and import them; returns (run_row, evidence_row)."""
    def _import(data: bytes, adapter: str, *, who="analyst", declared=None, execute=True, worker="w1", **kw):
        ctx = ctx_for(who)
        ev = upload(ctx, world.a.project, data, classification="internal")
        run = ingest.request_import(ctx, evidence_id=ev["id"], adapter=adapter, scope_id=world.a.project,
                                    declared_subject=declared)
        if execute:
            run = ingest.execute(world.a.id, world.a.system, run["id"], worker_id=worker, **kw)
        return run, ev
    return _import


def q(run, ctx, sql, *args):
    return run(ctx, lambda s: s.conn.execute(sql, args).fetchall())


def counts(run, ctx):
    return run(ctx, lambda s: {t: s.conn.execute(f"SELECT count(*) AS n FROM axiom.{t}").fetchone()["n"] for t in (
        "finding_occurrences", "finding_cases", "case_events", "decisions", "source_records", "observations",
        "occurrence_observations", "assets", "asset_versions", "identity_candidates", "quarantined_records")})


def test_trivy_import_preserves_original_and_correlates(world, run, ctx_for, importer):
    result, ev = importer(TRIVY.read_bytes(), "trivy_json")
    assert result["status"] == "completed" and result["coverage"] == "complete", result
    c = result["counts"]
    assert c["findings"] == 30 and c["occurrences_new"] == 30 and c["quarantined"] == 0
    analyst = ctx_for("analyst")
    obs = q(run, analyst, "SELECT raw_evidence_id, raw_locator, normalised FROM axiom.observations WHERE run_id = %s",
            result["id"])
    assert len(obs) == 30 and {o["raw_evidence_id"] for o in obs} == {ev["id"]}
    assert all(o["raw_locator"].startswith("/Results/0/Vulnerabilities/") for o in obs)
    versions = q(run, analyst, "SELECT deployment_digest FROM axiom.asset_versions")
    assert [v["deployment_digest"] for v in versions] == [DIGEST]
    distinct_cves = len({o["normalised"]["vulnerability_id"] for o in obs})
    assert c["cases_created"] == distinct_cves and c["cases_linked"] == 30 - distinct_cves
    cases = q(run, analyst, "SELECT workflow FROM axiom.finding_cases")
    assert len(cases) == distinct_cves and {x["workflow"] for x in cases} == {"received"}
    # Every case was created through the command layer: audited event at version 0 (and links after).
    assert q(run, analyst, "SELECT count(*) AS n FROM axiom.case_events WHERE audit_event_id IS NULL")[0]["n"] == 0


def test_replayed_import_creates_no_duplicates(world, run, ctx_for, importer):
    """A01: same report imported twice; no duplicate occurrences, cases, events or decisions."""
    analyst = ctx_for("analyst")
    importer(TRIVY.read_bytes(), "trivy_json")
    before = counts(run, analyst)
    second, _ = importer(TRIVY.read_bytes(), "trivy_json")
    after = counts(run, analyst)
    assert second["counts"]["occurrences_new"] == 0 and second["counts"]["cases_created"] == 0
    for table in ("finding_occurrences", "finding_cases", "case_events", "decisions", "source_records",
                  "assets", "asset_versions"):
        assert after[table] == before[table], table
    assert after["observations"] == before["observations"] + 30          # history: seen again in run 2
    assert after["occurrence_observations"] == before["occurrence_observations"] + 30


def test_resume_after_in_process_crash_skips_committed_pages(world, run, ctx_for, importer, ingest):
    analyst = ctx_for("analyst")

    def crash(page):
        if page == 1:
            raise RuntimeError("simulated crash after page 1")
    with pytest.raises(RuntimeError):
        importer(TRIVY.read_bytes(), "trivy_json", on_page_committed=crash)
    pending = q(run, analyst, "SELECT * FROM axiom.ingestion_runs WHERE status = 'running'")[0]
    assert pending["counts"]["pages_committed"] == 2
    # The lease is still live: another worker cannot take over yet.
    assert ingest.execute(world.a.id, world.a.system, pending["id"], worker_id="w2") is None
    _expire_lease(run, ctx_for, pending["id"])
    done = ingest.execute(world.a.id, world.a.system, pending["id"], worker_id="w2")
    assert done["status"] == "completed" and done["counts"]["pages_skipped"] == 2
    assert done["counts"]["findings"] == 30 and done["attempts"] == 2
    assert len(q(run, analyst, "SELECT 1 FROM axiom.finding_occurrences")) == 30


def _expire_lease(run, ctx_for, run_id):
    system = ctx_for("system")
    run(system, lambda s: s.conn.execute(
        """UPDATE axiom.ingestion_runs SET lease_expires_at = clock_timestamp() - interval '1 second',
                  record_version = record_version + 1 WHERE id = %s""", (run_id,)))


def test_stale_worker_is_fenced(world, run, ctx_for, importer, ingest):
    queued, _ = importer(TRIVY.read_bytes(), "trivy_json", execute=False)
    system = ctx_for("system")
    stale = ingest._claim(system, queued["id"], "worker-a")
    _expire_lease(run, ctx_for, queued["id"])
    fresh = ingest._claim(system, queued["id"], "worker-b")
    assert fresh.lease_token == stale.lease_token + 1
    with pytest.raises((LeaseLost, psycopg.errors.SerializationFailure)):
        ingest._commit_page(system, stale, "file:0", "0" * 64, [], raw_evidence_id=queued["raw_evidence_id"])
    assert q(run, ctx_for("analyst"), "SELECT count(*) AS n FROM axiom.ingestion_pages WHERE run_id = %s",
             queued["id"])[0]["n"] == 0


def test_real_process_kill_then_resume(world, run, ctx_for, importer, dbinfo, object_store, tmp_path):
    """Worker process SIGKILLed after committing page 1; a new process resumes without duplicates."""
    queued, _ = importer(TRIVY.read_bytes(), "trivy_json", execute=False)
    script = Path(__file__).with_name("ingest_child.py")
    env = {**os.environ, "CHILD_DSN": dbinfo.app_dsn, "CHILD_STORE": str(object_store.root),
           "CHILD_TENANT": str(world.a.id), "CHILD_SYSTEM": str(world.a.system), "CHILD_RUN": str(queued["id"])}
    proc = subprocess.run([sys.executable, str(script), "kill-after-page", "1"], env=env, capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == -signal.SIGKILL, (proc.returncode, proc.stderr[-2000:])
    mid = q(run, ctx_for("analyst"), "SELECT status, counts FROM axiom.ingestion_runs WHERE id = %s", queued["id"])[0]
    assert mid["status"] == "running" and mid["counts"]["pages_committed"] == 2
    _expire_lease(run, ctx_for, queued["id"])
    proc = subprocess.run([sys.executable, str(script), "run"], env=env, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr[-2000:]
    final = json.loads(proc.stdout.strip().splitlines()[-1])
    assert final["status"] == "completed" and final["counts"]["pages_skipped"] == 2
    assert len(q(run, ctx_for("analyst"), "SELECT 1 FROM axiom.finding_occurrences")) == 30


def test_partial_scan_closes_nothing_and_complete_rescan_records_absence(world, run, ctx_for, importer):
    """A03 and B04."""
    analyst = ctx_for("analyst")
    full = TRIVY.read_bytes()
    importer(full, "trivy_json")
    open_before = q(run, analyst, "SELECT count(*) AS n FROM axiom.finding_cases WHERE workflow <> 'closed'")[0]["n"]
    doc = json.loads(full)
    vulns = doc["Results"][0]["Vulnerabilities"]
    doc["Results"][0]["Vulnerabilities"] = vulns[:15] + [{"VulnerabilityID": "CVE-2099-9"}]   # half + invalid
    partial, _ = importer(json.dumps(doc).encode(), "trivy_json")
    assert partial["coverage"] == "partial" and partial["counts"]["quarantined"] == 1
    assert partial["counts"].get("absent_in_complete_scan", 0) == 0
    doc["Results"][0]["Vulnerabilities"] = vulns[:15]
    complete, _ = importer(json.dumps(doc).encode(), "trivy_json")
    assert complete["coverage"] == "complete" and complete["counts"]["absent_in_complete_scan"] == 15
    absent = q(run, analyst, "SELECT count(*) AS n FROM axiom.occurrence_observations WHERE observed_status = "
                             "'absent_in_complete_scan'")[0]["n"]
    assert absent == 15
    open_after = q(run, analyst, "SELECT count(*) AS n FROM axiom.finding_cases WHERE workflow <> 'closed'")[0]["n"]
    assert open_after == open_before                     # absence never closes a case


def test_tenable_identity_uncertainty_quarantine_and_source_fix(world, run, ctx_for, importer):
    analyst = ctx_for("analyst")
    result, _ = importer((FIX / "tenable/synthetic-vulns-chunk-1.json").read_bytes(), "tenable_vm")
    assert result["coverage"] == "partial" and result["counts"]["quarantined"] == 1
    assets = q(run, analyst, "SELECT id, identity_status FROM axiom.assets ORDER BY created_at")
    assert len(assets) == 2                               # same hostname/IP, different Tenable UUIDs: not merged
    cands = q(run, analyst, "SELECT method, asset_ids, matched_identifiers, status FROM axiom.identity_candidates")
    assert len(cands) == 1 and cands[0]["method"] == "weak_identifier_overlap" and cands[0]["status"] == "open"
    assert {m["namespace"] for m in cands[0]["matched_identifiers"]} >= {"hostname", "ipv4"}
    weak = q(run, analyst, "SELECT namespace, count(DISTINCT asset_id) AS n FROM axiom.asset_identifiers "
                           "WHERE strength = 'weak' GROUP BY namespace")
    assert {w["namespace"]: w["n"] for w in weak}["hostname"] == 2
    statuses = q(run, analyst, "SELECT observed_status FROM axiom.occurrence_observations ORDER BY observed_status")
    assert [s["observed_status"] for s in statuses] == ["fixed_by_source", "present", "present"]
    cases = q(run, analyst, "SELECT count(*) AS n FROM axiom.finding_cases")[0]["n"]
    assert cases == 2                                     # FIXED-only finding creates no case
    quarantine = run(analyst, lambda s: s.conn.execute(
        "SELECT reason_code, raw_locator FROM axiom.quarantined_records").fetchall())
    assert quarantine == [{"reason_code": "missing_asset_uuid", "raw_locator": "/3"}]


def test_sarif_import_with_untrusted_text_changes_no_authority(world, run, ctx_for, importer):
    """A05 (ingestion part): instructions inside imported text are stored as data only."""
    analyst = ctx_for("analyst")
    bindings_before = q(run, analyst, "SELECT count(*) AS n FROM axiom.role_bindings")[0]["n"]
    result, _ = importer((FIX / "sarif/synthetic-code-scanning.sarif").read_bytes(), "sarif")
    assert result["status"] == "completed" and result["counts"]["quarantined"] == 2
    assert result["counts"]["non_findings"] == 1
    assert q(run, analyst, "SELECT count(*) AS n FROM axiom.role_bindings")[0]["n"] == bindings_before
    assert q(run, analyst, "SELECT count(*) AS n FROM axiom.finding_cases WHERE workflow = 'closed'")[0]["n"] == 0
    stored = q(run, analyst, "SELECT source_fields FROM axiom.observations WHERE source_fields->'message'->>'text' "
                             "LIKE '%%IGNORE PREVIOUS%%'")
    assert len(stored) == 1
    ident = q(run, analyst, "SELECT namespace, value, origin FROM axiom.asset_identifiers")
    assert ident == [{"namespace": "repository_uri", "value": "https://git.example.invalid/acme/payments-api",
                      "origin": "observed"}]


def test_sarif_without_subject_fails_until_declared(world, run, ctx_for, importer):
    data = (FIX / "sarif/trivy-debian-bullseye.subset.sarif").read_bytes()
    failed, _ = importer(data, "sarif")
    assert failed["status"] == "failed" and failed["coverage"] == "failed" and "declare" in failed["error_summary"]
    declared = {"identifiers": [{"namespace": "image_repository", "value": "public.ecr.aws/docker/library/debian"}],
                "kind": "container_image", "display_name": "debian", "deployment_digest": DIGEST}
    ok, _ = importer(data, "sarif", declared=declared)
    assert ok["status"] == "completed" and ok["counts"]["findings"] == 30
    origin = q(run, ctx_for("analyst"), "SELECT DISTINCT origin FROM axiom.asset_identifiers")
    assert origin == [{"origin": "declared_by_importer"}]


def test_import_permissions_and_tenant_boundaries(world, ctx_for, upload, ingest):
    ev = upload(ctx_for("analyst"), world.a.project, TRIVY.read_bytes())
    with pytest.raises(PermissionDenied):
        ingest.request_import(ctx_for("owner"), evidence_id=ev["id"], adapter="trivy_json", scope_id=world.a.project)
    with pytest.raises(NotFound):
        ingest.request_import(ctx_for("consultant", "b"), evidence_id=ev["id"], adapter="trivy_json",
                              scope_id=world.b.project)
    pending = upload(ctx_for("analyst"), world.a.project, b"{}", finalise=False)
    from axiom.errors import Conflict
    with pytest.raises(Conflict):
        ingest.request_import(ctx_for("analyst"), evidence_id=pending["id"], adapter="trivy_json",
                              scope_id=world.a.project)


def test_tampered_original_fails_the_run(world, run, ctx_for, importer, ingest, object_store):
    """The original is re-verified before parsing; changed bytes fail the run instead of importing them."""
    queued, ev = importer(TRIVY.read_bytes(), "trivy_json", execute=False)
    object_store.put(ev["object_key"], iter([b'{"SchemaVersion": 2, "Results": []}']), max_bytes=10_000)
    result = ingest.execute(world.a.id, world.a.system, queued["id"], worker_id="w1")
    assert result["status"] == "failed" and "verified digest" in result["error_summary"]
    assert q(run, ctx_for("analyst"), "SELECT count(*) AS n FROM axiom.finding_occurrences")[0]["n"] == 0


def test_recurrence_after_verified_closure_reopens(world, run, ctx_for, importer, upload):
    """The old deployment is reported again after a verified fix: the case reopens (recurrence)."""
    analyst, owner, analyst2 = ctx_for("analyst"), ctx_for("owner"), ctx_for("analyst2")
    doc = json.loads(TRIVY.read_bytes())
    doc["Results"][0]["Vulnerabilities"] = doc["Results"][0]["Vulnerabilities"][4:5]
    first, _ = importer(json.dumps(doc).encode(), "trivy_json")
    case = q(run, analyst, "SELECT * FROM axiom.finding_cases")[0]
    asset_id = q(run, analyst, "SELECT asset_id FROM axiom.asset_versions")[0]["asset_id"]
    new_digest = "sha256:" + "e" * 64
    fixed = run(analyst, lambda s: s.assets.record_version(asset_id=asset_id, observed_at=datetime.now(timezone.utc),
                                                           deployment_digest=new_digest))
    proof = upload(analyst, world.a.project, b"trivy report showing the package")
    cid = case["id"]
    run(analyst, lambda s: s.cases.start_investigation(cid, 0, "triage"))
    run(analyst, lambda s: s.cases.record_assessment(cid, 1, assessment="supported", rationale="present",
                                                      limitations="none", evidence=[EvidenceRef(proof["id"])]))
    run(analyst, lambda s: s.cases.plan_remediation(cid, 2, owner_principal_id=world["owner"], rationale="patch"))
    run(owner, lambda s: s.cases.record_external_work(cid, 3, external_reference="JIRA-7", rationale="t"))
    run(owner, lambda s: s.cases.report_change(cid, 4, target_asset_version_id=fixed["id"],
                                              change_reference="rebuild", rationale="new image"))
    check = upload(analyst2, world.a.project, b"clean rescan of new digest")
    run(analyst2, lambda s: s.cases.record_verification(cid, 5, claimed_result="passed", coverage="complete",
                                                        criteria={"cve": case["title"]},
                                                        observed_deployment_digest=new_digest,
                                                        evidence_id=check["id"], rationale="clean"))
    vr = q(run, analyst2, "SELECT id FROM axiom.verification_runs WHERE case_id = %s", cid)[0]
    run(analyst2, lambda s: s.cases.close_verified(cid, 6, verification_run_id=vr["id"], rationale="verified"))
    assert q(run, analyst, "SELECT workflow FROM axiom.finding_cases WHERE id = %s", cid)[0]["workflow"] == "closed"
    second, _ = importer(json.dumps(doc).encode(), "trivy_json")      # old digest still reported
    assert second["counts"]["cases_reopened"] == 1
    reopened = q(run, analyst, "SELECT workflow FROM axiom.finding_cases WHERE id = %s", cid)[0]
    assert reopened["workflow"] == "investigating"
    events = q(run, analyst, "SELECT event_type, payload FROM axiom.case_events WHERE case_id = %s ORDER BY sequence", cid)
    assert events[-1]["event_type"] == "case.reopened" and events[-1]["payload"]["reason"] == "recurrence"


def test_strong_identifier_conflict_creates_conflict_asset_and_review(world, run, ctx_for, importer):
    """AST-02: a record whose strong identifiers belong to two different assets is never merged."""
    analyst = ctx_for("analyst")
    records = json.loads((FIX / "tenable/synthetic-vulns-chunk-1.json").read_bytes())
    importer(json.dumps([records[0]]).encode(), "tenable_vm")              # asset X: tenable uuid U1
    sarif_like_declared = {"identifiers": [{"namespace": "source_asset", "value": "cmdb:pay-db-01"}],
                           "kind": "host", "display_name": "pay-db-01 (CMDB)"}
    data = (FIX / "sarif/trivy-debian-bullseye.subset.sarif").read_bytes()
    importer(data, "sarif", declared=sarif_like_declared)                  # asset Y: cmdb id C1
    # A record claiming BOTH U1 and C1 links two existing assets: conflict, no merge.
    conflicting = {"identifiers": [{"namespace": "tenable_asset_uuid", "value": records[0]["asset"]["uuid"]},
                                   {"namespace": "source_asset", "value": "cmdb:pay-db-01"}],
                   "kind": "host", "display_name": "conflicting claim"}
    result, _ = importer(data, "sarif", declared=conflicting)
    assert result["status"] == "completed"
    conflict_assets = q(run, analyst, "SELECT id FROM axiom.assets WHERE identity_status = 'conflict'")
    assert len(conflict_assets) == 1
    cands = q(run, analyst, "SELECT asset_ids FROM axiom.identity_candidates WHERE method = 'strong_identifier_conflict'")
    assert len(cands) == 1 and len(cands[0]["asset_ids"]) == 3
    # The strong identifiers stay with their original owners (unique per tenant).
    owners = q(run, analyst, "SELECT namespace, count(DISTINCT asset_id) AS n FROM axiom.asset_identifiers "
                             "WHERE strength = 'strong' AND namespace IN ('tenable_asset_uuid', 'source_asset') "
                             "GROUP BY namespace")
    assert {o["namespace"]: o["n"] for o in owners} == {"tenable_asset_uuid": 1, "source_asset": 1}
    importer(data, "sarif", declared=conflicting)                         # same claim again, next run
    assert len(q(run, analyst, "SELECT id FROM axiom.assets WHERE identity_status = 'conflict'")) == 1
    assert len(q(run, analyst, "SELECT 1 FROM axiom.identity_candidates WHERE method = 'strong_identifier_conflict'")) == 1
