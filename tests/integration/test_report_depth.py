"""Reporting depth: coverage by source (sync success vs completeness), source-specific freshness, separate
denominators, explicit unknowns, as-of reproducibility, and classification-aware auditor evidence packages.

Findings come from the real Trivy fixture (complete) and a modified copy with one invalid record (partial); both are
imported through the ingestion pipeline. Future instants for freshness are evaluated with ``compute`` directly,
because ``generate`` refuses future ``as_of`` values.
"""
from __future__ import annotations

import base64
import json
from datetime import timedelta

import pytest

from axiom.access import Authorizer, PermissionDenied
from axiom.domains.cases import priority as prio
from axiom.domains.cases.service import EvidenceRef
from axiom.domains.cases.sla import sla_sweep
from axiom.domains.reports.service import STATEMENTS, ReportService

from .test_ingestion import TRIVY, importer, ingest  # noqa: F401 - fixtures

pytestmark = pytest.mark.db


def reports(db, ctx, fn, store=None):
    with db.tenant_tx(ctx) as conn:
        return fn(ReportService(conn, ctx, Authorizer(conn, ctx), store))


def db_now(db, ctx):
    with db.tenant_tx(ctx) as conn:
        return conn.execute("SELECT clock_timestamp() AS t").fetchone()["t"]


def partial_trivy() -> bytes:
    doc = json.loads(TRIVY.read_bytes())
    doc["Results"][0]["Vulnerabilities"] = doc["Results"][0]["Vulnerabilities"][:10] + [{"VulnerabilityID": "CVE-2099-9"}]
    return json.dumps(doc).encode()


def test_successful_sync_is_not_complete_coverage_and_freshness_is_per_source(db, run, ctx_for, world, importer):
    analyst, auditor = ctx_for("analyst"), ctx_for("auditor")
    full, _ = importer(TRIVY.read_bytes(), "trivy_json")
    part, _ = importer(partial_trivy(), "trivy_json")
    assert (full["coverage"], part["status"], part["coverage"]) == ("complete", "completed", "partial")
    now = db_now(db, analyst)
    content = reports(db, auditor, lambda r: r.compute(world.a.project, now))
    [src] = content["coverage_by_source"]
    assert src["source"] == "file_import:trivy_json" and src["runs"] == 2
    assert src["last_run_status"] == "completed" and src["freshness"] == "fresh"
    assert src["last_successful_run_coverage"] == "partial" and src["completeness"] == "partial"
    assert src["last_complete_coverage_at"] is not None and src["last_complete_coverage_at"] < src["last_successful_run_at"]
    assert content["unknowns"]["sources_not_fresh_or_not_complete"] == 1
    assert STATEMENTS[0] in content["statements"]
    assert content["freshness_policy"]["provisional"] and content["freshness_policy"]["max_age_hours"]["trivy_json"] == 336
    later = reports(db, auditor, lambda r: r.compute(world.a.project, now + timedelta(hours=337)))
    assert later["coverage_by_source"][0]["freshness"] == "stale"        # Trivy policy: 336 h
    # denominators are counted separately and match the stored records
    counts = run(analyst, lambda s: s.conn.execute(
        """SELECT (SELECT count(*) FROM axiom.finding_cases) AS cases, (SELECT count(*) FROM axiom.finding_occurrences) AS occ,
                  (SELECT count(*) FROM axiom.assets) AS assets""").fetchone())
    d = content["denominators"]
    assert (d["cases"]["total"], d["occurrences"]["total"], d["assets"]["total"]) == \
        (counts["cases"], counts["occ"], counts["assets"])
    assert d["cases"]["total"] != d["occurrences"]["total"] or d["assets"]["total"] != d["cases"]["total"]
    assert content["unknowns"]["unprioritised_open_cases"] == d["cases"]["open"]
    assert content["unknowns"]["unassessed_open_cases"] == d["cases"]["open"]
    assert content["unknowns"]["open_cases_without_resolved_owner"] == d["cases"]["open"]   # nothing routed yet


def test_snapshot_as_of_is_reproducible_after_later_changes(db, run, ctx_for, world, importer, object_store):
    analyst, auditor, system = ctx_for("analyst"), ctx_for("auditor"), ctx_for("system")
    importer(TRIVY.read_bytes(), "trivy_json")
    case = run(analyst, lambda s: s.conn.execute(
        "SELECT * FROM axiom.finding_cases ORDER BY created_at, id LIMIT 1").fetchone())
    out = run(analyst, lambda s: prio.override(s.cases, case["id"], case["record_version"], priority="medium",
                                               rationale="initial"))
    with db.tenant_tx(system) as conn:
        sla_sweep(conn, system)
    t1 = db_now(db, analyst)
    first = reports(db, auditor, lambda r: r.generate(kind="exposure_summary", scope_id=world.a.project, as_of=t1),
                    object_store)
    # later: priority change (the remediation timer is revised), a dismissal, another import
    out = run(analyst, lambda s: prio.override(s.cases, case["id"], out["record_version"], priority="urgent",
                                               rationale="exploit published"))
    with db.tenant_tx(system) as conn:
        assert sla_sweep(conn, system)["revised"] == 1
    other = run(analyst, lambda s: s.conn.execute(
        "SELECT * FROM axiom.finding_cases WHERE id <> %s ORDER BY created_at, id LIMIT 1", (case["id"],)).fetchone())
    run(analyst, lambda s: s.cases.start_investigation(other["id"], other["record_version"], "look"))
    importer(partial_trivy(), "trivy_json")
    again = reports(db, auditor, lambda r: r.generate(kind="exposure_summary", scope_id=world.a.project, as_of=t1),
                    object_store)
    assert again["content_digest"] == first["content_digest"] and again["content"] == first["content"]
    now = reports(db, auditor, lambda r: r.generate(kind="exposure_summary", scope_id=world.a.project), object_store)
    assert now["content_digest"] != first["content_digest"]
    assert now["content"]["open_by_priority"].get("urgent") == 1
    assert first["content"]["open_by_priority"].get("medium") == 1 and "urgent" not in first["content"]["open_by_priority"]


@pytest.fixture()
def packaged_case(world, run, ctx_for, upload):
    analyst = ctx_for("analyst")
    case = run(analyst, lambda s: s.cases.create(scope_id=world.a.project, title="exposed admin panel"))
    public = upload(analyst, world.a.project, b"internal advisory text", classification="internal")
    secret = upload(analyst, world.a.project, b"confidential scan with hostnames", classification="confidential")
    run(analyst, lambda s: s.cases.start_investigation(case["id"], 0, "triage"))
    run(analyst, lambda s: s.cases.record_assessment(case["id"], 1, assessment="supported", rationale="confirmed",
                                                      limitations="scan covered one host only",
                                                      evidence=[EvidenceRef(public["id"]), EvidenceRef(secret["id"])]))
    run(analyst, lambda s: prio.apply(s.cases, case["id"], 2, rationale="policy"))
    return case["id"], public, secret


def test_evidence_package_withholds_content_the_requester_cannot_read(db, run, ctx_for, world, dbinfo, object_store,
                                                                       packaged_case):
    case_id, public, secret = packaged_case
    auditor = ctx_for("auditor")
    with pytest.raises(PermissionDenied):                       # analysts lack audit.read
        reports(db, ctx_for("analyst"), lambda r: r.evidence_package(case_id), object_store)
    pkg = reports(db, auditor, lambda r: r.evidence_package(case_id), object_store)
    body = pkg["snapshot"]["content"]
    items = {e["evidence_id"]: e for e in body["evidence"]}
    for ev, cls in ((public, "internal"), (secret, "confidential")):     # the auditor role reads no evidence content
        hidden = items[str(ev["id"])]
        assert hidden["content"] is None and hidden["withheld"] == f"requester lacks evidence.read:{cls}"
        assert "content_base64" not in hidden
        # metadata (digest, size, filename) also needs an explicit permission, so only the reference remains
        assert "sha256" not in hidden and "filename" not in hidden and "size" not in hidden
        assert hidden["metadata_withheld"] == f"requester lacks evidence.read:{cls} and evidence.metadata:{cls}"
    assert body["withheld_evidence"] == 2 and body["withheld_metadata"] == 2
    raw0 = reports(db, auditor, lambda r: r.read_export(pkg["export"]["id"]), object_store)[1]
    assert secret["observed_digest"].encode() not in raw0
    from axiom.provisioning import Provisioner
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["auditor"], "evidence_metadata_reader",
                                                     world.a.project, "auditor may see evidence metadata")
    meta = reports(db, auditor, lambda r: r.evidence_package(case_id), object_store)["snapshot"]["content"]
    m = {e["evidence_id"]: e for e in meta["evidence"]}[str(secret["id"])]
    assert m["sha256"] == secret["observed_digest"] and m["filename"] == "evidence.txt" and m["content"] is None
    assert meta["withheld_metadata"] == 0 and meta["withheld_evidence"] == 2
    assert [d["kind"] for d in body["decisions"]] == ["investigation_start", "assessment", "prioritisation"]
    assert any("built-in provisional default" in (d["limitations"] or "") for d in body["decisions"])
    raw = reports(db, auditor, lambda r: r.read_export(pkg["export"]["id"]), object_store)[1]
    assert base64.b64encode(b"confidential scan with hostnames") not in raw and b"scan with hostnames" not in raw
    # with classification access, the same request includes the content and audits the read
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["auditor"], "evidence_reader", world.a.project,
                                                     "auditor needs confidential evidence for the audit")
    pkg2 = reports(db, auditor, lambda r: r.evidence_package(case_id), object_store)
    items2 = {e["evidence_id"]: e for e in pkg2["snapshot"]["content"]["evidence"]}
    assert base64.b64decode(items2[str(secret["id"])]["content_base64"]) == b"confidential scan with hostnames"
    assert base64.b64decode(items2[str(public["id"])]["content_base64"]) == b"internal advisory text"
    assert pkg2["snapshot"]["content"]["withheld_evidence"] == 0
    reads = run(ctx_for("auditor"), lambda s: s.conn.execute(
        """SELECT count(*) AS n FROM axiom.audit_events WHERE action = 'evidence.read' AND resource_id = %s
             AND detail->>'purpose' = 'evidence_package'""", (str(secret["id"]),)).fetchone())["n"]
    assert reads == 1
