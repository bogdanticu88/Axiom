"""Phase C core: frozen snapshots, durable investigation runs, claims and their place in human decisions.

Findings come from the real Trivy fixture and labelled modifications of it; models are the deterministic fake.
"""
from __future__ import annotations

import json

import psycopg
import pytest

from axiom.access import Authorizer
from axiom.domains.cases.service import EvidenceRef
from axiom.errors import Conflict, Forbidden, NotFound
from axiom.investigation import snapshots as snaps
from axiom.investigation.runner import InvestigationHandler

from .investigation_support import inv, trivy_doc  # noqa: F401
from .test_ingestion import importer, ingest  # noqa: F401

pytestmark = pytest.mark.db


def snapshot(inv, case_id, who="analyst"):
    ctx = inv.ctx_for(who)
    with inv.db.tenant_tx(ctx) as conn:
        row = snaps.build_snapshot(conn, ctx, Authorizer(conn, ctx), case_id)
        return snaps.get_snapshot(conn, Authorizer(conn, ctx), row["id"])


def rescan_without(vuln: str, *, hours_later: int = 24, digest: str | None = None) -> bytes:
    """Labelled modification of the real fixture: the same image scanned again (``hours_later`` after the fixture's
    CreatedAt; 0 = the same reported scan time) with one vulnerability gone. ``digest`` makes it a different
    deployment of the same image repository."""
    from datetime import datetime, timedelta
    doc = trivy_doc()
    doc["Results"][0]["Vulnerabilities"] = [v for v in doc["Results"][0]["Vulnerabilities"]
                                            if v["VulnerabilityID"] != vuln]
    t = datetime.fromisoformat(doc["CreatedAt"].replace("Z", "+00:00")[:26] + "+00:00")
    doc["CreatedAt"] = (t + timedelta(hours=hours_later)).isoformat().replace("+00:00", "Z")
    if digest:
        repo = doc["Metadata"]["RepoDigests"][0].split("@", 1)[0]
        doc["Metadata"]["RepoDigests"] = [f"{repo}@sha256:{digest}"]
    return json.dumps(doc).encode()


# --------------------------------------------------------------------------------------------- snapshots
def test_snapshot_freezes_observations_runs_assets_and_gaps(inv):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    snap = snapshot(inv, case["id"])
    kinds = {m["kind"] for m in snap["members"]}
    assert {"occurrence", "asset", "asset_version", "occurrence_observation", "observation", "ingestion_run",
            "evidence_object"} <= kinds
    obs = [m for m in snap["members"] if m["kind"] == "observation"][0]
    assert obs["ref_digest"] and obs["classification"] == "internal" and obs["freshness"] == "fresh"
    assert obs["attributes"]["vulnerability_ref"] == case["vulnerability_ref"]
    run_m = [m for m in snap["members"] if m["kind"] == "ingestion_run"][0]
    assert run_m["attributes"]["coverage"] == "complete" and run_m["attributes"]["adapter"] == "trivy_json"
    av = [m for m in snap["members"] if m["kind"] == "asset_version"][0]
    assert av["attributes"]["deployment_digest"].startswith("sha256:")
    assert {g["kind"] for g in snap["gaps"]} >= {"no_business_context"}          # missing information is kept
    assert snap["contradictions"] == []
    with inv.db.tenant_tx(inv.ctx_for("analyst")) as conn:
        assert snaps.verify_snapshot(conn, snap["id"])
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE axiom.evidence_snapshot_members SET freshness = 'stale' WHERE snapshot_id = %s",
                         (snap["id"],))


def test_contradictions_are_recorded_and_later_evidence_makes_a_new_snapshot(inv):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    first = snapshot(inv, case["id"])
    inv.importer(rescan_without(case["vulnerability_ref"]), "trivy_json")     # labelled: modified real fixture
    second = snapshot(inv, case["id"])
    assert second["id"] != first["id"] and second["digest"] != first["digest"]
    [c] = [c for c in second["contradictions"] if c["kind"] == "presence_disagreement"]
    assert (c["ordering"], c["latest_status"]) == ("by_scan_time", "absent_in_complete_scan") and c["member_keys"]
    assert c["latest_scan_time"] > [m for m in second["members"] if m["kind"] == "occurrence_observation"
                                    and m["attributes"]["observed_status"] == "present"][0]["attributes"]["scan_time"]
    statuses = sorted(m["attributes"]["observed_status"] for m in second["members"]
                      if m["kind"] == "occurrence_observation")
    assert statuses == ["absent_in_complete_scan", "present"]
    with inv.db.tenant_tx(inv.ctx_for("analyst")) as conn:                    # the earlier snapshot is unchanged
        again = snaps.get_snapshot(conn, Authorizer(conn, inv.ctx_for("analyst")), first["id"])
        assert again["members"] == first["members"] and snaps.verify_snapshot(conn, first["id"])


def test_snapshot_needs_permission_and_stays_in_tenant(inv):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    with pytest.raises(NotFound):                         # no membership in tenant A
        snapshot(inv, case["id"], who="outsider")
    ctx_b = inv.ctx_for("analyst", "b")
    with inv.db.tenant_tx(ctx_b) as conn:
        with pytest.raises(NotFound):
            snaps.build_snapshot(conn, ctx_b, Authorizer(conn, ctx_b), case["id"])
    from axiom.access import PermissionDenied
    with pytest.raises(PermissionDenied):
        snapshot(inv, case["id"], who="auditor")         # can read cases, cannot freeze snapshots


# ------------------------------------------------------------------------------------------- runs
def test_run_completes_with_validated_claims_tool_steps_and_usage(inv):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    run = inv.start(case["id"])
    assert run["status"] == "queued" and run["job_id"]
    got = inv.drive(run["id"])
    assert got["status"] == "completed", got["outcome_reason"]
    kinds = [s["kind"] for s in got["steps"]]
    assert kinds.count("model") == 2 and kinds.count("tool") == 1          # round 1 asked for one tool call
    assert got["model_calls"] == 2 and got["tool_calls"] == 1 and got["input_tokens"] > 0
    assert all(s["status"] == "completed" for s in got["steps"])
    claims = got["claims"]
    assert claims and all(c["validation"] == "references_checked" for c in claims)
    presence = [c for c in claims if c["subject"]["attribute"] == "present_in_deployment"][0]
    assert presence["accepted_conclusion"] == "supported" and presence["supporting"]
    assert presence["entailment"] == "not_verified" and presence["model_stated_confidence"] == "medium"
    assert any("criticality" in c["description"] for c in got["next_checks"])
    # nothing about the case changed
    after = inv.run(inv.ctx_for("analyst"), lambda s: s.cases.get(case["id"]))
    assert (after["workflow"], after["priority"], after["assessment"]) == (case["workflow"], case["priority"],
                                                                          case["assessment"])


def test_assessment_cites_the_run_only_after_human_review(inv):
    _, ev = inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    run = inv.drive(inv.start(case["id"])["id"])
    c = inv.investigate_case(case)
    analyst = inv.ctx_for("analyst")
    kw = dict(assessment="supported", rationale="scanner and investigation agree", limitations="reachability unknown",
              evidence=[EvidenceRef(ev["id"])], investigation_run_id=run["id"])
    with pytest.raises(Conflict) as err:
        inv.run(analyst, lambda s: s.cases.record_assessment(case["id"], c["record_version"], **kw))
    assert err.value.code == "claims_not_reviewed"
    for cl in run["claims"]:
        inv.svc("analyst2", lambda s: s.review_claim(cl["id"], verdict="confirmed", note="checked the observation"))
    out = inv.run(analyst, lambda s: s.cases.record_assessment(case["id"], c["record_version"], **kw))
    d = inv.run(analyst, lambda s: s.conn.execute(
        "SELECT * FROM axiom.decisions WHERE case_id = %s AND kind = 'assessment'", (case["id"],)).fetchone())
    assert d["investigation_run_id"] == run["id"] and d["evidence_snapshot_id"] == run["snapshot_id"]
    assert "not authoritative" in d["limitations"] and "recorded contradiction" in d["limitations"]
    assert out["priority"] == case["priority"]                # assessment never sets priority


def test_reassessment_on_new_evidence_keeps_the_original(inv):
    _, ev = inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    analyst = inv.ctx_for("analyst")
    s1 = snapshot(inv, case["id"])
    c = inv.investigate_case(case)
    c = inv.run(analyst, lambda s: s.cases.record_assessment(
        case["id"], c["record_version"], assessment="supported", rationale="first", limitations="none identified",
        evidence=[EvidenceRef(ev["id"])], evidence_snapshot_id=s1["id"]))
    c = inv.run(analyst, lambda s: s.cases.request_more_evidence(case["id"], c["record_version"], "new scan arrived"))
    _, ev2 = inv.importer(rescan_without(case["vulnerability_ref"]), "trivy_json")
    s2 = snapshot(inv, case["id"])
    inv.run(analyst, lambda s: s.cases.record_assessment(
        case["id"], c["record_version"], assessment="not_supported", rationale="absent in a complete rescan",
        limitations="single scanner", evidence=[EvidenceRef(ev2["id"])], evidence_snapshot_id=s2["id"]))
    ds = inv.run(analyst, lambda s: s.conn.execute(
        """SELECT outcome, evidence_snapshot_id FROM axiom.decisions WHERE case_id = %s AND kind = 'assessment'
            ORDER BY recorded_at""", (case["id"],)).fetchall())
    assert [(d["outcome"], d["evidence_snapshot_id"]) for d in ds] == [("supported", s1["id"]),
                                                                        ("not_supported", s2["id"])]


def test_workload_principals_cannot_record_consequential_decisions_or_reviews(inv):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    run = inv.drive(inv.start(case["id"])["id"])
    system = inv.ctx_for("system")
    with inv.db.tenant_tx(system) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                """INSERT INTO axiom.decisions(tenant_id, id, case_id, kind, outcome, rationale, actor_principal_id, authority)
                   VALUES (%s, gen_random_uuid(), %s, 'closure', 'dismissed', 'model says so', %s, '{}')""",
                (system.tenant_id, case["id"], system.principal_id))
    with inv.db.tenant_tx(system) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("""INSERT INTO axiom.claim_reviews(tenant_id, id, claim_id, run_id, verdict, note, reviewer)
                            VALUES (%s, gen_random_uuid(), %s, %s, 'confirmed', 'self review', %s)""",
                         (system.tenant_id, run["claims"][0]["id"], run["id"], system.principal_id))


# ------------------------------------------------------------------------------------- lifecycle controls
def test_cancellation_and_revocation_end_the_run(inv, dbinfo):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    r1 = inv.start(case["id"])
    inv.svc("analyst", lambda s: s.cancel(r1["id"], reason="wrong question"))
    got = inv.drive(r1["id"])
    assert (got["status"], got["outcome_reason"], got["model_calls"]) == ("cancelled", "cancel_requested", 0)
    with pytest.raises(Conflict):
        inv.svc("analyst", lambda s: s.cancel(r1["id"], reason="again"))
    r2 = inv.start(case["id"], who="analyst2")
    with inv.db.tenant_tx(inv.ctx_for("admin")) as conn:
        bindings = conn.execute("SELECT id FROM axiom.role_bindings WHERE principal_id = %s AND revoked_at IS NULL",
                                (inv.world["analyst2"],)).fetchall()
    inv.run(inv.ctx_for("admin"), lambda s: [s.tenancy.revoke_role(binding_id=b["id"], reason="left the team")
                                             for b in bindings])
    got = inv.drive(r2["id"])
    assert (got["status"], got["outcome_reason"]) == ("cancelled", "authority_revoked")


def test_disabled_route_fails_without_fallback(inv):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    inv.route("fake-rules-v1", name="backup-route")                      # another approved route exists
    run = inv.start(case["id"])
    inv.svc("admin", lambda s: s.disable_route(inv.routes["fake-rules-v1"]["id"], rationale="provider incident"))
    got = inv.drive(run["id"])
    assert (got["status"], got["outcome_reason"], got["model_calls"]) == ("failed", "route_disabled", 0)
    assert got["route_binding"]["route_name"] == "fake-rules-v1"


def test_lost_model_step_after_a_crash_is_counted_and_the_run_resumes(inv):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    run = inv.start(case["id"])

    class Crash(BaseException):
        pass

    class CrashingGateway:
        def __init__(self, real):
            self.real, self.armed = real, True

        def check_binding(self, b):
            return self.real.check_binding(b)

        def call(self, *a, **kw):
            if self.armed:
                self.armed = False
                raise Crash()
            return self.real.call(*a, **kw)

    h = InvestigationHandler(store=inv.store)
    h.gateway = CrashingGateway(h.gateway)
    with pytest.raises(Crash):
        inv.drive(run["id"], rounds=1, handler=h)
    inv.admin_conn.execute("""UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 second',
                                     step_deadline_at = clock_timestamp() - interval '1 second',
                                     record_version = record_version + 1 WHERE id = %s""", (run["job_id"],))
    got = inv.drive(run["id"], handler=h)
    assert got["status"] == "completed"
    assert [s["status"] for s in got["steps"]][0] == "lost" and got["model_calls"] == 3


def test_snapshot_from_another_case_or_tenant_is_refused(inv):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    other = inv.run(inv.ctx_for("analyst"), lambda s: s.conn.execute(
        "SELECT * FROM axiom.finding_cases WHERE id <> %s LIMIT 1", (case["id"],)).fetchone())
    s_other = snapshot(inv, other["id"])
    inv.route()
    with pytest.raises(NotFound):
        inv.svc("analyst", lambda s: s.start(case["id"], questions=["q"], route="fake-rules-v1",
                                             snapshot_id=s_other["id"]))
    ctx_b = inv.ctx_for("analyst", "b")
    run = inv.start(case["id"])
    with inv.db.tenant_tx(ctx_b) as conn:
        from axiom.investigation.service import InvestigationService
        with pytest.raises(NotFound):
            InvestigationService(conn, ctx_b, Authorizer(conn, ctx_b)).get(run["id"])


def test_route_approval_needs_a_second_person_and_definitions_are_immutable(inv):
    r = inv.svc("admin", lambda s: s.propose_route(
        name="r1", provider="deterministic_fake", model="fake-rules-v1", endpoint="fake://r1", region="local",
        max_classification="internal", rationale="x"))
    with pytest.raises(Forbidden):
        inv.svc("admin", lambda s: s.approve_route(r["id"], rationale="self"))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with inv.db.tenant_tx(inv.ctx_for("admin")) as conn:
            conn.execute("UPDATE axiom.model_routes SET model = 'other' WHERE id = %s", (r["id"],))
    from axiom.errors import ValidationFailed
    with pytest.raises(ValidationFailed):                     # unregistered real destination
        inv.svc("admin", lambda s: s.propose_route(
            name="r2", provider="anthropic_messages", model="m", endpoint="https://api.anthropic.com",
            region="us", max_classification="internal", rationale="x", credential_ref="secretref:env/X"))
    from axiom.investigation.service import InvestigationService
    ctx = inv.ctx_for("admin")
    with inv.db.tenant_tx(ctx) as conn:
        prod = InvestigationService(conn, ctx, Authorizer(conn, ctx), env="production")
        with pytest.raises(ValidationFailed):
            prod.propose_route(name="r3", provider="deterministic_fake", model="fake-rules-v1", endpoint="fake://r3",
                               region="local", max_classification="internal", rationale="x")


def test_snapshot_reads_disclose_content_and_metadata_only_with_permission(inv, dbinfo):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    snap = snapshot(inv, case["id"])
    auditor = inv.ctx_for("auditor")
    with inv.db.tenant_tx(auditor) as conn:
        seen = snaps.get_snapshot(conn, Authorizer(conn, auditor), snap["id"])
    ev = [m for m in seen["members"] if m["kind"] == "evidence_object"][0]
    obs = [m for m in seen["members"] if m["kind"] == "observation"][0]
    assert ev["ref_digest"] is None and "original_filename" not in ev["attributes"] and ev["metadata_withheld"]
    assert obs["attributes"]["source_text"] is None and obs["content_withheld"]
    from axiom.provisioning import Provisioner
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(inv.world.a.id, inv.world["auditor"], "evidence_metadata_reader",
                                                     inv.world.a.project, "metadata for audit")
    with inv.db.tenant_tx(auditor) as conn:
        seen = snaps.get_snapshot(conn, Authorizer(conn, auditor), snap["id"])
    ev = [m for m in seen["members"] if m["kind"] == "evidence_object"][0]
    obs = [m for m in seen["members"] if m["kind"] == "observation"][0]
    assert ev["ref_digest"] and ev["attributes"]["original_filename"] and obs["attributes"]["source_text"] is None



# --------------------------------------------------------------------- ordering is not decided by import time
def test_same_reported_scan_time_leaves_the_contradiction_open_for_a_person(inv):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    inv.importer(rescan_without(case["vulnerability_ref"], hours_later=0), "trivy_json")   # imported later, same scan time
    run = inv.drive(inv.start(case["id"])["id"])
    snap = snapshot(inv, case["id"])
    [c] = [c for c in snap["contradictions"] if c["kind"] == "presence_disagreement"]
    assert c["ordering"] == "undetermined" and "same latest scan time" in c["ordering_reason"] and "latest_status" not in c
    [p] = [cl for cl in run["claims"] if cl["subject"]["attribute"] == "present_in_deployment"]
    assert p["accepted_conclusion"] == "unknown" and "without a defensible order" in p["limitations"]
    adv = inv.drive(inv.start(case["id"], "fake-adversarial:ignore_contradiction")["id"])
    [a] = [cl for cl in adv["claims"] if cl["subject"]["attribute"] == "present_in_deployment"]
    assert a["accepted_conclusion"] == "unknown" and {"ignores_recorded_contradiction", "unresolved_contradiction"} \
        <= {r["code"] for r in a["validation_reasons"]}


def test_newer_scan_of_a_different_deployment_does_not_change_this_one(inv):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    inv.importer(rescan_without(case["vulnerability_ref"], hours_later=48, digest="ab" * 32), "trivy_json")
    snap = snapshot(inv, case["id"])
    assert [c for c in snap["contradictions"] if c["kind"] == "presence_disagreement"] == []
    statuses = [m["attributes"]["observed_status"] for m in snap["members"] if m["kind"] == "occurrence_observation"]
    assert statuses == ["present"]                 # the new deployment's scan says nothing about this deployment
    run = inv.drive(inv.start(case["id"])["id"])
    [p] = [cl for cl in run["claims"] if cl["subject"]["attribute"] == "present_in_deployment"]
    assert (p["accepted_conclusion"], p["validation"]) == ("supported", "references_checked")


def test_one_run_with_supported_and_unresolved_claims(inv):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    vulns = [v["VulnerabilityID"] for v in trivy_doc()["Results"][0]["Vulnerabilities"]]
    a, b = vulns[24], vulns[4]
    inv.importer(rescan_without(b, hours_later=0), "trivy_json")       # b: conflicting, same reported scan time
    ca, cb = inv.case_for(a), inv.case_for(b)
    occ_b = inv.run(inv.ctx_for("analyst"), lambda s: s.conn.execute(
        "SELECT occurrence_id FROM axiom.case_occurrence_links WHERE case_id = %s", (cb["id"],)).fetchone())
    inv.run(inv.ctx_for("analyst"), lambda s: s.cases.link_occurrence(ca["id"], ca["record_version"],
                                                                      occ_b["occurrence_id"], rationale="same package"))
    run = inv.drive(inv.start(ca["id"])["id"])
    pres = {cl["subject"]["vulnerability_ref"]: cl for cl in run["claims"]
            if cl["subject"]["attribute"] == "present_in_deployment"}
    assert pres[a]["accepted_conclusion"] == "supported" and pres[b]["accepted_conclusion"] == "unknown"
    assert run["status"] == "completed"
    # every surviving claim needs its own review before an assessment may cite the run
    c = inv.investigate_case(inv.run(inv.ctx_for("analyst"), lambda s: s.cases.get(ca["id"])))
    first = [cl for cl in run["claims"] if cl["validation"] != "rejected"][0]
    inv.svc("analyst2", lambda s: s.review_claim(first["id"], verdict="confirmed", note="checked"))
    from axiom.domains.cases.service import EvidenceRef
    _, ev = None, inv.run(inv.ctx_for("analyst"), lambda s: s.conn.execute(
        "SELECT raw_evidence_id AS id FROM axiom.ingestion_runs ORDER BY created_at LIMIT 1").fetchone())
    with pytest.raises(Conflict) as err:
        inv.run(inv.ctx_for("analyst"), lambda s: s.cases.record_assessment(
            ca["id"], c["record_version"], assessment="supported", rationale="x", limitations="b unresolved",
            evidence=[EvidenceRef(ev["id"])], investigation_run_id=run["id"]))
    assert err.value.code == "claims_not_reviewed"
