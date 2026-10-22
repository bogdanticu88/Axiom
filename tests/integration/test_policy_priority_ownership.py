"""Versioned policies, prioritisation and ownership routing.

Findings come from importing the real Trivy fixture (tests/fixtures/trivy, real Trivy 0.76.1 output; see
PROVENANCE.md). Business context and ownership rules are supplied by test users (manual steps), as an operator would.
"""
from __future__ import annotations

import psycopg
import pytest

from axiom.access import Authorizer, PermissionDenied
from axiom.domains.assets.service import AssetService, assert_business_context
from axiom.domains.cases import ownership as own
from axiom.domains.cases import priority as prio
from axiom.domains.cases.service import CaseService
from axiom.domains.policies.service import DEFAULTS, PolicyService
from axiom.errors import Forbidden, ValidationFailed

from .test_ingestion import TRIVY, importer, ingest  # noqa: F401 - fixtures

pytestmark = pytest.mark.db


@pytest.fixture()
def admins(world, dbinfo):
    """Two policy administrators so publishing can be independent."""
    from axiom.provisioning import Provisioner
    p = Provisioner(dbinfo.admin_cli_dsn)
    for who in ("admin", "auditor"):
        p.bootstrap_role(world.a.id, world[who], "policy_admin", world.a.root, "policy tests")
    return "admin", "auditor"


@pytest.fixture()
def imported(importer):  # noqa: F811
    run, _ = importer(TRIVY.read_bytes(), "trivy_json")
    return run


def svc(db, ctx, cls):
    conn_cm = db.tenant_tx(ctx)
    conn = conn_cm.__enter__()
    return conn_cm, cls(conn, ctx, Authorizer(conn, ctx))


def call(db, ctx, cls, fn):
    with db.tenant_tx(ctx) as conn:
        return fn(cls(conn, ctx, Authorizer(conn, ctx)))


def first_case(run, ctx):
    return run(ctx, lambda s: s.conn.execute(
        """SELECT c.*, av.asset_id, o.source_severity FROM axiom.finding_cases c
             JOIN axiom.case_occurrence_links l ON l.case_id = c.id JOIN axiom.finding_occurrences o ON o.id = l.occurrence_id
             JOIN axiom.asset_versions av ON av.id = o.asset_version_id
            WHERE o.source_severity IS NOT NULL ORDER BY c.created_at, c.id LIMIT 1""").fetchone())


# --------------------------------------------------------------------------------------------- policies
def test_publishing_needs_a_second_person_and_supersedes(db, ctx_for, admins):
    a, b = (ctx_for(x) for x in admins)
    v1 = call(db, a, PolicyService, lambda p: p.draft(kind="priority", definition=DEFAULTS["priority"],
                                                      rationale="initial matrix"))
    assert v1["status"] == "draft" and len(v1["definition_digest"]) == 64
    with pytest.raises(Forbidden) as err:
        call(db, a, PolicyService, lambda p: p.publish(v1["id"], rationale="self"))
    assert err.value.code == "separation_of_duties"
    call(db, b, PolicyService, lambda p: p.publish(v1["id"], rationale="reviewed"))
    v2 = call(db, a, PolicyService, lambda p: p.draft(kind="priority", definition=DEFAULTS["priority"],
                                                      rationale="second", provisional=False))
    call(db, b, PolicyService, lambda p: p.publish(v2["id"], rationale="reviewed"))
    rows = call(db, a, PolicyService, lambda p: p.list("priority"))
    assert [(r["version"], r["status"]) for r in rows][-2:] == [(1, "superseded"), (2, "published")]
    with pytest.raises(psycopg.errors.InsufficientPrivilege):          # definitions are immutable
        with db.tenant_tx(a) as conn:
            conn.execute("UPDATE axiom.policy_versions SET definition = '{}' WHERE id = %s", (v2["id"],))
    v3 = call(db, a, PolicyService, lambda p: p.draft(kind="sla", definition=DEFAULTS["sla"], rationale="x"))
    with pytest.raises(psycopg.errors.CheckViolation):                 # database backstop for independence
        with db.tenant_tx(a) as conn:
            conn.execute("""UPDATE axiom.policy_versions SET status = 'published', published_by = drafted_by,
                                   published_at = now(), record_version = record_version + 1 WHERE id = %s""",
                         (v3["id"],))


@pytest.mark.parametrize("kind,definition", [
    ("priority", {"matrix": {}, "unknown_severity": "high", "unknown_criticality": "high"}),
    ("ownership", {"rules": [{"id": "r1", "match": {"title": "x"}, "owner_principal_id": "00000000-0000-0000-0000-000000000001"}]}),
    ("ownership", {"rules": [{"id": "r1", "match": {}, "owner_principal_id": "00000000-0000-0000-0000-000000000001"}]}),
    ("sla", {"triage_days": 0, "remediation_days": {"urgent": 7, "high": 30, "medium": 90, "low": 180}}),
    ("freshness", {"max_age_hours": {"trivy_json": 24}}),
])
def test_invalid_definitions_are_refused(db, ctx_for, admins, kind, definition):
    with pytest.raises(ValidationFailed):
        call(db, ctx_for("admin"), PolicyService, lambda p: p.draft(kind=kind, definition=definition, rationale="x"))


# --------------------------------------------------------------------------------------------- priority
def test_priority_from_default_policy_records_its_limitations(db, run, ctx_for, imported):
    analyst = ctx_for("analyst")
    case = first_case(run, analyst)
    out = run(analyst, lambda s: prio.apply(s.cases, case["id"], case["record_version"], rationale="triage"))
    d = run(analyst, lambda s: s.conn.execute(
        "SELECT * FROM axiom.decisions WHERE case_id = %s AND kind = 'prioritisation'", (case["id"],)).fetchone())
    assert d["policy_version_id"] is None
    assert "built-in provisional default" in d["limitations"] and "no asserted asset criticality" in d["limitations"]
    sev = case["source_severity"].lower()
    expected = DEFAULTS["priority"]["matrix"]["medium" if sev == "moderate" else sev]["high"]
    assert out["priority"] == expected and out["workflow"] == case["workflow"]


def test_published_policy_and_context_drive_priority_and_old_decisions_keep_their_version(
        db, run, ctx_for, admins, imported):
    a, b = (ctx_for(x) for x in admins)
    analyst = ctx_for("analyst")
    case = first_case(run, analyst)
    strict = {**DEFAULTS["priority"], "matrix": {s: {c: "urgent" if c == "critical" else "low"
                                                     for c in ("critical", "high", "medium", "low")}
                                                 for s in ("critical", "high", "medium", "low", "info")}}
    v1 = call(db, a, PolicyService, lambda p: p.draft(kind="priority", definition=strict, rationale="strict"))
    call(db, b, PolicyService, lambda p: p.publish(v1["id"], rationale="ok"))
    call(db, analyst, AssetService, lambda s: assert_business_context(
        s, asset_id=case["asset_id"], rationale="payments core", criticality="critical", owner_ref="payments-team",
        environment="production"))
    out = run(analyst, lambda s: prio.apply(s.cases, case["id"], case["record_version"], rationale="policy v1"))
    assert out["priority"] == "urgent"
    v2 = call(db, a, PolicyService, lambda p: p.draft(kind="priority", definition=DEFAULTS["priority"], rationale="v2"))
    call(db, b, PolicyService, lambda p: p.publish(v2["id"], rationale="ok"))
    run(analyst, lambda s: prio.apply(s.cases, case["id"], out["record_version"], rationale="policy v2"))
    decisions = run(analyst, lambda s: s.conn.execute(
        "SELECT policy_version_id FROM axiom.decisions WHERE case_id = %s AND kind = 'prioritisation' "
        "ORDER BY recorded_at", (case["id"],)).fetchall())
    assert [d["policy_version_id"] for d in decisions] == [v1["id"], v2["id"]]     # A14: history kept


def test_override_is_a_recorded_decision_and_needs_permission(run, ctx_for, imported):
    case = first_case(run, ctx_for("analyst"))
    with pytest.raises(PermissionDenied):
        run(ctx_for("viewer"), lambda s: prio.override(s.cases, case["id"], case["record_version"], priority="low",
                                                       rationale="x"))
    out = run(ctx_for("analyst"), lambda s: prio.override(s.cases, case["id"], case["record_version"],
                                                          priority="low", rationale="compensating control"))
    assert out["priority"] == "low"
    ev = run(ctx_for("analyst"), lambda s: s.cases.history(case["id"]))["events"][-1]
    assert ev["event_type"] == "case.priority_overridden" and ev["payload"]["priority_to"] == "low"


# -------------------------------------------------------------------------------------------- ownership
def test_routing_unresolved_queue_rules_and_overrides(db, run, ctx_for, world, admins, imported):
    a, b = (ctx_for(x) for x in admins)
    analyst = ctx_for("analyst")
    case = first_case(run, analyst)
    row = run(analyst, lambda s: own.route(s.cases, case["id"]))
    assert row["basis"] == "unresolved" and "no published ownership policy" in row["reason"]
    queue = run(analyst, lambda s: own.unresolved_queue(s.cases))
    assert case["id"] in [q["id"] for q in queue]
    rules = {"rules": [
        {"id": "ghost", "match": {"owner_ref": "ghost-team"}, "owner_principal_id": str(world["outsider"])},
        {"id": "payments", "match": {"owner_ref": "payments-team", "environment": "production"},
         "owner_principal_id": str(world["owner"])}]}
    v = call(db, a, PolicyService, lambda p: p.draft(kind="ownership", definition=rules, rationale="teams"))
    call(db, b, PolicyService, lambda p: p.publish(v["id"], rationale="ok"))
    row = run(analyst, lambda s: own.route(s.cases, case["id"]))
    assert row["basis"] == "unresolved" and "no business context" in row["reason"]
    call(db, analyst, AssetService, lambda s: assert_business_context(
        s, asset_id=case["asset_id"], rationale="cmdb export reviewed", owner_ref="ghost-team"))
    row = run(analyst, lambda s: own.route(s.cases, case["id"]))
    assert row["basis"] == "unresolved" and "without an active membership" in row["reason"]
    call(db, analyst, AssetService, lambda s: assert_business_context(
        s, asset_id=case["asset_id"], rationale="corrected", owner_ref="payments-team", environment="production"))
    row = run(analyst, lambda s: own.route(s.cases, case["id"]))
    assert (row["basis"], row["owner_principal_id"], row["rule_id"]) == ("rule", world["owner"], "payments")
    assert row["policy_version_id"] == v["id"]
    assert case["id"] not in [q["id"] for q in run(analyst, lambda s: own.unresolved_queue(s.cases))]
    with pytest.raises(ValidationFailed):
        run(analyst, lambda s: own.override(s.cases, case["id"], owner_principal_id=world["outsider"], reason="x"))
    run(analyst, lambda s: own.override(s.cases, case["id"], owner_principal_id=world["analyst2"],
                                        reason="team reorganisation"))
    hist = run(analyst, lambda s: own.history(s.cases, case["id"]))
    assert [h["basis"] for h in hist] == ["unresolved", "unresolved", "unresolved", "rule", "manual_override"]
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        run(analyst, lambda s: s.conn.execute("DELETE FROM axiom.case_ownership WHERE case_id = %s", (case["id"],)))


def test_ownership_confers_no_authority(db, run, ctx_for, world, imported):
    analyst = ctx_for("analyst")
    case = first_case(run, analyst)
    viewer = world["viewer"]

    def powers():
        with db.tenant_tx(analyst) as conn:
            authz = Authorizer(conn, analyst)
            return {p: authz.has(p, world.a.project, principal_id=viewer) for p in (
                "risk.accept", "action.approve:ticket_create", "case.dismiss", "closure.propose", "remediation.update")}
    before = powers()
    bindings_before = run(analyst, lambda s: s.conn.execute("SELECT count(*) AS n FROM axiom.role_bindings WHERE "
                                                            "principal_id = %s", (viewer,)).fetchone()["n"])
    run(analyst, lambda s: own.override(s.cases, case["id"], owner_principal_id=viewer, reason="owns the image"))
    assert powers() == before and not any(before.values())
    assert run(analyst, lambda s: s.conn.execute("SELECT count(*) AS n FROM axiom.role_bindings WHERE principal_id = %s",
                                                 (viewer,)).fetchone()["n"]) == bindings_before


def test_sweep_reroutes_unresolved_cases_only_when_inputs_change(db, run, ctx_for, world, admins, imported):
    from axiom.domains.cases.ownership import OwnershipSweepHandler
    from axiom.jobs import Worker, WorkerConfig, enqueue
    a, b = (ctx_for(x) for x in admins)
    analyst, system = ctx_for("analyst"), ctx_for("system")

    def sweep():
        with db.tenant_tx(system) as conn:
            job = enqueue(conn, system, kind="cases.ownership_sweep", version=1, payload={})
        Worker(db, [OwnershipSweepHandler()], config=WorkerConfig()).run_once(only_tenants={world.a.id})
        with db.tenant_tx(system) as conn:
            return conn.execute("SELECT result FROM axiom.jobs WHERE id = %s", (job["id"],)).fetchone()["result"]["routed"]

    first = sweep()
    assert first and {r["basis"] for r in first} == {"unresolved"}
    assert sweep() == []                                    # unchanged inputs: no repeated unresolved rows
    case = first_case(run, analyst)
    call(db, analyst, AssetService, lambda s: assert_business_context(
        s, asset_id=case["asset_id"], rationale="catalogue", owner_ref="payments-team"))
    v = call(db, a, PolicyService, lambda p: p.draft(kind="ownership", definition={"rules": [
        {"id": "pay", "match": {"owner_ref": "payments-team"}, "owner_principal_id": str(world["owner"])}]},
        rationale="teams"))
    call(db, b, PolicyService, lambda p: p.publish(v["id"], rationale="ok"))
    again = sweep()
    assert again and str(case["id"]) in {r["case_id"] for r in again if r["basis"] == "rule"}
    assert sweep() == []
