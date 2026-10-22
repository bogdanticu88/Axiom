"""Decision authority of system identities (migration 0014) and expiring priority overrides with impact preview.

Findings come from the real Trivy fixture where a case needs occurrences.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from axiom.access import Authorizer
from axiom.db import TenantContext
from axiom.domains.cases import priority as prio
from axiom.domains.policies.service import DEFAULTS, PolicyService
from axiom.errors import Conflict, ValidationFailed

from .investigation_support import inv, trivy_doc  # noqa: F401
from .test_ingestion import importer, ingest  # noqa: F401

pytestmark = pytest.mark.db


def insert_decision(db, ctx, case_id, kind, outcome, authority: dict):
    with db.tenant_tx(ctx) as conn:
        conn.execute(
            """INSERT INTO axiom.decisions(tenant_id, id, case_id, kind, outcome, rationale, actor_principal_id, authority)
               VALUES (%s, gen_random_uuid(), %s, %s, %s, 'test', %s, %s)""",
            (ctx.tenant_id, case_id, kind, outcome, ctx.principal_id, json.dumps(authority)))


# ------------------------------------------------------------------------------------- system authority
@pytest.mark.parametrize("kind,outcome,authority,allowed", [
    ("prioritisation", "high", {"permission": "priority.apply"}, True),
    ("prioritisation", "high", {"system": True}, False),                        # needs the policy permission
    ("verification_review", "passed", {"permission": "verification.record"}, True),
    ("verification_review", "passed", {"permission": "priority.apply"}, False),
    ("reopen", "acceptance_expiry", {"system": True}, True),                     # expiry event
    ("reopen", "recurrence", {"system": True}, True),
    ("reopen", "authorised_reassessment", {"system": True}, False),              # a person's judgement
    ("assessment", "supported", {"permission": "assessment.record"}, False),     # discretionary
    ("closure", "dismissed", {"permission": "case.dismiss"}, False),
    ("risk_acceptance", "accepted", {"permission": "risk.accept"}, False),
    ("priority_override", "low", {"permission": "override.propose"}, False),
])
def test_system_principal_records_only_policy_authorised_results(db, run, ctx_for, world, kind, outcome, authority,
                                                                   allowed):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    system = ctx_for("system")
    if allowed:
        insert_decision(db, system, case["id"], kind, outcome, authority)
    else:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            insert_decision(db, system, case["id"], kind, outcome, authority)


def test_principal_kind_comes_from_identity_records_not_the_context(db, run, ctx_for, world):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    lying = TenantContext(world.a.id, world.a.system, "human", "test-lying-context")   # workload claiming "human"
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        insert_decision(db, lying, case["id"], "assessment", "supported", {"permission": "assessment.record"})
    honest_human = TenantContext(world.a.id, world["analyst"], "workload", "test-understated")
    insert_decision(db, honest_human, case["id"], "escalation", "escalated", {"permission": "assessment.record"})
    # system results record the kind held in the identity records
    run(ctx_for("analyst"), lambda s: s.cases.start_investigation(case["id"], 0, "x"))


def test_api_cannot_assert_principal_kind(client, as_, world):
    from .test_api import as_ as _a, client as _c  # noqa: F401 - fixtures resolved by pytest
    r = client.post("/api/v1/cases", headers=as_("analyst"), json={"scope_id": str(world.a.project), "title": "t",
                                                                   "principal_kind": "workload"})
    assert r.status_code == 422
    me = client.get("/api/v1/me", headers=as_("analyst")).json()
    assert me.get("principal_kind", me.get("kind", "human")) == "human"


from .test_api import as_, client  # noqa: E402,F401


# ---------------------------------------------------------------------------------------- overrides
def first_case(inv):
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    return inv.case_for()


def test_override_holds_until_expiry_then_policy_reassesses_with_provenance(inv):
    case = first_case(inv)
    analyst, system = inv.ctx_for("analyst"), inv.ctx_for("system")
    c = inv.run(analyst, lambda s: prio.apply(s.cases, case["id"], case["record_version"], rationale="policy"))
    policy_priority = c["priority"]
    soon = datetime.now(timezone.utc) + timedelta(days=1)
    c = inv.run(analyst, lambda s: prio.override(s.cases, case["id"], c["record_version"], priority="low",
                                                 rationale="compensating control", expires_at=soon))
    assert c["priority"] == "low"
    with pytest.raises(Conflict) as err:                          # policy does not silently replace an active override
        inv.run(analyst, lambda s: prio.apply(s.cases, case["id"], c["record_version"], rationale="again"))
    assert err.value.code == "override_active"
    with pytest.raises(ValidationFailed):
        inv.run(analyst, lambda s: prio.override(s.cases, case["id"], c["record_version"], priority="low",
                                                 rationale="x", expires_at=soon + timedelta(days=400)))
    with inv.db.tenant_tx(system) as conn:
        assert prio.expire_overrides(conn, system)["expired"] == 0
    with inv.db.tenant_tx(system) as conn:                        # evaluated as if two days later
        out = prio.expire_overrides(conn, system, now=soon + timedelta(days=1))
    assert out == {"expired": 1, "reassessed": 1, "closed_cases": 0}
    after = inv.run(analyst, lambda s: s.cases.get(case["id"]))
    assert after["priority"] == policy_priority                   # re-derived, here equal to the policy result
    d = inv.run(analyst, lambda s: s.conn.execute(
        """SELECT d.*, axiom_auth.principal_kind(d.actor_principal_id) AS actor_kind, e.payload FROM axiom.decisions d
             JOIN axiom.case_events e ON e.decision_id = d.id
            WHERE d.case_id = %s ORDER BY d.recorded_at DESC LIMIT 1""", (case["id"],)).fetchone())
    assert (d["kind"], d["actor_kind"], d["authority"]["permission"]) == ("prioritisation", "workload", "priority.apply")
    assert "expired" in d["limitations"] and "not restored" in d["limitations"]
    assert d["payload"]["provenance"]["override_priority"] == "low"
    ov = inv.run(analyst, lambda s: s.conn.execute("SELECT * FROM axiom.priority_overrides WHERE case_id = %s",
                                                    (case["id"],)).fetchone())
    assert (ov["end_reason"], ov["ended_by_decision_id"]) == ("expired", d["id"])


def test_expired_override_does_not_restore_a_stale_priority(inv):
    case = first_case(inv)
    analyst, system = inv.ctx_for("analyst"), inv.ctx_for("system")
    from axiom.domains.assets.service import AssetService, assert_business_context
    with inv.db.tenant_tx(analyst) as conn:                  # start from critical so that "low" must differ
        assert_business_context(AssetService(conn, analyst, Authorizer(conn, analyst)), asset_id=case["asset_id"],
                                rationale="test asset", criticality="critical")
    c = inv.run(analyst, lambda s: prio.apply(s.cases, case["id"], case["record_version"], rationale="policy"))
    before = c["priority"]
    soon = datetime.now(timezone.utc) + timedelta(hours=1)
    c = inv.run(analyst, lambda s: prio.override(s.cases, case["id"], c["record_version"], priority="urgent",
                                                 rationale="incident", expires_at=soon))
    # inputs change while the override is in force: the asset is asserted low criticality
    with inv.db.tenant_tx(analyst) as conn:
        assert_business_context(AssetService(conn, analyst, Authorizer(conn, analyst)), asset_id=case["asset_id"],
                                rationale="test asset", criticality="low")
    with inv.db.tenant_tx(system) as conn:
        prio.expire_overrides(conn, system, now=soon + timedelta(minutes=1))
    after = inv.run(analyst, lambda s: s.cases.get(case["id"]))
    matrix = DEFAULTS["priority"]["matrix"][case_sev(inv, case)]
    expected = matrix["low"]
    assert before == matrix["critical"] and expected != before      # the scenario can tell restoring from reassessing
    assert after["priority"] == expected


def case_sev(inv, case):
    sev = inv.run(inv.ctx_for("analyst"), lambda s: s.conn.execute(
        """SELECT o.source_severity FROM axiom.case_occurrence_links l JOIN axiom.finding_occurrences o ON o.id = l.occurrence_id
            WHERE l.case_id = %s""", (case["id"],)).fetchone())["source_severity"].lower()
    return "medium" if sev == "moderate" else sev


def test_preview_shows_effects_without_changing_anything(inv, dbinfo):
    from axiom.provisioning import Provisioner
    case = first_case(inv)
    analyst = inv.ctx_for("analyst")
    inv.run(analyst, lambda s: prio.apply(s.cases, case["id"], case["record_version"], rationale="policy"))
    everyone_urgent = {**DEFAULTS["priority"], "matrix": {s: {c: "urgent" for c in ("critical", "high", "medium", "low")}
                                                          for s in ("critical", "high", "medium", "low", "info")}}
    p = Provisioner(dbinfo.admin_cli_dsn)
    p.bootstrap_role(inv.world.a.id, inv.world["admin"], "policy_admin", inv.world.a.root, "preview test")
    draft = PolicyService_call(inv, "admin", lambda s: s.draft(kind="priority", definition=everyone_urgent,
                                                               rationale="what if"))

    def state():
        return inv.run(analyst, lambda s: s.conn.execute(
            """SELECT (SELECT count(*) FROM axiom.case_events) AS ev, (SELECT count(*) FROM axiom.decisions) AS d,
                      (SELECT string_agg(priority || record_version::text, ',' ORDER BY id) FROM axiom.finding_cases) AS c,
                      (SELECT count(*) FROM axiom.priority_overrides) AS o""").fetchone())
    before = state()
    out = PolicyService_call(inv, "admin", lambda s: s.preview(draft["id"]))
    assert state() == before and out["mutated"] is False
    items = {str(i["case_id"]): i for i in out["items"]}
    one = items[str(case["id"])]
    assert one["preview_priority"] == "urgent" and one["current_priority"] != "urgent" and one["changes"]
    assert "no asserted asset criticality" in " ".join(one["missing_inputs"])
    assert out["previewed"] == {"version": draft["version"], "status": "draft"}
    assert out["counts"]["cases"] == len(out["items"]) and out["counts"]["with_missing_inputs"] == out["counts"]["cases"]
    # an active override is reported as holding the case
    c = inv.run(analyst, lambda s: s.cases.get(case["id"]))
    inv.run(analyst, lambda s: prio.override(s.cases, case["id"], c["record_version"], priority="low", rationale="x"))
    out = PolicyService_call(inv, "admin", lambda s: s.preview(definition=everyone_urgent))
    held = {str(i["case_id"]): i for i in out["items"]}[str(case["id"])]
    assert held["override"]["priority"] == "low" and "override is in force" in held["note"]
    # cross-tenant: tenant B sees none of tenant A's cases
    ctx_b = inv.ctx_for("analyst_b", "b")                    # analysts hold policy.preview in their own tenant
    with inv.db.tenant_tx(ctx_b) as conn:
        b_out = PolicyService(conn, ctx_b, Authorizer(conn, ctx_b)).preview(definition=everyone_urgent)
    assert str(case["id"]) not in {str(i["case_id"]) for i in b_out["items"]}


def PolicyService_call(inv, who, fn):
    ctx = inv.ctx_for(who)
    with inv.db.tenant_tx(ctx) as conn:
        return fn(PolicyService(conn, ctx, Authorizer(conn, ctx)))
