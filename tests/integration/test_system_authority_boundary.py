"""Negative tests for the human/system authority boundary (checkpoint 6 review; migrations 0014 and 0016).

Each refusal is checked for the *reason* it was refused (permission denied by the service, or the database guard's
own message), so a test cannot pass because something unrelated failed first.

The tenant system principal holds exactly one role, ``ingestion_worker`` (case.read, case.create, case.reopen,
asset.read, asset.manage, ingestion.read, evidence.upload, job.read, priority.apply, ownership.route), bound at the
tenant root. Workload principals can hold only roles marked for workloads (migration 0016).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from axiom.access import Authorizer, PermissionDenied
from axiom.db import TenantContext
from axiom.domains.actions.service import ActionService
from axiom.domains.cases import priority as prio
from axiom.domains.cases.risk import RiskService
from axiom.domains.cases.service import EvidenceRef
from axiom.errors import NotFound, ValidationFailed

from .test_actions import Env, PAYLOAD  # noqa: F401
from .test_api import as_, client  # noqa: F401

pytestmark = pytest.mark.db
GUARD = "not a policy-authorised system result"


def soon(days=30):
    return datetime.now(timezone.utc) + timedelta(days=days)


def insert_decision(db, ctx, case_id, kind, outcome, authority):
    with db.tenant_tx(ctx) as conn:
        conn.execute(
            """INSERT INTO axiom.decisions(tenant_id, id, case_id, kind, outcome, rationale, actor_principal_id, authority)
               VALUES (%s, gen_random_uuid(), %s, %s, %s, 'test', %s, %s)""",
            (ctx.tenant_id, case_id, kind, outcome, ctx.principal_id, json.dumps(authority)))


@pytest.fixture()
def review_case(world, run, ctx_for, upload):
    analyst = ctx_for("analyst")
    case = run(analyst, lambda s: s.cases.create(scope_id=world.a.project, title="exposed admin panel"))
    ev = upload(analyst, world.a.project, b"scan: admin panel reachable")
    run(analyst, lambda s: s.cases.start_investigation(case["id"], 0, "triage"))
    return run(analyst, lambda s: s.cases.record_assessment(case["id"], 1, assessment="supported", rationale="ok",
                                                             limitations="none", evidence=[EvidenceRef(ev["id"])]))


# ------------------------------------------------------------------- 1. discretionary actions by a system principal
def test_system_principal_cannot_override_priority(run, ctx_for, review_case):
    with pytest.raises(PermissionDenied):
        run(ctx_for("system"), lambda s: prio.override(s.cases, review_case["id"], review_case["record_version"],
                                                       priority="low", rationale="system says so"))


def test_system_principal_cannot_request_or_accept_risk(run, ctx_for, review_case):
    system = ctx_for("system")
    with pytest.raises(PermissionDenied):
        run(system, lambda s: RiskService(s.conn, system, s.authz).request(
            review_case["id"], review_case["record_version"], expires_at=soon(), rationale="automatic"))
    with pytest.raises(PermissionDenied):
        run(system, lambda s: s.cases.accept_risk(review_case["id"], review_case["record_version"],
                                                  expires_at=soon(), rationale="automatic"))
    owner = ctx_for("risk_owner")      # a pending request made by a person cannot be authorised by the system
    req = run(owner, lambda s: RiskService(s.conn, owner, s.authz).request(
        review_case["id"], review_case["record_version"], expires_at=soon(), rationale="mitigated"))
    with pytest.raises(PermissionDenied):
        run(system, lambda s: RiskService(s.conn, system, s.authz).authorise(req["id"], rationale="automatic"))


def test_system_principal_cannot_approve_an_action(env, admin_conn):
    proposal = env.propose()
    with pytest.raises((PermissionDenied, NotFound)):      # no proposal.read either: the proposal is not visible
        env.svc("system", lambda s: s.decide(proposal["id"], 1, decision="approved", rationale="automatic"))
    # database backstop: a hand-written approval row by the system principal is refused by the human guard
    v = proposal["version"]
    system = env.ctx_for("system")
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as err:
        with env.db.tenant_tx(system) as conn:
            conn.execute(
                """INSERT INTO axiom.approvals(tenant_id, id, proposal_id, proposal_version_id, payload_digest, decision,
                       approver_principal_id, authorised_scope_id, authority_snapshot, rationale, valid_until,
                       max_uses, status) VALUES (%s, gen_random_uuid(), %s, %s, %s, 'approved', %s, %s,
                       '{"permission": "action.approve.ticket.create"}', 'forged', %s, 1, 'active')""",
                (system.tenant_id, proposal["id"], v["id"], v["payload_digest"], system.principal_id,
                 env.world.a.root, soon(5)))
    assert GUARD in str(err.value)


@pytest.mark.parametrize("kind,outcome", [("risk_acceptance", "accepted"), ("priority_override", "low"),
                                          ("assessment", "supported"), ("closure", "dismissed"),
                                          ("reopen", "authorised_reassessment")])
def test_database_refuses_discretionary_decisions_by_the_system_even_with_forged_authority(db, run, ctx_for, world,
                                                                                           kind, outcome):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as err:
        insert_decision(db, ctx_for("system"), case["id"], kind, outcome,
                        {"permission": "anything", "system": True, "roles": ["tenant_admin"]})
    assert GUARD in str(err.value)


def test_system_principal_cannot_be_given_a_human_role(run, ctx_for, world, dbinfo):
    from axiom.provisioning import Provisioner
    for role in ("approver", "risk_owner", "analyst", "tenant_admin"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as err:       # through the tenant admin API path
            run(ctx_for("admin"), lambda s: s.tenancy.assign_role(principal_id=world.a.system, role_id=role,
                                                                  scope_id=world.a.project, reason="automation"))
        assert "is for human principals" in str(err.value)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):                   # and through provisioning
        Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world.a.system, "approver", world.a.root, "x")
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as err:            # nor a person a workload role
        run(ctx_for("admin"), lambda s: s.tenancy.assign_role(principal_id=world["analyst"], role_id="ingestion_worker",
                                                              scope_id=world.a.project, reason="x"))
    assert "is for workload principals" in str(err.value)


def test_system_reopen_is_limited_to_policy_reasons(run, ctx_for, world):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    with pytest.raises(ValidationFailed):
        run(ctx_for("system"), lambda s: s.cases.reopen(case["id"], 0, reason="authorised_reassessment",
                                                        rationale="x", system=True))


# ------------------------------------------------------------------- 2. callers cannot supply their principal type
def test_principal_type_cannot_be_supplied_in_requests_or_tokens(client, as_, world, issuer):  # noqa: F811
    r = client.post("/api/v1/cases", headers=as_("analyst"),
                    json={"scope_id": str(world.a.project), "title": "t", "principal_kind": "workload"})
    assert r.status_code == 422                                              # unknown body field refused
    forged = issuer.token(world.subjects["analyst"], principal_kind="workload", kind="workload",
                          roles=["approver"], groups=["tenant_admin"])
    h = {"Authorization": f"Bearer {forged}", "X-Axiom-Tenant": world.a.slug, "X-Principal-Kind": "workload"}
    me = client.get("/api/v1/me", headers=h).json()
    assert me["kind"] == "human" and me["principal_id"] == str(world["analyst"])
    # token claims grant nothing: the analyst still cannot do what an approver or admin could
    r = client.post("/api/v1/role-bindings", headers=h, json={"principal_id": str(world["viewer"]),
                                                              "role_id": "approver", "scope_id": str(world.a.project),
                                                              "reason": "claims say so"})
    assert r.status_code == 403


def test_decisions_record_the_kind_from_identity_records(db, run, ctx_for, world, admin_conn):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    lying = TenantContext(world.a.id, world.a.system, "human", "claims-to-be-human")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        insert_decision(db, lying, case["id"], "assessment", "supported", {"permission": "assessment.record"})
    run(lying, lambda s: prio.apply(s.cases, case["id"], 0, rationale="policy"))
    d = admin_conn.execute("SELECT authority FROM axiom.decisions WHERE case_id = %s AND kind = 'prioritisation'",
                           (case["id"],)).fetchone()
    assert d["authority"]["permission"] == "priority.apply"
    kinds = {r["actor_kind"] for r in admin_conn.execute(
        "SELECT actor_kind FROM axiom.audit_events WHERE actor_principal_id = %s", (world.a.system,))}
    assert kinds == {"workload"}            # the audit trail records the kind from identity records, not the context


# ------------------------------------------------------------------- 3. permitted system operations out of scope
def test_system_operation_in_another_tenant_is_invisible(run, ctx_for, world):
    case_b = run(ctx_for("analyst_b", "b"), lambda s: s.cases.create(scope_id=world.b.project, title="b"))
    with pytest.raises(NotFound):
        run(ctx_for("system", "a"), lambda s: prio.apply(s.cases, case_b["id"], 0, rationale="policy"))


def test_workload_bound_to_one_project_cannot_act_on_another(db, run, ctx_for, world, dbinfo):
    from axiom.provisioning import Provisioner
    p = Provisioner(dbinfo.admin_cli_dsn)
    worker = p.create_principal("scoped importer", kind="workload")
    p.add_membership(world.a.id, worker)
    p.bootstrap_role(world.a.id, worker, "ingestion_worker", world.a.project, "project-scoped importer")
    ctx = TenantContext(world.a.id, worker, "workload", "scoped")
    mine = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="in scope"))
    other = run(ctx_for("marketing_analyst"), lambda s: s.cases.create(scope_id=world.a.other_project, title="out"))
    run(ctx, lambda s: prio.apply(s.cases, mine["id"], 0, rationale="policy"))          # in its scope: allowed
    with pytest.raises((PermissionDenied, NotFound)):
        run(ctx, lambda s: prio.apply(s.cases, other["id"], 0, rationale="policy"))
    # the database checks the real binding, not the JSON: a forged in-scope authority for the other project fails
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as err:
        insert_decision(db, ctx, other["id"], "prioritisation", "high", {"permission": "priority.apply"})
    assert "requires priority.apply at the case scope" in str(err.value)


def test_revoked_system_binding_stops_policy_results(db, run, ctx_for, world, admin_conn):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    admin_conn.execute("UPDATE axiom.role_bindings SET revoked_at = clock_timestamp() WHERE principal_id = %s",
                       (world.a.system,))                                                # operator revocation
    with pytest.raises(PermissionDenied):
        run(ctx_for("system"), lambda s: prio.apply(s.cases, case["id"], 0, rationale="policy"))
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as err:
        insert_decision(db, ctx_for("system"), case["id"], "prioritisation", "high", {"permission": "priority.apply"})
    assert "requires priority.apply" in str(err.value)


# ------------------------------------------------------------------- 4. revocation takes effect on the next request
def test_role_and_membership_revocation_apply_to_the_next_bearer_request(client, as_, world, run, ctx_for):  # noqa: F811
    h = as_("analyst2")
    assert client.get("/api/v1/cases", headers=h).status_code == 200
    created = client.post("/api/v1/cases", headers=h, json={"scope_id": str(world.a.project), "title": "before"})
    assert created.status_code == 201
    binding = run(ctx_for("admin"), lambda s: s.conn.execute(
        "SELECT id FROM axiom.role_bindings WHERE principal_id = %s AND revoked_at IS NULL", (world["analyst2"],)).fetchone())
    run(ctx_for("admin"), lambda s: s.tenancy.revoke_role(binding_id=binding["id"], reason="left the team"))
    # same token, next request: the role no longer applies (the token is still valid; authority is not cached)
    r = client.post("/api/v1/cases", headers=h, json={"scope_id": str(world.a.project), "title": "after"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "permission_denied"
    r = client.get(f"/api/v1/cases/{created.json()['id']}", headers=h)
    assert r.status_code == 403 and r.json()["error"]["code"] == "permission_denied"
    run(ctx_for("admin"), lambda s: s.tenancy.suspend_membership(principal_id=world["analyst2"], reason="left"))
    r = client.get("/api/v1/cases", headers=h)
    assert r.status_code == 403 and r.json()["error"]["code"] == "tenant_not_available"


@pytest.fixture()
def env(db, world, ctx_for, dbinfo, run):
    return Env(db, world, ctx_for, dbinfo, run)
