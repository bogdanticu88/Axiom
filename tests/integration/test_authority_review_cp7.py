"""Adversarial tests of the authority boundary (ADR 0012 amendment 3, migration 0017).

Each test body attempts the attack directly:
  D1 a transaction bound to one principal cannot record a decision as another principal;
  D2 a bound transaction cannot re-bind to a different principal;
  D3 a revocation cannot commit between a command's permission check and the command's commit.
Hardening with no known application-level exploit:
  H1 bindings that predate migration 0016 are reviewed and incompatible ones revoked;
  H2 a principal's kind cannot change.
"""
from __future__ import annotations

import json
import threading
import time

import psycopg
import pytest

from axiom.access import Authorizer, PermissionDenied
from axiom.domains.cases import priority as prio
from axiom.domains.cases.service import CaseService

from .test_api import as_, client  # noqa: F401

pytestmark = pytest.mark.db
BOUND = "must be recorded by the principal bound to the transaction"


# ------------------------------------------------------------------------------------------------ D1, D2
def test_d1_bound_transaction_cannot_record_a_decision_as_someone_else(db, run, ctx_for, world):
    """Preconditions: code running with the runtime role in a transaction bound to the system principal.
    The insert attempts an assessment attributed to the analyst but written by the system context."""
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    system = ctx_for("system")
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as err:
        with db.tenant_tx(system) as conn:
            conn.execute(
                """INSERT INTO axiom.decisions(tenant_id, id, case_id, kind, outcome, rationale, actor_principal_id,
                       authority) VALUES (%s, gen_random_uuid(), %s, 'assessment', 'supported', 'forged', %s, '{}')""",
                (system.tenant_id, case["id"], world["analyst"]))
    assert BOUND in str(err.value)
    analyst2 = ctx_for("analyst2")              # the same holds between two humans
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as err:
        with db.tenant_tx(analyst2) as conn:
            conn.execute(
                """INSERT INTO axiom.decisions(tenant_id, id, case_id, kind, outcome, rationale, actor_principal_id,
                       authority) VALUES (%s, gen_random_uuid(), %s, 'escalation', 'escalated', 'x', %s, '{}')""",
                (analyst2.tenant_id, case["id"], world["analyst"]))
    assert BOUND in str(err.value)


def test_d1_approvals_must_be_recorded_by_the_bound_principal(db, world, ctx_for, dbinfo, run):
    from .test_actions import Env
    env = Env(db, world, ctx_for, dbinfo, run)
    p = env.propose()
    v = p["version"]
    approver = ctx_for("approver")
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as err:
        with db.tenant_tx(approver) as conn:       # bound to the approver, but the row names the risk owner
            conn.execute(
                """INSERT INTO axiom.approvals(tenant_id, id, proposal_id, proposal_version_id, payload_digest, decision,
                       approver_principal_id, authorised_scope_id, authority_snapshot, rationale, valid_until,
                       max_uses, status) VALUES (%s, gen_random_uuid(), %s, %s, %s, 'approved', %s, %s, '{}', 'x',
                       clock_timestamp() + interval '1 day', 1, 'active')""",
                (approver.tenant_id, p["id"], v["id"], v["payload_digest"], world["risk_owner"], world.a.project))
    assert BOUND in str(err.value)


def test_d2_a_bound_transaction_cannot_switch_principal(db, ctx_for, world):
    analyst = ctx_for("analyst")
    with pytest.raises(psycopg.errors.InsufficientPrivilege, match="principal context already bound"):
        with db.tenant_tx(analyst) as conn:
            conn.execute("SELECT axiom.bind_context(%s, %s)", (analyst.tenant_id, world["approver"]))


# ------------------------------------------------------------------------------------------------ D3
def _binding(run, ctx_for, who, world):
    return run(ctx_for("admin"), lambda s: s.conn.execute(
        "SELECT id FROM axiom.role_bindings WHERE principal_id = %s AND revoked_at IS NULL", (world[who],)).fetchone())["id"]


@pytest.mark.parametrize("revocation", ["role", "membership"])
def test_d3_revocation_waits_for_a_command_that_already_checked_the_permission(db, run, ctx_for, world, revocation):
    """A revocation issued while a command's transaction is open waits until the command ends, so the command never
    commits a decision whose authority has already been revoked."""
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    binding = _binding(run, ctx_for, "analyst", world)
    analyst, finished = ctx_for("analyst"), {}

    def revoke():
        if revocation == "role":
            run(ctx_for("admin"), lambda s: s.tenancy.revoke_role(binding_id=binding, reason="left"))
        else:
            run(ctx_for("admin"), lambda s: s.tenancy.suspend_membership(principal_id=world["analyst"], reason="left"))
        finished["at"] = time.monotonic()

    with db.tenant_tx(analyst) as conn:
        CaseService(conn, analyst, Authorizer(conn, analyst)).start_investigation(case["id"], 0, "triage")
        t = threading.Thread(target=revoke)
        t.start()
        t.join(1.5)
        assert "at" not in finished                 # blocked behind the command that relied on the binding
        committed_at = time.monotonic()
    t.join(10)
    assert finished["at"] >= committed_at           # the revocation completed only after the decision committed
    with pytest.raises((PermissionDenied, Exception)):    # and the next command is refused
        run(ctx_for("analyst"), lambda s: s.cases.escalate(case["id"], 1, "again"))


def test_d3_a_revocation_that_commits_first_is_seen_by_the_next_check(run, ctx_for, world):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    run(ctx_for("admin"), lambda s: s.tenancy.revoke_role(binding_id=_binding(run, ctx_for, "analyst", world),
                                                          reason="left"))
    with pytest.raises(PermissionDenied):
        run(ctx_for("analyst"), lambda s: s.cases.start_investigation(case["id"], 0, "triage"))


# ------------------------------------------------------------------------------------------------ H1, H2
def test_h1_bindings_that_predate_the_kind_rule_are_revoked_on_review(db, run, ctx_for, world, dbinfo, admin_conn):
    # fault injection: an approver binding on the system principal, as could exist before migration 0016
    admin_conn.execute("SET session_replication_role = replica")
    try:
        admin_conn.execute(
            """INSERT INTO axiom.role_bindings(tenant_id, id, principal_id, role_id, scope_id, granted_by, reason)
               VALUES (%s, gen_random_uuid(), %s, 'approver', %s, NULL, 'pre-0016 binding')""",
            (world.a.id, world.a.system, world.a.project))
    finally:
        admin_conn.execute("SET session_replication_role = origin")
    system = ctx_for("system")
    assert run(system, lambda s: s.authz.has("action.approve:ticket_create", world.a.project))      # the stale grant is live
    with psycopg.connect(dbinfo.admin_cli_dsn) as conn:                                 # provisioning identity
        n = conn.execute("SELECT axiom_auth.revoke_incompatible_bindings() AS n").fetchone()[0]
    assert n >= 1
    assert not run(system, lambda s: s.authz.has("action.approve:ticket_create", world.a.project))
    ev = admin_conn.execute("""SELECT reason_code FROM axiom.security_events WHERE event_type =
                               'role_binding.incompatible_revoked' AND principal_id = %s""", (world.a.system,)).fetchall()
    assert [e["reason_code"] for e in ev] == ["approver:workload"]
    with psycopg.connect(dbinfo.admin_cli_dsn) as conn:                                 # idempotent
        assert conn.execute("SELECT axiom_auth.revoke_incompatible_bindings()").fetchone()[0] == 0


def test_h2_principal_kind_cannot_change(dbinfo, world, admin_conn):
    with psycopg.connect(dbinfo.admin_cli_dsn) as conn:        # provisioning identity has no privilege on kind
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE axiom.principals SET kind = 'human' WHERE id = %s", (world.a.system,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege, match="kind cannot change"):   # nor the owner
        admin_conn.execute("UPDATE axiom.principals SET kind = 'human' WHERE id = %s", (world.a.system,))


# ------------------------------------------------------------------------------------------------ API path
def test_workload_identity_over_the_api_gets_only_workload_results(client, world, issuer, dbinfo, admin_conn):  # noqa: F811
    """A workload identity can authenticate with a bearer token. Over the API it can apply the priority policy
    (priority.apply) but cannot start investigations, override priority or approve; its decisions carry kind
    'workload' from the identity record."""
    from axiom.provisioning import Provisioner
    p = Provisioner(dbinfo.admin_cli_dsn)
    provider = p.ensure_identity_provider(issuer.issuer, issuer.audience)
    worker = p.create_principal("api importer", provider_id=provider, subject="importer-cp7", kind="workload")
    p.add_membership(world.a.id, worker)
    p.bootstrap_role(world.a.id, worker, "ingestion_worker", world.a.project, "test importer")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        p.bootstrap_role(world.a.id, worker, "analyst", world.a.project, "would give discretionary authority")
    h = {"Authorization": f"Bearer {issuer.token('importer-cp7')}", "X-Axiom-Tenant": world.a.slug}
    case = client.post("/api/v1/cases", headers=h, json={"scope_id": str(world.a.project), "title": "by importer"})
    assert case.status_code == 201
    cid = case.json()["id"]
    r = client.post(f"/api/v1/cases/{cid}/commands/start-investigation", headers=h,
                    json={"expected_version": 0, "rationale": "x"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "permission_denied"
    r = client.post(f"/api/v1/cases/{cid}/commands/override-priority", headers=h,
                    json={"expected_version": 0, "rationale": "x", "priority": "low"})
    assert r.status_code == 403
    r = client.post(f"/api/v1/cases/{cid}/commands/apply-priority-policy", headers=h,
                    json={"expected_version": 0, "rationale": "policy"})
    assert r.status_code == 200, r.text
    d = admin_conn.execute("SELECT d.kind, d.authority FROM axiom.decisions d WHERE d.case_id = %s", (cid,)).fetchone()
    a = admin_conn.execute("SELECT actor_kind FROM axiom.audit_events WHERE actor_principal_id = %s LIMIT 1",
                           (worker,)).fetchone()
    assert d["kind"] == "prioritisation" and d["authority"]["permission"] == "priority.apply"
    assert a["actor_kind"] == "workload"
    _ = json
