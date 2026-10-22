"""Disabled principals, suspended tenants and expiry, checked at the next request (data design S 12 steps 2, 3, 6).

The transaction-level boundary is in test_revocation_boundary.py. These tests are about the ordinary case: once the
change has committed, the next command, job step or effect must be refused. Workload principals (the system and
verification identities) never authenticate through the identity provider, so the check that refuses a disabled
person at sign-in does not cover them; the authority check itself has to.

Binding expiry at the next request is cases::test_expired_binding_denied.
"""
from __future__ import annotations

import psycopg
import pytest

from axiom.access import PermissionDenied
from axiom.provisioning import Provisioner

from .test_actions import env  # noqa: F401
from .test_cases import advance_to_verification, scenario  # noqa: F401
from .test_verification_lifecycle import records
from .test_verification_worker import job_for, setup, target  # noqa: F401

pytestmark = pytest.mark.db


def disable(dbinfo, principal):
    with Provisioner(dbinfo.admin_cli_dsn)._connect() as c:
        c.execute("UPDATE axiom.principals SET status = 'disabled' WHERE id = %s", (principal,))


def test_a_disabled_verification_identity_cannot_record_a_result(world, run, ctx_for, scenario, setup, target,  # noqa: F811
                                                               admin_conn, dbinfo):
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    disable(dbinfo, setup.verifier)
    setup.worker.run_once(only_tenants={world.a.id})
    job = job_for(admin_conn, cid)
    assert job["state"] == "failed" and job["last_error"].startswith("authority_missing")
    assert len(target.requests) == 0                                  # refused before the endpoint is asked
    assert set(records(admin_conn, cid, setup.verifier).values()) == {0}
    assert run(ctx_for("analyst"), lambda s: s.cases.get(cid))["workflow"] == "awaiting_verification"


def test_an_action_approved_by_a_since_disabled_approver_is_not_executed(env, admin_conn, world, dbinfo):  # noqa: F811
    p = env.propose()
    a = env.approve(p)
    e = env.execute(p, a)
    disable(dbinfo, world["approver"])
    assert env.drive(admin_conn, e["job_id"])["state"] == "failed"
    assert "approver no longer holds action.approve" in env.execution(e["id"])["outcome_detail"]["error"]
    assert env.fake.create_requests == 0


def test_a_disabled_principal_holds_no_permission_in_the_database(world, dbinfo, admin_conn):
    """axiom.holds_permission is what the database's own guards consult."""
    q = "SELECT axiom.holds_permission(%s, 'investigation.request', %s) AS ok"
    assert admin_conn.execute(q, (world["analyst"], world.a.project)).fetchone()["ok"]
    disable(dbinfo, world["analyst"])
    assert not admin_conn.execute(q, (world["analyst"], world.a.project)).fetchone()["ok"]


def test_a_disabled_principal_bound_directly_is_refused(world, run, ctx_for, dbinfo):
    """A request that reaches the service with a disabled principal (an existing worker context, or a defect that
    skips authentication) is refused by the authority check, not only at sign-in."""
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    disable(dbinfo, world["analyst"])
    with pytest.raises(PermissionDenied):
        run(ctx_for("analyst"), lambda s: s.cases.start_investigation(case["id"], 0, "triage"))


def test_a_suspended_tenant_refuses_the_next_command_and_its_workers_stop(world, run, ctx_for, dbinfo, db):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    Provisioner(dbinfo.admin_cli_dsn).set_tenant_status(world.a.id, "suspended")
    with pytest.raises(Exception):
        run(ctx_for("analyst"), lambda s: s.cases.start_investigation(case["id"], 0, "triage"))
    with db.unbound_tx() as conn:
        workers = {r["tenant_id"] for r in conn.execute("SELECT * FROM axiom_auth.active_tenant_workers()")}
    assert world.a.id not in workers and world.b.id in workers


def test_an_expired_membership_refuses_the_next_command(world, run, ctx_for, admin_conn):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    admin_conn.execute("""UPDATE axiom.memberships SET valid_until = clock_timestamp(), record_version = record_version + 1
                           WHERE tenant_id = %s AND principal_id = %s""", (world.a.id, world["analyst"]))
    with pytest.raises(PermissionDenied):
        run(ctx_for("analyst"), lambda s: s.cases.start_investigation(case["id"], 0, "triage"))


def test_suspending_a_tenant_while_its_check_runs(world, run, ctx_for, scenario, setup, target, admin_conn,  # noqa: F811
                                                 dbinfo):
    """In-flight work: the endpoint has already been asked when the suspension commits. That request cannot be taken
    back, but nothing is recorded for the suspended tenant. The worker's pass stops at the job's bookkeeping (the
    tenant's rows are no longer visible or writable), the job stays leased, and no worker serves the tenant again
    while it is suspended. Cancelling that job is the open part of TEN-16."""
    from .test_verification_worker import clean
    cid = advance_to_verification(run, ctx_for, world, scenario)["id"]
    prov = Provisioner(dbinfo.admin_cli_dsn)

    def suspended_meanwhile(req):
        prov.set_tenant_status(world.a.id, "suspended")
        return clean(req)
    target.behaviour = suspended_meanwhile
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        setup.worker.run_once(only_tenants={world.a.id})
    assert len(target.requests) == 1
    assert set(records(admin_conn, cid, setup.verifier).values()) == {0}
    assert job_for(admin_conn, cid)["state"] == "running"
    assert setup.worker.run_once(only_tenants={world.a.id}) == 0      # suspended tenants are not served
