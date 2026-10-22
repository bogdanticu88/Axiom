"""The revocation boundary at transaction level (ADR 0012 amendments 3 and 4).

Covered elsewhere: a revocation committed first is seen by the next check, and a revocation issued after a command's
check waits for that command (test_authority_review_cp7.py); the worker's commit phase (test_verification_worker.py).
Here: failed and rolled-back commands release the locks at once, other ways of withdrawing authority, and the
operations that do not take part in the boundary.
"""
from __future__ import annotations

import threading
import time

import psycopg
import pytest

from axiom.access import Authorizer, PermissionDenied
from axiom.domains.cases.service import CaseService
from axiom.provisioning import Provisioner

pytestmark = pytest.mark.db


def binding_of(admin_conn, principal):
    return admin_conn.execute("SELECT id FROM axiom.role_bindings WHERE principal_id = %s AND revoked_at IS NULL",
                              (principal,)).fetchone()["id"]


def in_background(fn):
    done = {}

    def go():
        fn()
        done["at"] = time.monotonic()
    t = threading.Thread(target=go)
    t.start()
    return t, done


@pytest.mark.parametrize("ending", ["exception", "failed_statement"])
def test_a_command_that_fails_after_its_check_releases_the_lock_and_commits_nothing(db, run, ctx_for, world,
                                                                                    admin_conn, ending):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    binding = binding_of(admin_conn, world["analyst"])
    analyst = ctx_for("analyst")
    t = None
    with pytest.raises((RuntimeError, psycopg.Error)):
        with db.tenant_tx(analyst) as conn:
            CaseService(conn, analyst, Authorizer(conn, analyst)).start_investigation(case["id"], 0, "triage")
            t, done = in_background(lambda: run(ctx_for("admin"), lambda s: s.tenancy.revoke_role(
                binding_id=binding, reason="left")))
            t.join(1.0)
            assert "at" not in done                                  # waiting behind the command
            ended = time.monotonic()
            if ending == "exception":
                raise RuntimeError("request failed after its permission check")
            conn.execute("SELECT 1/0")
    t.join(10)
    assert done["at"] - ended < 5                                    # released by the rollback, not a timeout
    assert run(ctx_for("analyst2"), lambda s: s.cases.get(case["id"]))["workflow"] == "received"   # nothing committed
    with pytest.raises(PermissionDenied):
        run(ctx_for("analyst"), lambda s: s.cases.start_investigation(case["id"], 0, "again"))


def test_shortening_a_membership_waits_like_a_suspension(db, run, ctx_for, world, admin_conn):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    analyst = ctx_for("analyst")

    def expire_now():
        with psycopg.connect(admin_conn.info.dsn) as c:              # owner connection, as an operator would
            c.execute("UPDATE axiom.memberships SET valid_until = clock_timestamp(), record_version = record_version + 1"
                      " WHERE tenant_id = %s AND principal_id = %s", (world.a.id, world["analyst"]))
    with db.tenant_tx(analyst) as conn:
        CaseService(conn, analyst, Authorizer(conn, analyst)).start_investigation(case["id"], 0, "triage")
        t, done = in_background(expire_now)
        t.join(1.0)
        assert "at" not in done
        committed = time.monotonic()
    t.join(10)
    assert done["at"] >= committed
    with pytest.raises(PermissionDenied):
        run(ctx_for("analyst"), lambda s: s.cases.escalate(case["id"], 1, "again"))


def test_the_runtime_role_cannot_move_a_binding_or_a_scope(world, dbinfo, admin_conn):
    """Authority could be moved without a revocation only by changing what a binding covers. The runtime role cannot:
    a binding's scope and role are not updatable, and scopes cannot be re-parented."""
    binding = binding_of(admin_conn, world["analyst"])
    with psycopg.connect(dbinfo.app_dsn) as c:
        for stmt, args in (("UPDATE axiom.role_bindings SET scope_id = %s WHERE id = %s", (world.a.other_project, binding)),
                           ("UPDATE axiom.role_bindings SET role_id = 'approver' WHERE id = %s", (binding,)),
                           ("UPDATE axiom.scopes SET parent_id = %s WHERE id = %s", (world.a.other_project, world.a.project))):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with c.transaction():
                    c.execute("SELECT axiom.bind_context(%s, %s)", (world.a.id, world["admin"]))
                    c.execute(stmt, args)


def test_disabling_a_principal_does_not_wait_for_its_open_command(db, run, ctx_for, world, dbinfo, issuer):
    """Not part of the boundary: principal records are changed by the provisioning identity, which cannot lock them
    against the runtime role, and the authority check reads bindings and memberships, not the principal's status. An
    open command may still commit after the principal is disabled; the next request is refused at authentication."""
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    analyst = ctx_for("analyst")
    p = Provisioner(dbinfo.admin_cli_dsn)
    with db.tenant_tx(analyst) as conn:
        CaseService(conn, analyst, Authorizer(conn, analyst)).start_investigation(case["id"], 0, "triage")
        with p._connect() as c:
            c.execute("UPDATE axiom.principals SET status = 'disabled' WHERE id = %s", (world["analyst"],))
        disabled_first = True
    assert disabled_first
    assert run(ctx_for("analyst2"), lambda s: s.cases.get(case["id"]))["workflow"] == "investigating"
    with db.unbound_tx() as conn:                                     # the next request cannot authenticate
        assert conn.execute("SELECT * FROM axiom_auth.resolve_principal(%s, %s, %s)",
                            (issuer.issuer, issuer.audience, world.subjects["analyst"])).fetchall() == []
