"""What the application database credential can and cannot do (ADR 0002 amendment, ADR 0012 amendment 4).

The database does not authenticate people. ``axiom.bind_context(tenant, principal)`` records which tenant and
principal the *application* says it is acting for; the API calls it after authenticating the request. Anyone holding
the runtime login (``axiom_app``, shared by the API and the job worker for every tenant of an installation) can call
it with any values. The first group of tests pins that capability down so the documentation cannot drift from it:
they pass because the capability exists. The second group shows the guarantees that still hold for a holder of that
credential. The third covers transaction and connection-pool behaviour.
"""
from __future__ import annotations

import psycopg
import pytest
from psycopg.rows import dict_row

from axiom.access import Authorizer
from axiom.db import TenantContext
from axiom.domains.actions.service import ActionService

from .test_actions import Env

pytestmark = pytest.mark.db


@pytest.fixture()
def app(dbinfo):
    """A raw connection with the runtime login: what an attacker holding the application credential has."""
    with psycopg.connect(dbinfo.app_dsn, row_factory=dict_row) as conn:
        yield conn


def bind(conn, tenant, principal):
    conn.execute("SELECT axiom.bind_context(%s, %s)", (tenant, principal))


# --------------------------------------------------------------------- accepted capability of the runtime credential
def test_the_runtime_credential_can_bind_any_tenant_and_any_principal(world, run, ctx_for, app):
    """Not limited to "its" tenant: one runtime login serves every tenant of a shared installation, and nothing checks
    that the principal is a member of the tenant it is bound to."""
    case_b = run(ctx_for("analyst_b", tenant="b"), lambda s: s.cases.create(scope_id=world.b.project, title="b only"))
    with app.transaction():
        bind(app, world.b.id, world["outsider"])            # a principal with no membership anywhere
        titles = [r["title"] for r in app.execute("SELECT title FROM axiom.finding_cases")]
    assert "b only" in titles
    with app.transaction():
        bind(app, world.a.id, world["analyst_b"])           # a principal of tenant B, bound to tenant A
        assert app.execute("SELECT count(*) AS n FROM axiom.finding_cases WHERE id = %s",
                           (case_b["id"],)).fetchone()["n"] == 0      # RLS still separates the tenants' rows


def test_the_runtime_credential_can_act_as_any_principal_including_an_approver(db, world, ctx_for, dbinfo, run,
                                                                               admin_conn):
    """Separation of duties holds between principals, not between people who control the credential: binding the
    approver's identity approves the analyst's proposal, and the records attribute it to the approver."""
    env = Env(db, world, ctx_for, dbinfo, run)
    proposal = env.propose(who="analyst")
    impersonated = TenantContext(world.a.id, world["approver"], "human", "forged-request")
    with db.tenant_tx(impersonated) as conn:            # no token, no session: only the credential
        approval = ActionService(conn, impersonated, Authorizer(conn, impersonated)).decide(
            proposal["id"], 1, decision="approved", rationale="looks fine", max_uses=1)
    assert approval["approver_principal_id"] == world["approver"]
    actor = admin_conn.execute("""SELECT actor_principal_id, actor_kind FROM axiom.audit_events
                                   WHERE resource_id = %s AND action = 'action.approved'""",
                               (str(approval["id"]),)).fetchone()
    assert (actor["actor_principal_id"], actor["actor_kind"]) == (world["approver"], "human")


def test_the_runtime_credential_can_write_audit_rows_attributed_to_anyone(world, app, admin_conn):
    with app.transaction():
        bind(app, world.a.id, world["auditor"])
        app.execute("""INSERT INTO axiom.audit_events(tenant_id, id, actor_principal_id, actor_kind, action,
                           resource_type, resource_id, outcome, correlation_id, detail)
                       VALUES (%s, gen_random_uuid(), %s, 'human', 'report.export', 'report', gen_random_uuid(),
                               'committed', 'forged', '{}')""", (world.a.id, world["auditor"]))
    n = admin_conn.execute("SELECT count(*) AS n FROM axiom.audit_events WHERE correlation_id = 'forged'").fetchone()
    assert n["n"] == 1


def test_the_no_switch_rule_is_enforced_by_bind_context_only(world, app):
    """bind_context refuses a second principal in one transaction, but the context is an ordinary setting: the
    runtime role can overwrite it directly. The rule catches application bugs; it is not a barrier to a holder of
    the credential (who could equally start a new transaction)."""
    with app.transaction():
        bind(app, world.a.id, world["analyst"])
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="already bound"):
            with app.transaction():
                bind(app, world.a.id, world["approver"])
        app.execute("SELECT set_config('axiom.ctx', %s || '|' || %s || '|' || axiom.tx_marker(), true)",
                    (str(world.a.id), str(world["approver"])))
        assert app.execute("SELECT axiom.current_principal() AS p").fetchone()["p"] == world["approver"]


def test_human_permissions_are_checked_by_the_application_not_the_database(world, run, ctx_for, app):
    """For people, the database checks only that the recorded actor is the bound principal. Whether that person
    holds the permission is the application's check: a viewer bound directly can append a decision row (it does not
    change the case, whose state transitions the database does guard)."""
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="t"))
    with app.transaction():
        bind(app, world.a.id, world["viewer"])
        app.execute("""INSERT INTO axiom.decisions(tenant_id, id, case_id, kind, outcome, rationale, actor_principal_id,
                           authority) VALUES (%s, gen_random_uuid(), %s, 'assessment', 'supported', 'x', %s, '{}')""",
                    (world.a.id, case["id"], world["viewer"]))
    assert run(ctx_for("analyst"), lambda s: s.cases.get(case["id"]))["assessment"] == "unassessed"


# ---------------------------------------------------------------------------------- guarantees that still hold
@pytest.mark.parametrize("table", ["decisions", "audit_events", "case_events"])
def test_recorded_history_cannot_be_rewritten_with_the_runtime_credential(world, run, ctx_for, app, table):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="history"))
    run(ctx_for("analyst"), lambda s: s.cases.start_investigation(case["id"], 0, "triage"))
    for stmt in (f"UPDATE axiom.{table} SET tenant_id = tenant_id", f"DELETE FROM axiom.{table}"):
        with app.transaction():
            bind(app, world.a.id, world["admin"])
            assert app.execute(f"SELECT count(*) AS n FROM axiom.{table}").fetchone()["n"] > 0
        with pytest.raises(psycopg.Error):
            with app.transaction():
                bind(app, world.a.id, world["admin"])
                app.execute(stmt)


def test_the_runtime_credential_cannot_escalate_its_database_privileges(app):
    for stmt in ("SET ROLE axiom_owner", "SET ROLE axiom_authn", "SET row_security = off",
                 "SELECT * FROM axiom.ui_sessions", "SELECT * FROM axiom.federated_identities"):
        with pytest.raises(psycopg.Error):
            with app.transaction():
                app.execute(stmt)
                if stmt.startswith("SET row_security"):
                    # turning row security off is allowed as a setting, but then RLS raises instead of filtering
                    app.execute("SELECT count(*) FROM axiom.finding_cases")


def test_without_a_bound_context_the_runtime_credential_sees_no_tenant_rows(world, run, ctx_for, app):
    run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="hidden"))
    with app.transaction():
        assert app.execute("SELECT count(*) AS n FROM axiom.finding_cases").fetchone()["n"] == 0


def test_database_structure_rules_hold_against_the_credential(world, app):
    """Kind rules do not depend on who is bound: a workload principal still cannot be given a human role, even by
    a transaction bound to a tenant administrator."""
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with app.transaction():
            bind(app, world.a.id, world["admin"])
            app.execute("""INSERT INTO axiom.role_bindings(tenant_id, id, principal_id, role_id, scope_id, granted_by,
                               reason) VALUES (%s, gen_random_uuid(), %s, 'approver', %s, %s, 'x')""",
                        (world.a.id, world.a.system, world.a.project, world["admin"]))


# ------------------------------------------------------------------------------- transactions and pooled connections
def test_context_ends_with_the_transaction_after_commit_rollback_and_failure(world, dbinfo):
    from axiom.db import Database
    db = Database(dbinfo.app_dsn, min_size=1, max_size=1, name="single")
    db.open()
    try:
        a = TenantContext(world.a.id, world["analyst"], "human", "t")
        pids = set()

        def unbound():
            with db.unbound_tx() as conn:
                pids.add(conn.info.backend_pid)
                return conn.execute("SELECT axiom.current_tenant() AS t, axiom.current_principal() AS p").fetchone()

        with db.tenant_tx(a) as conn:
            pids.add(conn.info.backend_pid)
        assert unbound() == {"t": None, "p": None}                        # after commit
        with pytest.raises(RuntimeError):
            with db.tenant_tx(a) as conn:
                raise RuntimeError("rolled back")
        assert unbound() == {"t": None, "p": None}                        # after rollback
        with pytest.raises(psycopg.Error):
            with db.tenant_tx(a) as conn:
                conn.execute("SELECT 1/0")
        assert unbound() == {"t": None, "p": None}                        # after a failed statement
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with db.tenant_tx(a) as conn:
                conn.execute("SELECT axiom.bind_context(%s, %s)", (world.b.id, world["analyst"]))   # replace tenant
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with db.tenant_tx(a) as conn:
                conn.execute("SELECT axiom.bind_context(%s, %s)", (world.a.id, world["approver"]))  # replace actor
        assert unbound() == {"t": None, "p": None}
        assert len(pids) == 1, "one pooled connection must have been reused throughout"
    finally:
        db.close()
