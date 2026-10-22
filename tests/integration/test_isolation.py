"""Database isolation and privilege tests (Data and Access Design section 13).

These run as the real runtime login (axiom_app) unless stated, against a database
migrated by the real runner. They test the database layer directly, bypassing
the service layer, to show what holds if application code is wrong.
"""
from __future__ import annotations

import shutil
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from axiom import migrate
from axiom.db import Database, TenantContext
from axiom.errors import ConfigurationError, Forbidden, Unauthenticated

pytestmark = pytest.mark.db

TENANT_TABLES = ["memberships", "scopes", "role_bindings", "delegation_limits", "audit_events", "outbox", "inbox",
                 "evidence_objects", "assets", "asset_versions", "finding_occurrences", "finding_cases",
                 "case_occurrence_links", "decisions", "decision_evidence", "case_events", "remediation_reports",
                 "verification_runs", "risk_acceptances", "closure_records"]


def bound(conn, tenant, principal):
    conn.execute("SELECT axiom.bind_context(%s, %s)", (tenant, principal))


@pytest.fixture()
def raw(dbinfo):
    with psycopg.connect(dbinfo.app_dsn, row_factory=dict_row) as conn:
        yield conn


def test_migration_ledger_is_idempotent_and_detects_edits(dbinfo, tmp_path):
    assert migrate.apply(dbinfo.migrator_dsn) == []
    copy = tmp_path / "migrations"
    shutil.copytree(migrate.MIGRATIONS_DIR, copy)
    target = copy / "0002_cases.sql"
    target.write_text(target.read_text() + "\n-- edited after apply\n")
    with pytest.raises(migrate.MigrationError, match="checksum mismatch"):
        migrate.apply(dbinfo.migrator_dsn, directory=copy)


def test_runtime_role_self_check(dbinfo, db):
    db.verify_runtime_role()   # axiom_app passes
    unsafe = Database(dbinfo.migrator_dsn, min_size=1, max_size=1, name="unsafe")
    unsafe.open()
    try:
        with pytest.raises(ConfigurationError, match="axiom_owner"):
            unsafe.verify_runtime_role()
    finally:
        unsafe.close()


def test_no_context_sees_nothing(world, run, ctx_for, raw):
    run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="exists"))
    with raw.transaction():
        for table in TENANT_TABLES + ["tenants", "principals"]:
            count = raw.execute(f"SELECT count(*) AS n FROM axiom.{table}").fetchone()["n"]
            assert count == 0, f"{table} leaked {count} rows without context"


def test_context_limits_rows_and_writes(world, run, ctx_for, raw):
    run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="a"))
    run(ctx_for("analyst_b", "b"), lambda s: s.cases.create(scope_id=world.b.project, title="b"))
    with raw.transaction():
        bound(raw, world.a.id, world["analyst"])
        tenants = {r["tenant_id"] for r in raw.execute("SELECT tenant_id FROM axiom.finding_cases")}
        assert tenants == {world.a.id}
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with raw.transaction():
                raw.execute("INSERT INTO axiom.scopes(tenant_id, id, kind, parent_id, name) VALUES (%s, %s,"
                            " 'project', %s, 'x')", (world.b.id, uuid.uuid4(), world.b.root))


def test_cross_tenant_foreign_key_rejected(world, raw):
    with raw.transaction():
        bound(raw, world.a.id, world["analyst"])
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            raw.execute("""INSERT INTO axiom.finding_cases(tenant_id, id, scope_id, title, workflow, assessment,
                           priority, disposition, record_version) VALUES (%s, %s, %s, 'x', 'received',
                           'unassessed', 'pending', 'unset', 0)""", (world.a.id, uuid.uuid4(), world.b.project))


def test_cannot_switch_tenant_inside_transaction(world, raw):
    with raw.transaction():
        bound(raw, world.a.id, world["consultant"])
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="already bound"):
            bound(raw, world.b.id, world["consultant"])


def test_session_level_context_does_not_leak_into_next_transaction(world, raw):
    with raw.transaction():
        marker = raw.execute("SELECT axiom.tx_marker() AS m").fetchone()["m"]
        # Simulate a bug: session-level (is_local=false) setting with this transaction's marker.
        raw.execute("SELECT set_config('axiom.ctx', %s, false)", (f"{world.a.id}|{world['analyst']}|{marker}",))
        assert raw.execute("SELECT count(*) AS n FROM axiom.scopes").fetchone()["n"] > 0
    with raw.transaction():
        assert raw.execute("SELECT current_setting('axiom.ctx', true) AS v").fetchone()["v"]   # still set...
        assert raw.execute("SELECT count(*) AS n FROM axiom.scopes").fetchone()["n"] == 0      # ...but ignored


def test_pool_reuse_rollback_and_tenant_switching(world, dbinfo):
    db = Database(dbinfo.app_dsn, min_size=1, max_size=1, name="single")
    db.open()
    try:
        a = TenantContext(world.a.id, world["consultant"], "human", "t")
        b = TenantContext(world.b.id, world["consultant"], "human", "t")
        pids = set()
        with db.tenant_tx(a) as conn:
            pids.add(conn.info.backend_pid)
            assert {r["tenant_id"] for r in conn.execute("SELECT tenant_id FROM axiom.scopes")} == {world.a.id}
            conn.execute("SELECT set_config('axiom.ctx', current_setting('axiom.ctx'), false)")  # buggy session set
        with db.unbound_tx() as conn:
            pids.add(conn.info.backend_pid)
            assert conn.execute("SELECT count(*) AS n FROM axiom.scopes").fetchone()["n"] == 0
            assert conn.execute("SELECT current_setting('axiom.ctx', true) AS v").fetchone()["v"] in (None, "")
        with pytest.raises(RuntimeError):
            with db.tenant_tx(b) as conn:
                pids.add(conn.info.backend_pid)
                raise RuntimeError("request failed mid-transaction")
        with db.unbound_tx() as conn:
            assert conn.execute("SELECT count(*) AS n FROM axiom.scopes").fetchone()["n"] == 0
        with db.tenant_tx(b) as conn:
            assert {r["tenant_id"] for r in conn.execute("SELECT tenant_id FROM axiom.scopes")} == {world.b.id}
        assert len(pids) == 1, "test must exercise a single reused connection"
    finally:
        db.close()


def test_suspended_tenant_is_inaccessible(world, dbinfo, db, issuer):
    from axiom.auth import Actor, Authenticator, TokenVerifier
    from axiom.config import TrustedIssuer
    from axiom.provisioning import Provisioner
    Provisioner(dbinfo.admin_cli_dsn).set_tenant_status(world.b.id, "suspended")
    with db.tenant_tx(TenantContext(world.b.id, world["analyst_b"], "human", "t")) as conn:
        assert conn.execute("SELECT count(*) AS n FROM axiom.scopes").fetchone()["n"] == 0
    auth = Authenticator(db, TokenVerifier([TrustedIssuer(issuer=issuer.issuer, audience=issuer.audience,
                                                          jwks=issuer.jwks())]))
    actor = Actor(world["analyst_b"], "human", issuer.issuer, "x")
    with pytest.raises(Forbidden):
        auth.select_tenant(actor, world.b.slug, "t")


def test_runtime_cannot_read_identity_tables_directly(world, raw):
    with raw.transaction():
        bound(raw, world.a.id, world["admin"])
        for table in ("identity_providers", "federated_identities", "installation_role_bindings"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with raw.transaction():
                    raw.execute(f"SELECT * FROM axiom.{table}")
        principals = {r["id"] for r in raw.execute("SELECT id FROM axiom.principals")}
        assert world["analyst_b"] not in principals and world["analyst"] in principals


def test_provisioner_cannot_read_case_or_evidence_data(world, dbinfo):
    with psycopg.connect(dbinfo.admin_cli_dsn) as conn:
        for table in ("finding_cases", "evidence_objects", "audit_events", "decisions", "case_events"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute(f"SELECT * FROM axiom.{table}")


def test_relay_reads_only_outbox(world, run, ctx_for, dbinfo):
    run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="a"))
    with psycopg.connect(dbinfo.relay_dsn) as conn:
        assert conn.execute("SELECT count(*) FROM axiom.outbox").fetchone()[0] > 0
        for table in ("finding_cases", "evidence_objects", "tenants", "audit_events"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute(f"SELECT * FROM axiom.{table}")


def test_append_only_tables_reject_mutation_even_for_owner(world, run, ctx_for, dbinfo):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="a"))
    run(ctx_for("analyst"), lambda s: s.cases.start_investigation(case["id"], 0, "triage"))      # one decision row
    with psycopg.connect(dbinfo.app_dsn) as conn:
        with conn.transaction():
            bound(conn, world.a.id, world["analyst"])
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute("UPDATE axiom.audit_events SET action = 'tampered'")
    with psycopg.connect(dbinfo.admin_dsn) as conn:   # superuser bypasses RLS but not triggers
        for table in ("audit_events", "case_events", "decisions"):
            for stmt in (f"UPDATE axiom.{table} SET tenant_id = tenant_id", f"DELETE FROM axiom.{table}"):
                with pytest.raises(psycopg.errors.InsufficientPrivilege, match="append-only"):
                    with conn.transaction():
                        conn.execute(stmt)


def test_direct_sql_cannot_bypass_case_commands(world, run, ctx_for, raw):
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="a"))
    with pytest.raises(psycopg.errors.CheckViolation, match="not allowed"):
        with raw.transaction():
            bound(raw, world.a.id, world["analyst"])
            raw.execute("UPDATE axiom.finding_cases SET workflow = 'closed', record_version = 1 WHERE id = %s",
                        (case["id"],))
    # Allowed edge, but no event/audit: rejected at commit by the deferred guard.
    with pytest.raises(psycopg.errors.CheckViolation, match="no case event"):
        with raw.transaction():
            bound(raw, world.a.id, world["analyst"])
            raw.execute("UPDATE axiom.finding_cases SET workflow = 'investigating', record_version = 1 WHERE id = %s",
                        (case["id"],))
    with pytest.raises(psycopg.errors.CheckViolation, match="created as received"):
        with raw.transaction():
            bound(raw, world.a.id, world["analyst"])
            raw.execute("""INSERT INTO axiom.finding_cases(tenant_id, id, scope_id, title, workflow, assessment, priority,
                           disposition, record_version) VALUES (%s, %s, %s, 'x', 'closed', 'unassessed', 'pending',
                           'unset', 0)""", (world.a.id, uuid.uuid4(), world.a.project))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with raw.transaction():
            bound(raw, world.a.id, world["analyst"])
            raw.execute("DELETE FROM axiom.finding_cases WHERE id = %s", (case["id"],))


def test_closure_without_valid_record_fails_at_commit(world, run, ctx_for, raw):
    """Even with an event and audit row, closing from review needs a valid reason-specific record."""
    case = run(ctx_for("analyst"), lambda s: s.cases.create(scope_id=world.a.project, title="a"))
    run(ctx_for("analyst"), lambda s: s.cases.start_investigation(case["id"], 0, "go"))
    run(ctx_for("analyst"), lambda s: s.cases.escalate(case["id"], 1, "unsure"))
    with pytest.raises(psycopg.errors.CheckViolation, match="closure requires a closure record"):
        with raw.transaction():
            bound(raw, world.a.id, world["analyst"])
            audit_id = uuid.uuid4()
            raw.execute("""INSERT INTO axiom.audit_events(tenant_id, id, actor_principal_id, actor_kind, correlation_id,
                           action, resource_type, outcome) VALUES (%s, %s, %s, 'human', 'x', 'forge', 'case',
                           'committed')""", (world.a.id, audit_id, world["analyst"]))
            raw.execute("UPDATE axiom.finding_cases SET workflow = 'closed', record_version = 3 WHERE id = %s",
                        (case["id"],))
            raw.execute("""INSERT INTO axiom.case_events(tenant_id, id, case_id, sequence, event_type, from_workflow,
                           to_workflow, actor_principal_id, audit_event_id, correlation_id) VALUES
                           (%s, %s, %s, 3, 'forged', 'review_required', 'closed', %s, %s, 'x')""",
                        (world.a.id, uuid.uuid4(), case["id"], world["analyst"], audit_id))


def test_tenant_selection_and_security_events(world, db, issuer, admin_conn):
    from axiom.auth import Authenticator, TokenVerifier
    from axiom.config import TrustedIssuer
    auth = Authenticator(db, TokenVerifier([TrustedIssuer(issuer=issuer.issuer, audience=issuer.audience,
                                                          jwks=issuer.jwks())]))
    consultant = auth.authenticate(issuer.token(world.subjects["consultant"]))
    assert {t["slug"] for t in auth.list_tenants(consultant)} == {world.a.slug, world.b.slug}
    assert auth.select_tenant(consultant, world.b.slug, "c1").tenant_id == world.b.id
    analyst = auth.authenticate(issuer.token(world.subjects["analyst"]))
    with pytest.raises(Forbidden) as err:
        auth.select_tenant(analyst, world.b.slug, "c2")
    nonexistent = None
    with pytest.raises(Forbidden) as err2:
        auth.select_tenant(analyst, "does-not-exist", "c3")
    assert err.value.message == err2.value.message   # no existence oracle
    operator = auth.authenticate(issuer.token(world.subjects["operator"]))
    assert auth.installation_roles(operator) == ["installation_operator"]
    with pytest.raises(Forbidden):
        auth.select_tenant(operator, world.a.slug, "c4")   # operators get no routine tenant access
    events = admin_conn.execute(
        "SELECT correlation_id FROM axiom.security_events WHERE correlation_id IN ('c2','c3','c4')").fetchall()
    assert len(events) == 3 and nonexistent is None
    with pytest.raises(Unauthenticated):
        auth.authenticate(issuer.token("never-provisioned"))
