"""Inbound ticket sync, SLA timers, report snapshots and exports (Phase D)."""
from __future__ import annotations

import json

import psycopg
import pytest

from axiom.access import Authorizer, PermissionDenied
from axiom.domains.actions.sync import TicketSyncHandler
from axiom.domains.reports.service import ReportService
from axiom.errors import Conflict
from axiom.jobs import Worker, enqueue

from .test_actions import FAST, Env, env  # noqa: F401 - fixture

pytestmark = pytest.mark.db


def created_ticket(env, admin_conn):
    p = env.propose()
    e = env.execute(p, env.approve(p))
    assert env.drive(admin_conn, e["job_id"])["state"] == "succeeded"
    return e


def sync_once(env):
    sys = env.ctx_for("system")
    with env.db.tenant_tx(sys) as conn:
        job = enqueue(conn, sys, kind="actions.ticket_sync", version=1, payload={})
    Worker(env.db, [TicketSyncHandler(env.adapter)], config=FAST).run_once(only_tenants={env.world.a.id})
    with env.db.tenant_tx(sys) as conn:
        return conn.execute("SELECT state, result FROM axiom.jobs WHERE id = %s", (job["id"],)).fetchone()


def states(env):
    with env.db.tenant_tx(env.ctx_for("analyst")) as conn:
        return [(r["status"], r["status_category"]) for r in conn.execute(
            "SELECT status, status_category FROM axiom.external_ticket_states ORDER BY observed_at, id")]


# ------------------------------------------------------------------------------------------- ticket sync
def test_external_ticket_closure_is_recorded_but_never_closes_the_case(env, admin_conn):
    created_ticket(env, admin_conn)
    case_before = env.run(env.ctx_for("analyst"), lambda s: s.cases.get(env.case["id"]))
    assert sync_once(env)["result"]["changed"] == 1
    assert sync_once(env)["result"]["changed"] == 0                  # unchanged state is not recorded again
    env.fake.set_status("SEC-1", "Done", "done")
    assert sync_once(env)["result"]["changed"] == 1
    assert states(env) == [("To Do", "open"), ("Done", "done")]
    case_after = env.run(env.ctx_for("analyst"), lambda s: s.cases.get(env.case["id"]))
    assert (case_after["workflow"], case_after["record_version"]) == (case_before["workflow"],
                                                                      case_before["record_version"])
    with env.db.tenant_tx(env.ctx_for("analyst")) as conn:
        topics = [r["topic"] for r in conn.execute("SELECT topic FROM axiom.outbox WHERE topic LIKE 'external_ticket.%%'"
                                                   " AND aggregate_id = %s", (env.case["id"],))]
    assert "external_ticket.done" in topics


def test_deleted_ticket_and_unreachable_provider(env, admin_conn):
    created_ticket(env, admin_conn)
    env.fake.delete("SEC-1")
    sync_once(env)
    assert states(env)[-1] == ("missing", "missing")

    class Down:
        def fetch_state(self, ref):
            raise ConnectionError("tracker unreachable")
    env.adapter = lambda *_: Down()
    result = sync_once(env)["result"]
    assert result["changed"] == 0                                   # missing is terminal, not polled again


def test_sync_errors_do_not_stop_other_references(env, admin_conn):
    created_ticket(env, admin_conn)
    p2 = env.propose({"project_key": "SEC", "summary": "second", "description": "", "labels": []})
    e2 = env.execute(p2, env.approve(p2))
    env.drive(admin_conn, e2["job_id"])
    real = env.adapter

    class Flaky:
        def __init__(self):
            self.inner = real()

        def fetch_state(self, ref):
            if ref == "SEC-1":
                raise TimeoutError("slow")
            return self.inner.fetch_state(ref)
    env.adapter = lambda *_: Flaky()
    result = sync_once(env)["result"]
    assert result["checked"] == 1 and len(result["errors"]) == 1 and result["changed"] == 1


# SLA timers are tested in test_sla_reporting_journey.py (v2 timers, migration 0012).


# ------------------------------------------------------------------------------------------ reports
def report(env, who, fn):
    ctx = env.ctx_for(who)
    with env.db.tenant_tx(ctx) as conn:
        return fn(ReportService(conn, ctx, Authorizer(conn, ctx), env.store))


def test_snapshot_is_immutable_digest_checked_and_separates_outcomes(env, admin_conn, object_store, world):
    env.store = object_store
    created_ticket(env, admin_conn)
    sync_once(env)
    snap = report(env, "analyst", lambda r: r.generate(kind="exposure_summary", scope_id=world.a.project))
    c = snap["content"]
    assert c["denominators"]["cases"]["total"] >= 1 and c["open_by_workflow"]["received"] >= 1
    assert c["external_tickets"] == {"open": 1}
    assert set(c) >= {"closed_by_reason", "accepted_exposure", "sla", "unknowns", "coverage_by_source"}
    again = report(env, "auditor", lambda r: r.get(snap["id"]))
    assert again["content_digest"] == snap["content_digest"]
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with env.db.tenant_tx(env.ctx_for("analyst")) as conn:
            conn.execute("UPDATE axiom.report_snapshots SET content = '{}' WHERE id = %s", (snap["id"],))
    # tampering below the application (superuser, triggers off) is detected on read
    admin_conn.execute("SET session_replication_role = replica")
    admin_conn.execute("UPDATE axiom.report_snapshots SET content = jsonb_set(content, '{query_version}', '\"forged\"') "
                       "WHERE id = %s", (snap["id"],))
    admin_conn.execute("SET session_replication_role = origin")
    with pytest.raises(Conflict) as err:
        report(env, "auditor", lambda r: r.get(snap["id"]))
    assert err.value.code == "report_integrity"


def test_exports_need_their_permission_and_are_verified_on_read(env, admin_conn, object_store, world):
    env.store = object_store
    snap = report(env, "analyst", lambda r: r.generate(kind="exposure_summary", scope_id=world.a.project))
    with pytest.raises(PermissionDenied):
        report(env, "analyst", lambda r: r.export(snap["id"], "json"))
    ex_json = report(env, "auditor", lambda r: r.export(snap["id"], "json"))
    ex_csv = report(env, "auditor", lambda r: r.export(snap["id"], "csv"))
    row, data = report(env, "auditor", lambda r: r.read_export(ex_json["id"]))
    doc = json.loads(data)
    assert doc["snapshot"]["content_digest"] == snap["content_digest"] and doc["content"] == snap["content"]
    _, csv_data = report(env, "auditor", lambda r: r.read_export(ex_csv["id"]))
    assert csv_data.decode().splitlines()[0] == "section,key,value" and "denominators" in csv_data.decode()
    # tamper with the stored object: read refuses
    key = ex_json["object_key"]
    path = object_store.root / key if hasattr(object_store, "root") else None
    if path is None:
        pytest.skip("object store has no filesystem root")
    path.write_bytes(data.replace(b'"denominators"', b'"denominatorZ"'))
    with pytest.raises(Conflict) as err:
        report(env, "auditor", lambda r: r.read_export(ex_json["id"]))
    assert err.value.code == "export_integrity"


def test_reports_are_scoped(env, world):
    from axiom.errors import NotFound
    env.store = None
    snap = report(env, "analyst", lambda r: r.generate(kind="exposure_summary", scope_id=world.a.project))
    with pytest.raises(PermissionDenied):
        report(env, "marketing_analyst", lambda r: r.generate(kind="exposure_summary", scope_id=world.a.project))
    with pytest.raises(NotFound):
        report(env, "marketing_analyst", lambda r: r.get(snap["id"]))
    b = env.ctx_for("analyst_b", "b")
    with env.db.tenant_tx(b) as conn:
        with pytest.raises(NotFound):
            ReportService(conn, b, Authorizer(conn, b), None).get(snap["id"])
