"""Durable job runner (ADR 0006): leases, fencing, step deadlines, poison claims, versions, effects, restore.

Crash tests use real SIGKILL of a separate process. The external system is a file-backed fake
(tests/integration/jobs_support.py); results say nothing about any real ticketing product.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

from axiom.access import Authorizer, PermissionDenied
from axiom.jobs import (Done, Fail, JobOperations, NeedsOperator, RestoreNotAcknowledged, Retry, Wait, Worker,
                           WorkerConfig, enqueue)
from axiom.errors import ValidationFailed

from .jobs_support import FileTickets, ScriptedHandler, TicketHandler

pytestmark = pytest.mark.db
HERE = Path(__file__).resolve().parent
FAST = WorkerConfig(lease_seconds=1.0, step_timeout_seconds=2.0, per_tenant_running_limit=10, batch_per_tenant=10,
                    max_backoff_seconds=0.01)


def put(db, ctx, kind="test.ticket", payload=None, **kw):
    with db.tenant_tx(ctx) as conn:
        return enqueue(conn, ctx, kind=kind, version=kw.pop("version", 1), payload=payload or {"title": "t"}, **kw)


def job(db, ctx, job_id):
    with db.tenant_tx(ctx) as conn:
        return conn.execute("SELECT * FROM axiom.jobs WHERE id = %s", (job_id,)).fetchone()


def events(db, ctx, job_id):
    with db.tenant_tx(ctx) as conn:
        return [r["event"] for r in conn.execute(
            "SELECT event FROM axiom.job_events WHERE job_id = %s ORDER BY created_at, id", (job_id,))]


def make_due(admin_conn, job_id):
    """Fault injection: skip the backoff wait without waiting in real time."""
    admin_conn.execute("UPDATE axiom.jobs SET due_at = clock_timestamp(), record_version = record_version + 1 "
                       "WHERE id = %s", (job_id,))


def drive(worker, tenant, admin_conn, job_id, db, ctx, *, max_passes=10):
    for _ in range(max_passes):
        row = job(db, ctx, job_id)
        if row["state"] not in ("queued", "waiting", "running"):
            return row
        make_due(admin_conn, job_id)
        worker.run_once(only_tenants={tenant})
    return job(db, ctx, job_id)


@pytest.fixture()
def sys_ctx(ctx_for):
    return ctx_for("system")


@pytest.fixture()
def ops(db, world, ctx_for, dbinfo):
    from axiom.provisioning import Provisioner
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["admin"], "policy_admin", world.a.root,
                                                     "operate jobs in tests")

    def _ops(name="admin", fn=None):
        ctx = ctx_for(name)
        with db.tenant_tx(ctx) as conn:
            return fn(JobOperations(conn, ctx, Authorizer(conn, ctx)))
    return _ops


# ----------------------------------------------------------------------------------------------- basics
def test_runtime_can_read_fingerprint_and_it_is_acknowledged(db, world, sys_ctx):
    worker = Worker(db, [])
    fp = worker.preflight()
    assert fp.count(":") == 2


def test_enqueue_dedupe_returns_existing_job(db, sys_ctx):
    a = put(db, sys_ctx, dedupe_key="sweep:2026-10-22")
    b = put(db, sys_ctx, dedupe_key="sweep:2026-10-22")
    assert a["id"] == b["id"]
    assert events(db, sys_ctx, a["id"]).count("enqueued") == 1


def test_payloads_carry_identifiers_only(db, sys_ctx):
    with pytest.raises(ValidationFailed):
        put(db, sys_ctx, payload={"title": "x" * 600})


def test_wait_then_done(db, world, sys_ctx, admin_conn):
    later = datetime.now(timezone.utc) + timedelta(hours=1)
    h = ScriptedHandler([Wait(later, "waiting for approval"), Done({"ok": True})])
    j = put(db, sys_ctx, kind="test.scripted")
    w = Worker(db, [h], config=FAST)
    w.run_once(only_tenants={world.a.id})
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "waiting" and row["wait_reason"] == "waiting for approval"
    assert w.run_once(only_tenants={world.a.id}) == 0          # not due yet
    make_due(admin_conn, j["id"])
    w.run_once(only_tenants={world.a.id})
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "succeeded" and row["result"] == {"ok": True}


def test_retry_backs_off_then_dead_letters_at_max_attempts(db, world, sys_ctx, admin_conn):
    h = ScriptedHandler([Retry("boom")] * 10)
    j = put(db, sys_ctx, kind="test.scripted", max_attempts=3)
    w = Worker(db, [h], config=WorkerConfig(max_backoff_seconds=60))
    w.run_once(only_tenants={world.a.id})
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "queued" and row["due_at"] > datetime.now(timezone.utc)   # backed off
    row = drive(w, world.a.id, admin_conn, j["id"], db, sys_ctx)
    assert row["state"] == "dead_lettered" and row["attempts"] == 3 and h.calls == 3
    assert "boom" in row["last_error"]


def test_handler_exception_is_retried_not_lost(db, world, sys_ctx, admin_conn):
    def explode(jc):
        raise RuntimeError("bug")
    h = ScriptedHandler([explode, Done({"second": True})])
    j = put(db, sys_ctx, kind="test.scripted")
    row = drive(Worker(db, [h], config=FAST), world.a.id, admin_conn, j["id"], db, sys_ctx)
    assert row["state"] == "succeeded" and row["attempts"] == 2


def test_finished_jobs_are_immutable(db, world, sys_ctx):
    j = put(db, sys_ctx, kind="test.scripted")
    Worker(db, [ScriptedHandler([Done()])], config=FAST).run_once(only_tenants={world.a.id})
    with pytest.raises(psycopg.errors.CheckViolation):
        with db.tenant_tx(sys_ctx) as conn:
            conn.execute("UPDATE axiom.jobs SET state = 'queued', finished_at = NULL, record_version = record_version + 1 "
                         "WHERE id = %s", (j["id"],))


# ---------------------------------------------------------------------------- poison, deadlines, fences
def test_poison_job_dead_letters_after_max_claims_even_if_handler_never_runs(db, world, sys_ctx, admin_conn):
    j = put(db, sys_ctx, kind="test.scripted", max_claims=3)
    w = Worker(db, [ScriptedHandler([])], config=FAST)
    for _ in range(4):
        claimed = w.claim(sys_ctx)          # claim, then "crash" before executing: never call execute
        admin_conn.execute("UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 second', "
                           "record_version = record_version + 1 WHERE id = %s AND state = 'running'", (j["id"],))
        if not claimed:
            break
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "dead_lettered" and row["claims"] == 4 and row["attempts"] == 0
    assert "poison" in row["last_error"]
    assert "dead_lettered_poison" in events(db, sys_ctx, j["id"])


def test_hung_step_loses_lease_at_deadline_and_its_late_result_is_fenced_out(db, world, sys_ctx):
    release = threading.Event()

    def hang(jc):
        release.wait(20)
        return Done({"by": "hung worker"})
    cfg = WorkerConfig(lease_seconds=0.6, step_timeout_seconds=1.2, per_tenant_running_limit=10)
    slow = Worker(db, [ScriptedHandler([hang])], worker_id="slow", config=cfg)
    fast = Worker(db, [ScriptedHandler([Done({"by": "second worker"})])], worker_id="fast", config=cfg)
    j = put(db, sys_ctx, kind="test.scripted")
    [(claimed, token)] = slow.claim(sys_ctx)
    t = threading.Thread(target=slow.execute, args=(sys_ctx, claimed, token))
    t.start()
    time.sleep(0.9)
    row = job(db, sys_ctx, j["id"])
    assert row["lease_expires_at"] <= row["step_deadline_at"]      # heartbeat never extends past the deadline
    assert fast.run_once(only_tenants={world.a.id}) == 0             # still leased (heartbeat ran)
    time.sleep(0.6)                                                  # past the 1.2s step deadline
    assert fast.run_once(only_tenants={world.a.id}) == 1
    release.set()
    t.join(10)
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "succeeded" and row["result"] == {"by": "second worker"}
    ev = events(db, sys_ctx, j["id"])
    assert "stale_result_discarded" in ev


def expire_lease_now(admin_conn, job_id, *, cancel=False):
    """Fault injection with the database clock: the lease and the step deadline end before the handler returns, and
    no other worker has reclaimed the job. The deadline is moved too, so no heartbeat can extend the lease again."""
    admin_conn.execute(
        """UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 second',
                  step_deadline_at = clock_timestamp() - interval '1 second', cancel_requested = cancel_requested OR %s,
                  record_version = record_version + 1 WHERE id = %s""", (cancel, job_id))


OUTCOMES = {
    "done": Done({"by": "expired worker"}),
    "fail": Fail("failed by expired worker"),
    "retry": Retry("retry from expired worker"),
    "wait": Wait(datetime(2099, 1, 1, tzinfo=timezone.utc), "wait from expired worker"),
    "needs_operator": NeedsOperator("operator from expired worker"),
}


@pytest.mark.parametrize("cancel", [False, True], ids=["plain", "cancel-requested"])
@pytest.mark.parametrize("name", list(OUTCOMES))
def test_result_returned_after_the_lease_expired_is_discarded_and_the_job_stays_reclaimable(
        db, world, sys_ctx, admin_conn, name, cancel):
    """The interval the late-worker test above does not cover: the lease has expired but nobody has reclaimed the job
    yet when the original handler returns. The expired worker no longer holds the lease (JobContext.fenced and claim
    both say so), so its outcome must not be written, and the job must stay claimable."""
    cfg = WorkerConfig(lease_seconds=60, step_timeout_seconds=120, per_tenant_running_limit=10)
    j = put(db, sys_ctx, kind="test.scripted")

    def expire_then_return(jc):
        expire_lease_now(admin_conn, j["id"], cancel=cancel)
        return OUTCOMES[name]
    first = Worker(db, [ScriptedHandler([expire_then_return])], worker_id="expired", config=cfg)
    [(claimed, token)] = first.claim(sys_ctx)
    first.execute(sys_ctx, claimed, token)

    row = job(db, sys_ctx, j["id"])
    assert (row["state"], row["lease_token"], row["result"], row["last_error"], row["finished_at"]) == \
        ("running", token, None, None, None), "the expired worker's outcome was written"
    assert row["lease_expires_at"] < datetime.now(timezone.utc)
    assert events(db, sys_ctx, j["id"])[-1] == "stale_result_discarded"
    assert first.counters["stale_results_discarded"] == 1

    second = Worker(db, [ScriptedHandler([Done({"by": "second worker"})])], worker_id="second", config=cfg)
    reclaimed = second.claim(sys_ctx)
    row = job(db, sys_ctx, j["id"])
    if cancel:   # a cancellation requested meanwhile is applied by the claim, not by the expired worker
        assert reclaimed == [] and row["state"] == "cancelled" and row["lease_token"] == token
        return
    [(again, token2)] = reclaimed
    assert token2 == token + 1 and again["lease_owner"] == "second"
    second.execute(sys_ctx, again, token2)
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "succeeded" and row["result"] == {"by": "second worker"}


def test_a_worker_whose_lease_is_still_valid_finishes_normally(db, world, sys_ctx):
    cfg = WorkerConfig(lease_seconds=60, step_timeout_seconds=120, per_tenant_running_limit=10)
    j = put(db, sys_ctx, kind="test.scripted")
    w = Worker(db, [ScriptedHandler([Done({"by": "valid worker"})])], worker_id="valid", config=cfg)
    [(claimed, token)] = w.claim(sys_ctx)
    w.execute(sys_ctx, claimed, token)
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "succeeded" and row["result"] == {"by": "valid worker"} and row["lease_token"] == token
    assert "stale_result_discarded" not in events(db, sys_ctx, j["id"])


def wait_until(admin_conn, sql, args, *, limit=15.0):
    """Coordination on database state, not on elapsed time: poll a condition until it holds. The limit only turns a
    hang into a failure; it never decides the outcome."""
    give_up = time.monotonic() + limit
    while time.monotonic() < give_up:
        row = admin_conn.execute(sql, args).fetchone()
        if row and row["ok"]:
            return
        time.sleep(0.02)
    raise AssertionError(f"condition never held: {sql}")


def test_running_heartbeat_does_not_revive_an_expired_lease_for_the_final_write(db, world, sys_ctx, admin_conn):
    """End to end, with the worker's own heartbeat thread: the lease expires while the step deadline is still ahead
    and nobody has reclaimed the job. The handler then waits until the heartbeat has acted, either by renewing the lease
    (revival) or by reporting the loss, and returns. A revived lease would pass the final write's check."""
    cfg = WorkerConfig(lease_seconds=0.6, step_timeout_seconds=60, per_tenant_running_limit=10)   # beat every 0.2 s
    j = put(db, sys_ctx, kind="test.scripted")
    seen = {}

    def expire_then_wait_for_the_heartbeat(jc):
        admin_conn.execute("UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 second', "
                           "record_version = record_version + 1 WHERE id = %s", (j["id"],))
        wait_until(admin_conn,
                   """SELECT j.lease_expires_at > clock_timestamp()
                             OR EXISTS (SELECT 1 FROM axiom.job_events e WHERE e.job_id = j.id
                                        AND e.event = 'heartbeat_lease_lost') AS ok
                        FROM axiom.jobs j WHERE j.id = %s""", (j["id"],))
        seen["revived"] = admin_conn.execute("SELECT lease_expires_at > clock_timestamp() AS r FROM axiom.jobs "
                                             "WHERE id = %s", (j["id"],)).fetchone()["r"]
        return Done({"by": "worker whose lease had expired"})
    w = Worker(db, [ScriptedHandler([expire_then_wait_for_the_heartbeat])], worker_id="late", config=cfg)
    [(claimed, token)] = w.claim(sys_ctx)
    w.execute(sys_ctx, claimed, token)

    assert seen["revived"] is False, "the heartbeat renewed a lease that had already expired"
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "running" and row["result"] is None, "the revived worker's outcome was written"
    ev = events(db, sys_ctx, j["id"])
    assert "heartbeat_lease_lost" in ev and ev[-1] == "stale_result_discarded"
    [(again, token2)] = Worker(db, [ScriptedHandler([])], worker_id="second", config=cfg).claim(sys_ctx)
    assert token2 == token + 1


@pytest.mark.parametrize("op", ["finish", "renew"])
@pytest.mark.parametrize("blocker_updates", [False, True], ids=["blocker-only-locks", "blocker-updates-row"])
def test_lease_that_expires_while_waiting_for_the_row_lock_is_not_accepted(
        db, world, sys_ctx, admin_conn, dbinfo, blocker_updates, op):
    """PostgreSQL (READ COMMITTED) evaluates a locking query's WHERE clause before it waits for a row lock. If the
    transaction it waited for changed the row, the clause is evaluated again on the new row version; if that
    transaction only locked the row, the earlier evaluation stands. So the lease is tested after the lock is held
    (lock_held_lease). Here the lease is valid when the final write, or a heartbeat, starts waiting; it expires during
    the wait; then the blocking transaction ends."""
    cfg = WorkerConfig(lease_seconds=60, step_timeout_seconds=120, per_tenant_running_limit=10)
    j = put(db, sys_ctx, kind="test.scripted")
    w = Worker(db, [ScriptedHandler([])], worker_id="waiting", config=cfg)
    [(claimed, token)] = w.claim(sys_ctx)
    admin_conn.execute("UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() + interval '2 seconds', "
                       "record_version = record_version + 1 WHERE id = %s", (j["id"],))
    blocker = psycopg.connect(dbinfo.admin_dsn, row_factory=dict_row)
    try:
        blocker.execute("SELECT id FROM axiom.jobs WHERE id = %s FOR UPDATE", (j["id"],))
        target = (w._finish, (sys_ctx, claimed, token, Done({"by": "waited"}))) if op == "finish" else \
            (w._renew, (sys_ctx, j["id"], token))
        t = threading.Thread(target=target[0], args=target[1])
        t.start()
        wait_until(admin_conn, """SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                                     WHERE %s = ANY(pg_blocking_pids(pid))) AS ok""", (blocker.info.backend_pid,))
        still_valid = admin_conn.execute("SELECT lease_expires_at > clock_timestamp() AS v FROM axiom.jobs "
                                         "WHERE id = %s", (j["id"],)).fetchone()["v"]
        assert still_valid, "precondition: the final write must start waiting while the lease is still valid"
        wait_until(admin_conn, "SELECT lease_expires_at <= clock_timestamp() AS ok FROM axiom.jobs WHERE id = %s",
                   (j["id"],))
        if blocker_updates:
            blocker.execute("UPDATE axiom.jobs SET record_version = record_version + 1 WHERE id = %s", (j["id"],))
        blocker.commit()
        t.join(15)
        assert not t.is_alive()
    finally:
        blocker.close()
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "running" and row["result"] is None, \
        f"an outcome was accepted although the lease expired before the row lock was acquired: {row['state']}"
    assert row["lease_expires_at"] <= datetime.now(timezone.utc), "the heartbeat renewed an expired lease"
    assert events(db, sys_ctx, j["id"])[-1] == ("stale_result_discarded" if op == "finish" else "heartbeat_lease_lost")


def lease_row(admin_conn, job_id):
    return admin_conn.execute("SELECT lease_token, lease_owner, lease_expires_at, step_deadline_at, state, "
                              "clock_timestamp() AS now FROM axiom.jobs WHERE id = %s", (job_id,)).fetchone()


def last_event(db, ctx, job_id):
    with db.tenant_tx(ctx) as conn:
        return conn.execute("SELECT event, lease_token, detail FROM axiom.job_events WHERE job_id = %s "
                            "ORDER BY created_at DESC, id DESC LIMIT 1", (job_id,)).fetchone()


HB = WorkerConfig(lease_seconds=30, step_timeout_seconds=120, per_tenant_running_limit=10)


def test_heartbeat_renews_a_lease_that_is_still_held_and_never_past_the_step_deadline(db, world, sys_ctx, admin_conn):
    j = put(db, sys_ctx, kind="test.scripted")
    w = Worker(db, [ScriptedHandler([])], worker_id="holder", config=HB)
    [(_, token)] = w.claim(sys_ctx)
    admin_conn.execute("UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() + interval '5 seconds', "
                       "record_version = record_version + 1 WHERE id = %s", (j["id"],))
    before = lease_row(admin_conn, j["id"])
    assert w._renew(sys_ctx, j["id"], token) is True
    after = lease_row(admin_conn, j["id"])
    assert after["lease_expires_at"] > before["lease_expires_at"] + timedelta(seconds=20)
    assert after["lease_token"] == token and after["lease_owner"] == "holder"
    # the step deadline still caps the lease
    admin_conn.execute("UPDATE axiom.jobs SET step_deadline_at = clock_timestamp() + interval '3 seconds', "
                       "record_version = record_version + 1 WHERE id = %s", (j["id"],))
    assert w._renew(sys_ctx, j["id"], token) is True
    capped = lease_row(admin_conn, j["id"])
    assert capped["lease_expires_at"] == capped["step_deadline_at"]
    assert "heartbeat_lease_lost" not in events(db, sys_ctx, j["id"])


def test_heartbeat_after_expiry_without_reclaim_reports_the_loss_and_does_not_renew(db, world, sys_ctx, admin_conn):
    j = put(db, sys_ctx, kind="test.scripted")
    w = Worker(db, [ScriptedHandler([])], worker_id="late", config=HB)
    [(_, token)] = w.claim(sys_ctx)
    admin_conn.execute("UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 second', "
                       "record_version = record_version + 1 WHERE id = %s", (j["id"],))   # deadline still ahead
    expired_at = lease_row(admin_conn, j["id"])["lease_expires_at"]
    assert w._renew(sys_ctx, j["id"], token) is False
    row = lease_row(admin_conn, j["id"])
    assert row["lease_expires_at"] == expired_at and row["step_deadline_at"] > row["now"]
    ev = last_event(db, sys_ctx, j["id"])
    assert (ev["event"], ev["lease_token"], ev["detail"]) == ("heartbeat_lease_lost", token, {"reason": "lease expired"})
    assert w.counters["heartbeat_lease_lost"] == 1
    [(_, token2)] = Worker(db, [ScriptedHandler([])], worker_id="second", config=HB).claim(sys_ctx)
    assert token2 == token + 1


def test_heartbeat_after_another_worker_reclaimed_the_job_leaves_the_new_lease_alone(db, world, sys_ctx, admin_conn):
    j = put(db, sys_ctx, kind="test.scripted")
    first = Worker(db, [ScriptedHandler([])], worker_id="first", config=HB)
    [(_, token)] = first.claim(sys_ctx)
    admin_conn.execute("UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 second', "
                       "record_version = record_version + 1 WHERE id = %s", (j["id"],))
    [(_, token2)] = Worker(db, [ScriptedHandler([])], worker_id="second", config=HB).claim(sys_ctx)
    reclaimed = lease_row(admin_conn, j["id"])
    assert first._renew(sys_ctx, j["id"], token) is False
    assert lease_row(admin_conn, j["id"])["lease_expires_at"] == reclaimed["lease_expires_at"]
    assert (reclaimed["lease_token"], reclaimed["lease_owner"]) == (token2, "second")
    ev = last_event(db, sys_ctx, j["id"])
    assert (ev["event"], ev["detail"]) == ("heartbeat_lease_lost", {"reason": "reclaimed by a later claim"})


def test_attempted_heartbeat_revival_then_final_write_is_discarded(db, world, sys_ctx, admin_conn):
    j = put(db, sys_ctx, kind="test.scripted")
    w = Worker(db, [ScriptedHandler([])], worker_id="late", config=HB)
    [(claimed, token)] = w.claim(sys_ctx)
    admin_conn.execute("UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 second', "
                       "record_version = record_version + 1 WHERE id = %s", (j["id"],))
    assert w._renew(sys_ctx, j["id"], token) is False, "the heartbeat revived an expired lease"
    w._finish(sys_ctx, claimed, token, Done({"by": "late worker"}))
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "running" and row["result"] is None, "the late worker's outcome was written"
    assert events(db, sys_ctx, j["id"])[-2:] == ["heartbeat_lease_lost", "stale_result_discarded"]


def test_lease_expiry_is_enforced_by_the_worker_not_by_the_database(db, world, sys_ctx, admin_conn):
    """Documents the boundary (ADR 0006 amendment 1). The runtime credential, shared by the API and every worker, may
    update the lease columns, so a database rule on expiry could not stop its holder: it could move the expiry first.
    Leases coordinate workers that share that trusted credential against crashes, hangs and pauses; expiry is checked
    by the worker (lock_held_lease). What the database does enforce stays enforced: the token cannot go back, and a
    finished job cannot change."""
    j = put(db, sys_ctx, kind="test.scripted")
    [(_, token)] = Worker(db, [ScriptedHandler([])], config=HB).claim(sys_ctx)
    admin_conn.execute("UPDATE axiom.jobs SET lease_expires_at = clock_timestamp() - interval '1 second', "
                       "record_version = record_version + 1 WHERE id = %s", (j["id"],))
    with db.tenant_tx(sys_ctx) as conn:      # the runtime credential, writing directly, not through the worker
        n = conn.execute("UPDATE axiom.jobs SET state = 'succeeded', finished_at = clock_timestamp(), "
                         "record_version = record_version + 1 WHERE id = %s AND lease_token = %s",
                         (j["id"], token)).rowcount
    assert n == 1 and job(db, sys_ctx, j["id"])["state"] == "succeeded"
    with pytest.raises(psycopg.errors.CheckViolation, match="finished job is immutable"):
        with db.tenant_tx(sys_ctx) as conn:
            conn.execute("UPDATE axiom.jobs SET state = 'queued', record_version = record_version + 1 "
                         "WHERE id = %s", (j["id"],))


def test_stale_token_cannot_write_even_bypassing_python(db, world, sys_ctx):
    j = put(db, sys_ctx, kind="test.scripted")
    w = Worker(db, [ScriptedHandler([])], config=FAST)
    [(_, token)] = w.claim(sys_ctx)
    with db.tenant_tx(sys_ctx) as conn:
        n = conn.execute("UPDATE axiom.jobs SET state = 'succeeded', finished_at = now(), "
                         "record_version = record_version + 1 WHERE id = %s AND lease_token = %s",
                         (j["id"], token - 1)).rowcount
    assert n == 0
    with pytest.raises(psycopg.errors.CheckViolation):
        with db.tenant_tx(sys_ctx) as conn:
            conn.execute("UPDATE axiom.jobs SET lease_token = lease_token - 1, record_version = record_version + 1 "
                         "WHERE id = %s", (j["id"],))


def test_per_tenant_running_cap(db, world, sys_ctx, ctx_for):
    for _ in range(5):
        put(db, sys_ctx, kind="test.scripted")
    w = Worker(db, [ScriptedHandler([])], config=WorkerConfig(per_tenant_running_limit=2, batch_per_tenant=10))
    first = w.claim(sys_ctx)
    assert len(first) == 2
    assert w.claim(sys_ctx) == []               # cap reached while those leases are live
    other = put(db, ctx_for("system", "b"), kind="test.scripted")
    assert [j["id"] for j, _ in w.claim(ctx_for("system", "b"))] == [other["id"]]   # other tenant unaffected


def test_jobs_are_tenant_isolated(db, world, sys_ctx, ctx_for):
    j = put(db, sys_ctx, kind="test.scripted")
    assert job(db, ctx_for("system", "b"), j["id"]) is None


# -------------------------------------------------------------------------------------- versions & ops
def test_version_pinning_drain_and_explicit_migration(db, world, sys_ctx, ops):
    j = put(db, sys_ctx, kind="test.scripted", version=2)
    v1 = Worker(db, [ScriptedHandler([], versions=frozenset({1}))], config=FAST)
    assert v1.run_once(only_tenants={world.a.id}) == 0
    drain = ops(fn=lambda o: o.drain_status())
    assert any(r["kind"] == "test.scripted" and r["handler_version"] == 2 for r in drain)
    with pytest.raises(PermissionDenied):
        ops("analyst", lambda o: o.migrate_version(j["id"], 1, "no"))
    ops(fn=lambda o: o.migrate_version(j["id"], 1, "v2 handler withdrawn"))
    assert v1.run_once(only_tenants={world.a.id}) == 1
    assert job(db, sys_ctx, j["id"])["state"] == "succeeded"


def test_cancel_queued_and_running(db, world, sys_ctx, ops, tmp_path):
    queued = put(db, sys_ctx, kind="test.scripted")
    ops(fn=lambda o: o.request_cancel(queued["id"], "not needed"))
    assert job(db, sys_ctx, queued["id"])["state"] == "cancelled"

    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=True)
    running = put(db, sys_ctx)

    def cancel_midway(jc):
        ops(fn=lambda o: o.request_cancel(jc.job["id"], "stop it"))
    w = Worker(db, [TicketHandler(tickets, before_effect=cancel_midway)], config=FAST)
    w.run_once(only_tenants={world.a.id})
    assert job(db, sys_ctx, running["id"])["state"] == "cancelled"
    assert tickets.tickets() == []


# ---------------------------------------------------------------------------------------------- effects
def test_effect_once_and_rerun_adopts_recorded_outcome(db, world, sys_ctx, admin_conn, tmp_path):
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=True)
    j = put(db, sys_ctx)
    w = Worker(db, [TicketHandler(tickets)], config=FAST)
    w.run_once(only_tenants={world.a.id})
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "succeeded" and row["result"]["external_ref"] == "TICKET-1"
    assert len(tickets.tickets()) == 1
    assert tickets.lookups == 1                       # lookup ran before create, on the first attempt too


def test_lost_ack_with_lookup_is_adopted_not_repeated(db, world, sys_ctx, admin_conn, tmp_path):
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=True, failures=["lost_ack"])
    j = put(db, sys_ctx)
    w = Worker(db, [TicketHandler(tickets)], config=FAST)
    w.run_once(only_tenants={world.a.id})
    assert job(db, sys_ctx, j["id"])["state"] == "queued"           # retry scheduled; intent unknown
    row = drive(w, world.a.id, admin_conn, j["id"], db, sys_ctx)
    assert row["state"] == "succeeded" and row["result"] == {"external_ref": "TICKET-1", "adopted": True}
    assert len(tickets.tickets()) == 1
    assert "effect_adopted" in events(db, sys_ctx, j["id"])


def test_lost_ack_without_lookup_parks_and_operator_adopts(db, world, sys_ctx, admin_conn, tmp_path, ops):
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=False, failures=["lost_ack"])
    j = put(db, sys_ctx)
    w = Worker(db, [TicketHandler(tickets)], config=FAST)
    w.run_once(only_tenants={world.a.id})
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "needs_operator" and "cannot be queried" in row["operator_reason"]
    assert w.run_once(only_tenants={world.a.id}) == 0               # parked jobs are not retried
    assert [a["id"] for a in ops(fn=lambda o: o.list_attention())].count(j["id"]) == 1
    with pytest.raises(PermissionDenied):
        ops("analyst", lambda o: o.resolve_effect(j["id"], resolution="adopt", rationale="x", external_ref="T"))
    ops(fn=lambda o: o.resolve_effect(j["id"], resolution="adopt", rationale="found TICKET-1 in the tracker",
                                      external_ref="TICKET-1"))
    row = drive(w, world.a.id, admin_conn, j["id"], db, sys_ctx)
    assert row["state"] == "succeeded" and row["result"]["external_ref"] == "TICKET-1"
    assert len(tickets.tickets()) == 1


def test_operator_not_applied_lets_job_retry(db, world, sys_ctx, admin_conn, tmp_path, ops):
    # the fake loses the ack, then the operator (wrongly or rightly) says it was not applied: the platform records
    # that decision and retries; the duplicate is the operator's judgement, visible in the audit trail
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=False, failures=["not_applied", "lost_ack"])
    j = put(db, sys_ctx)
    w = Worker(db, [TicketHandler(tickets)], config=FAST)
    w.run_once(only_tenants={world.a.id})
    assert job(db, sys_ctx, j["id"])["state"] == "queued"            # definitely-not-applied: safe retry
    make_due(admin_conn, j["id"])
    w.run_once(only_tenants={world.a.id})
    assert job(db, sys_ctx, j["id"])["state"] == "needs_operator"
    ops(fn=lambda o: o.resolve_effect(j["id"], resolution="abandon", rationale="ticket exists; will link by hand"))
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "failed" and "abandoned by operator" in row["last_error"]
    assert len(tickets.tickets()) == 1


def test_permanent_failure_fails_without_retry(db, world, sys_ctx, tmp_path):
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=True, failures=["permanent"])
    j = put(db, sys_ctx)
    Worker(db, [TicketHandler(tickets)], config=FAST).run_once(only_tenants={world.a.id})
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "failed" and "invalid project" in row["last_error"]


def test_revoked_authority_is_rechecked_at_the_effect_boundary(db, world, sys_ctx, tmp_path):
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=True)
    revoked = {"now": False}

    def revalidate(conn):
        return "approval revoked" if revoked["now"] else None

    # the first fenced check passes; authority is revoked while the gate looks up the external system
    original_lookup = tickets.lookup

    def lookup_then_revoke(key):
        revoked["now"] = True
        return original_lookup(key)
    tickets.lookup = lookup_then_revoke
    j = put(db, sys_ctx)
    Worker(db, [TicketHandler(tickets, revalidate=revalidate)], config=FAST).run_once(only_tenants={world.a.id})
    row = job(db, sys_ctx, j["id"])
    assert row["state"] == "failed" and "approval revoked" in row["last_error"]
    assert tickets.tickets() == []


def test_intent_rows_are_guarded(db, world, sys_ctx, tmp_path):
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=True)
    j = put(db, sys_ctx)
    Worker(db, [TicketHandler(tickets)], config=FAST).run_once(only_tenants={world.a.id})
    with pytest.raises(psycopg.errors.CheckViolation):
        with db.tenant_tx(sys_ctx) as conn:
            conn.execute("UPDATE axiom.effect_intents SET state = 'prepared', record_version = record_version + 1 "
                         "WHERE job_id = %s", (j["id"],))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.tenant_tx(sys_ctx) as conn:
            conn.execute("DELETE FROM axiom.effect_intents WHERE job_id = %s", (j["id"],))


# ------------------------------------------------------------------------------------------- real kills
def _spawn(dbinfo, world, tickets, lookup, marker):
    return subprocess.Popen([sys.executable, str(HERE / "jobs_child.py"), dbinfo.app_dsn, str(world.a.id),
                             str(tickets), "1" if lookup else "0", str(marker)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def _kill_after_effect(proc, marker):
    deadline = time.time() + 30
    while not marker.exists():
        if proc.poll() is not None:
            raise AssertionError(f"child exited early: {proc.stdout.read().decode()}")
        assert time.time() < deadline, "child never performed the effect"
        time.sleep(0.05)
    os.kill(proc.pid, signal.SIGKILL)
    proc.wait(10)
    assert proc.returncode == -signal.SIGKILL


@pytest.mark.parametrize("lookup", [True, False], ids=["with-lookup", "without-lookup"])
def test_sigkill_after_effect_before_outcome_recorded(db, world, sys_ctx, admin_conn, tmp_path, dbinfo, lookup,
                                                       ops):
    path, marker = tmp_path / "t.jsonl", tmp_path / "effect-done"
    j = put(db, sys_ctx)
    proc = _spawn(dbinfo, world, path, lookup, marker)
    _kill_after_effect(proc, marker)
    with db.tenant_tx(sys_ctx) as conn:
        intent = conn.execute("SELECT state FROM axiom.effect_intents WHERE job_id = %s", (j["id"],)).fetchone()
    assert intent["state"] == "executing"                       # the crash left the outcome unrecorded
    time.sleep(2.2)                                              # lease (1s) and step deadline (2s) lapse
    tickets = FileTickets(path, lookup_supported=lookup)
    Worker(db, [TicketHandler(tickets)], worker_id="survivor", config=FAST).run_once(only_tenants={world.a.id})
    row = job(db, sys_ctx, j["id"])
    if lookup:
        assert row["state"] == "succeeded" and row["result"] == {"external_ref": "TICKET-1", "adopted": True}
    else:
        assert row["state"] == "needs_operator"
    assert len(tickets.tickets()) == 1
    ev = events(db, sys_ctx, j["id"])
    assert ev.count("claimed") == 2


# -------------------------------------------------------------------------------------- restore detection
def test_restore_is_detected_and_no_lookup_effects_park(db, world, sys_ctx, tmp_path, dbinfo, admin_conn):
    """Backup taken while jobs are queued; effects then happen; the backup is restored into a new database.

    A worker must refuse to run until an operator acknowledges the restored fingerprint; after that, lookup
    integrations adopt the existing effect and no-lookup integrations park instead of repeating it.
    """
    from axiom.db import Database
    from axiom.provisioning import Provisioner
    with_lookup = FileTickets(tmp_path / "lookup.jsonl", lookup_supported=True)
    without = FileTickets(tmp_path / "nolookup.jsonl", lookup_supported=False)

    class NoLookupHandler(TicketHandler):
        kind = "test.ticket_nolookup"
    j1 = put(db, sys_ctx)
    j2 = put(db, sys_ctx, kind="test.ticket_nolookup")
    dump = tmp_path / "backup.dump"
    admin = dbinfo.admin_dsn
    params = psycopg.conninfo.conninfo_to_dict(admin)
    env = {**os.environ, "PGHOST": params["host"], "PGPORT": str(params.get("port", 5432)),
           "PGUSER": params["user"]}
    subprocess.run(["pg_dump", "-Fc", "-f", str(dump), "-d", dbinfo.name], check=True, env=env)

    w = Worker(db, [TicketHandler(with_lookup), NoLookupHandler(without)], config=FAST)
    w.run_once(only_tenants={world.a.id})
    assert job(db, sys_ctx, j1["id"])["state"] == "succeeded" and job(db, sys_ctx, j2["id"])["state"] == "succeeded"
    assert len(with_lookup.tickets()) == 1 and len(without.tickets()) == 1

    restored = f"{dbinfo.name}_restored"
    with psycopg.connect(admin.replace(f"dbname={dbinfo.name}", "dbname=postgres"), autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{restored}" OWNER axiom_owner')
        c.execute(f'GRANT CONNECT ON DATABASE "{restored}" TO axiom_migrator, axiom_app, axiom_relay_app, axiom_admin_cli')
    try:
        subprocess.run(["pg_restore", "--exit-on-error", "-d", restored, str(dump)], check=True, env=env)
        rdb = Database(dbinfo.app_dsn.replace(f"dbname={dbinfo.name}", f"dbname={restored}"), min_size=1, max_size=3)
        rdb.open()
        try:
            rw = Worker(rdb, [TicketHandler(with_lookup), NoLookupHandler(without)], config=FAST)
            with pytest.raises(RestoreNotAcknowledged):
                rw.run_once(only_tenants={world.a.id})
            prov = Provisioner(dbinfo.admin_cli_dsn.replace(f"dbname={dbinfo.name}", f"dbname={restored}"))
            status = prov.recovery_status()
            assert status["acknowledged"] is False
            prov.acknowledge_recovery("test-operator", "restore drill: workers stopped, reconciling pending effects")
            rw.run_once(only_tenants={world.a.id})
            r1, r2 = job(rdb, sys_ctx, j1["id"]), job(rdb, sys_ctx, j2["id"])
            assert r1["state"] == "succeeded" and r1["result"] == {"external_ref": "TICKET-1", "adopted": True}
            assert r2["state"] == "needs_operator" and "restore" in r2["operator_reason"]
            assert len(with_lookup.tickets()) == 1 and len(without.tickets()) == 1     # no duplicate effects
        finally:
            rdb.close()
    finally:
        with psycopg.connect(admin.replace(f"dbname={dbinfo.name}", "dbname=postgres"), autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{restored}" WITH (FORCE)')


def test_worker_metrics_endpoint_serves_prometheus_text(db, world, sys_ctx):
    import socket
    import urllib.request

    from axiom.jobs.metrics import serve
    put(db, sys_ctx, kind="test.scripted")
    w = Worker(db, [ScriptedHandler([Done()])], worker_id="metrics-test", config=FAST)
    w.run_once(only_tenants={world.a.id})
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = serve(w, port, host="127.0.0.1")
    try:
        text = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=10).read().decode()
    finally:
        server.shutdown()
    assert f'axiom_jobs{{tenant="{world.a.id}",kind="test.scripted",state="succeeded"}}' in text
    assert 'axiom_worker_total{worker="metrics-test",counter="executed"} 1' in text
    assert "axiom_jobs_oldest_due_seconds" in text
