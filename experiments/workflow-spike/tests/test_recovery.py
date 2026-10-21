"""Q5 (heartbeat timeout, stale worker, fencing), Q6 (cancellation, revocation), Q8 (backup/restore).

Workflow workers and activity workers are separate processes here, so freezing an activity worker
(SIGSTOP) does not also freeze the workflow's sticky cache.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
import uuid
from pathlib import Path

import pytest
from temporalio.client import Client, WorkflowFailureError

from harness import fresh_dir, log, start_ticket_service, tickets, wait_status
from secure_fixtures import sec_server  # noqa: F401  (fixture)
from secure_harness import (
    DevServer, api_approve, copy_sqlite_set, new_action, show_sdb, sigcont, sigstop, start_secure_worker,
)
from spike import secure_db as sdb
from spike.secure_activities import GATE_ENV, HANG_ENV, INTERRUPTIBLE_ENV, MODE_ENV, PAUSE_ENV
from spike.secure_models import SecureInput, SecureOutcome
from spike.secure_workflow import SecureRemediationWorkflow


def run(coro):
    return asyncio.run(coro)


def activity_attempts(history, only_effect: bool = False) -> list[str]:
    """Readable summary of activity (and cancellation) events, with activity type and worker identity."""
    out = []
    types: dict[int, str] = {}
    for e in history.events:
        if e.HasField("activity_task_scheduled_event_attributes"):
            a = e.activity_task_scheduled_event_attributes
            types[e.event_id] = a.activity_type.name
            continue
        for field, label in (("activity_task_started_event_attributes", "Started"),
                             ("activity_task_completed_event_attributes", "Completed"),
                             ("activity_task_failed_event_attributes", "Failed"),
                             ("activity_task_timed_out_event_attributes", "TimedOut"),
                             ("activity_task_canceled_event_attributes", "Canceled")):
            if e.HasField(field):
                a = getattr(e, field)
                name = types.get(a.scheduled_event_id, "?")
                if only_effect and name != "execute_effect":
                    break
                extra = ""
                if label == "Started":
                    lf = a.last_failure.message if a.HasField("last_failure") else ""
                    extra = f" attempt={a.attempt} identity={a.identity} last_failure={lf!r}"
                elif label in ("Completed", "Failed", "Canceled"):
                    extra = f" identity={a.identity}"
                    if label == "Failed":
                        extra += f" msg={a.failure.message!r}"
                elif label == "TimedOut":
                    extra = f" failure={a.failure.message!r}"
                out.append(f"#{e.event_id} {name} {label}{extra}")
                break
        else:
            if e.HasField("activity_task_cancel_requested_event_attributes"):
                out.append(f"#{e.event_id} ActivityTaskCancelRequested")
            elif e.HasField("workflow_execution_cancel_requested_event_attributes"):
                out.append(f"#{e.event_id} WorkflowExecutionCancelRequested")
            elif e.HasField("workflow_execution_canceled_event_attributes"):
                out.append(f"#{e.event_id} WorkflowExecutionCanceled")
    return out


def grep_log(path: Path, *needles: str) -> list[str]:
    lines = path.read_text(errors="replace").splitlines()
    return [ln[:300] for ln in lines if any(n in ln for n in needles)]


# =================================================================================================
# Q5. Stale worker: SIGSTOP an activity worker mid-activity, let the server retry elsewhere,
#     SIGCONT the stale worker after the retry completed.
@pytest.mark.parametrize("variant", ["naive", "platform", "heartbeat_gate"])
def test_q5_stale_worker_sigstop(sec_server, variant):
    async def body():
        d = fresh_dir(f"q5-stale-{variant}")
        pdb = str(d / "platform.db")
        pause = d / "pause-before-effect"
        pause.touch()
        mode = "platform" if variant == "platform" else "naive"
        env = {MODE_ENV: mode, PAUSE_ENV: str(pause)}
        if variant == "heartbeat_gate":
            env[GATE_ENV] = "1"
        ts, url = start_ticket_service(d)
        q = f"q5-{variant}-{uuid.uuid4().hex[:4]}"
        wfw = start_secure_worker(d, sec_server.address, q, "wf-worker", platform_db=pdb, ticket_url=url,
                                  role="workflow")
        a1 = start_secure_worker(d, sec_server.address, q, "act-A", platform_db=pdb, ticket_url=url,
                                 role="activity", env=env)
        c = await Client.connect(sec_server.address)
        a2 = None
        try:
            run_id, dig, wf = new_action(pdb, "tenant-a")
            h = await c.start_workflow(SecureRemediationWorkflow.run, SecureInput("tenant-a", run_id, dig),
                                       id=wf, task_queue=q)
            await wait_status(h, "awaiting_approval")
            await h.signal(SecureRemediationWorkflow.approval_ready, api_approve(pdb, "tenant-a", run_id, dig))
            a1.wait_for_log("PRE-EFFECT attempt=1", 30)
            sigstop(a1)
            t_stop = time.monotonic()
            pause.unlink()  # attempt 2 (on act-B) must not pause
            a2 = start_secure_worker(d, sec_server.address, q, "act-B", platform_db=pdb, ticket_url=url,
                                     role="activity", env=env)
            out: SecureOutcome = await asyncio.wait_for(h.result(), 60)
            t_done = time.monotonic() - t_stop
            log(f"workflow result {t_done:.1f}s after SIGSTOP of act-A: {out}")
            n_before = len(tickets(url))
            log(f"tickets while act-A is still stopped: {n_before}")
            sigcont(a1)
            a1.wait_for_log("ACTIVITY ", 30)  # RETURNING or EXIT
            await asyncio.sleep(4)  # let the SDK try to report the stale completion
            t = tickets(url)
            log(f"tickets after act-A resumed: {len(t)} {[x['id'] for x in t]}")
            log("act-A log (activity and SDK lines):")
            for ln in grep_log(a1.logfile, "PRE-EFFECT", "RESUMED", "GATE", "EFFECT APPLIED", "ACTIVITY", "STALE",
                               "WARN", "ERROR", "not found", "NotFound", "adopt"):
                log(f"    {ln}")
            log("act-B log:")
            for ln in grep_log(a2.logfile, "EFFECT APPLIED", "ACTIVITY", "adopt", "STALE"):
                log(f"    {ln}")
            hist = await h.fetch_history()
            for ln in activity_attempts(hist):
                log(f"    history {ln}")
            show_sdb(pdb, ("execution_intents", "execution_results", "workflow_events"))
            assert out.status == "completed" and n_before == 1
            completed = [ln for ln in activity_attempts(hist, True) if "Completed" in ln]
            assert len(completed) == 1 and "act-B" in completed[0]  # stale completion was not recorded
            starts = [ln for ln in activity_attempts(hist, True) if "Started" in ln]
            log(f"execute_effect attempts recorded by the server: {len(starts)}")
            if variant == "naive":
                # >= 2: the stale attempt 1 creates a ticket on resume; if the frozen worker was also
                # handed a later attempt through its open long-poll, that one creates another.
                assert len(t) >= 2, "expected the stale worker's effect to go through"
            elif variant == "platform":
                assert len(t) == 1
                assert grep_log(a1.logfile, "STALE attempt=1") or grep_log(a1.logfile, "found recorded result")
            else:
                log(f"heartbeat_gate observed ticket count: {len(t)}")
                assert len(t) == 1
        finally:
            if pause.exists():
                pause.unlink()
            sigcont(a1)
            ts.stop()
    run(body())


# =================================================================================================
# Q6a. Cancel while waiting for approval.
def test_q6_cancel_during_approval_wait(sec_server):
    async def body():
        d = fresh_dir("q6-cancel-wait")
        pdb = str(d / "platform.db")
        ts, url = start_ticket_service(d)
        q = f"q6a-{uuid.uuid4().hex[:4]}"
        w = start_secure_worker(d, sec_server.address, q, "w", platform_db=pdb, ticket_url=url)
        c = await Client.connect(sec_server.address)
        try:
            run_id, dig, wf = new_action(pdb, "tenant-a")
            h = await c.start_workflow(SecureRemediationWorkflow.run, SecureInput("tenant-a", run_id, dig),
                                       id=wf, task_queue=q)
            await wait_status(h, "awaiting_approval")
            await h.cancel()
            try:
                await asyncio.wait_for(h.result(), 30)
                res = "returned normally"
            except WorkflowFailureError as e:
                res = f"WorkflowFailureError cause={type(e.cause).__name__}: {e.cause}"
            desc = await h.describe()
            log(f"result: {res}; status={desc.status.name}")
            for ln in activity_attempts(await h.fetch_history()):
                log(f"    history {ln}")
            show_sdb(pdb, ("workflow_events",))
            # A late approval after cancellation is rejected by the server.
            try:
                await h.signal(SecureRemediationWorkflow.approval_ready, api_approve(pdb, "tenant-a", run_id, dig))
                late = "accepted"
            except Exception as e:  # noqa: BLE001
                late = f"{type(e).__name__}: {e}"
            log(f"approval signal after cancel -> {late}")
            assert desc.status.name == "CANCELED" and late != "accepted"
            assert [e["event"] for e in sdb.dump(pdb, "workflow_events")] == ["cancelled"]
            assert tickets(url) == []
        finally:
            w.stop(); ts.stop()
    run(body())


# Q6b. Cancel while the effect activity runs (heartbeat-driven cancellation).
def test_q6_cancel_during_activity(sec_server):
    async def body():
        d = fresh_dir("q6-cancel-activity")
        pdb = str(d / "platform.db")
        pause = d / "pause-before-effect"
        pause.touch()
        env = {MODE_ENV: "platform", PAUSE_ENV: str(pause), INTERRUPTIBLE_ENV: "1"}
        ts, url = start_ticket_service(d)
        q = f"q6b-{uuid.uuid4().hex[:4]}"
        w = start_secure_worker(d, sec_server.address, q, "w", platform_db=pdb, ticket_url=url, env=env)
        c = await Client.connect(sec_server.address)
        try:
            run_id, dig, wf = new_action(pdb, "tenant-a")
            h = await c.start_workflow(SecureRemediationWorkflow.run, SecureInput("tenant-a", run_id, dig),
                                       id=wf, task_queue=q)
            await wait_status(h, "awaiting_approval")
            await h.signal(SecureRemediationWorkflow.approval_ready, api_approve(pdb, "tenant-a", run_id, dig))
            w.wait_for_log("PRE-EFFECT attempt=1", 30)
            t0 = time.monotonic()
            await h.cancel()
            try:
                await asyncio.wait_for(h.result(), 30)
                res = "returned normally"
            except WorkflowFailureError as e:
                res = f"WorkflowFailureError cause={type(e.cause).__name__}: {e.cause}"
            desc = await h.describe()
            log(f"result {time.monotonic() - t0:.1f}s after cancel: {res}; status={desc.status.name}")
            for ln in grep_log(w.logfile, "ACTIVITY EXIT", "EFFECT APPLIED"):
                log(f"    worker: {ln}")
            for ln in activity_attempts(await h.fetch_history()):
                log(f"    history {ln}")
            show_sdb(pdb, ("execution_intents", "execution_results", "workflow_events"))
            ev = [e["event"] for e in sdb.dump(pdb, "workflow_events")]
            assert desc.status.name == "CANCELED"
            assert "activity_observed_cancel" in ev and ev[-1] == "cancelled"
            assert tickets(url) == []
        finally:
            if pause.exists():
                pause.unlink()
            w.stop(); ts.stop()
    run(body())


# Q6c. Approval revoked after the workflow accepted it, while the effect activity is running.
def test_q6_revoked_approval_rechecked_before_effect(sec_server):
    async def body():
        d = fresh_dir("q6-revocation")
        pdb = str(d / "platform.db")
        pause = d / "pause-before-effect"
        pause.touch()
        env = {MODE_ENV: "platform", PAUSE_ENV: str(pause)}
        ts, url = start_ticket_service(d)
        q = f"q6c-{uuid.uuid4().hex[:4]}"
        w = start_secure_worker(d, sec_server.address, q, "w", platform_db=pdb, ticket_url=url, env=env)
        c = await Client.connect(sec_server.address)
        try:
            run_id, dig, wf = new_action(pdb, "tenant-a")
            h = await c.start_workflow(SecureRemediationWorkflow.run, SecureInput("tenant-a", run_id, dig),
                                       id=wf, task_queue=q)
            await wait_status(h, "awaiting_approval")
            apr = api_approve(pdb, "tenant-a", run_id, dig)
            await h.signal(SecureRemediationWorkflow.approval_ready, apr)
            w.wait_for_log("PRE-EFFECT attempt=1", 30)
            log(f"workflow status at pause: {await h.query(SecureRemediationWorkflow.status)} (approval verified)")
            sdb.revoke_approval(pdb, apr)
            log(f"API revoked {apr}")
            pause.unlink()
            out = await asyncio.wait_for(h.result(), 30)
            log(f"result: {out}")
            for ln in grep_log(w.logfile, "re-check", "EFFECT APPLIED", "ACTIVITY EXIT"):
                log(f"    worker: {ln}")
            show_sdb(pdb, ("execution_intents", "execution_results", "workflow_events"))
            assert out.status == "approval_revoked" and tickets(url) == []
        finally:
            if pause.exists():
                pause.unlink()
            w.stop(); ts.stop()
    run(body())


# =================================================================================================
# Q8. Backup taken after the external effect but before Temporal recorded completion; restore it.
@pytest.mark.parametrize("mode", ["platform", "naive"])
def test_q8_backup_restore_mid_flight(mode):
    async def body():
        d = fresh_dir(f"q8-backup-restore-{mode}")
        pdb = str(d / "platform.db")
        hang = d / "hang-after-create"
        hang.touch()
        env = {MODE_ENV: mode, HANG_ENV: str(hang)}
        db_file = d / "temporal.db"
        backup_dir = d / "backup"
        backup_dir.mkdir()
        srv = DevServer(d, db_file).start()
        ts, url = start_ticket_service(d)
        q = f"q8-{mode}-{uuid.uuid4().hex[:4]}"
        wfw = start_secure_worker(d, srv.address, q, "wf-worker-1", platform_db=pdb, ticket_url=url, role="workflow")
        act = start_secure_worker(d, srv.address, q, "act-1", platform_db=pdb, ticket_url=url, role="activity",
                                  env=env)
        try:
            c = await Client.connect(srv.address)
            run_id, dig, wf = new_action(pdb, "tenant-a")
            h = await c.start_workflow(SecureRemediationWorkflow.run, SecureInput("tenant-a", run_id, dig),
                                       id=wf, task_queue=q)
            await wait_status(h, "awaiting_approval")
            await h.signal(SecureRemediationWorkflow.approval_ready, api_approve(pdb, "tenant-a", run_id, dig))
            act.wait_for_log("HANG-AFTER-CREATE attempt=1", 30)
            log(f"effect applied, completion not yet reported; tickets={len(tickets(url))}")
            # Crash-consistent snapshot: freeze the server process, copy the SQLite files, resume.
            sigstop(srv.proc)
            copied = copy_sqlite_set(db_file, backup_dir / "temporal.db")
            sigcont(srv.proc)
            log(f"backup taken (server frozen during copy): {copied}")
            import sqlite3
            with sqlite3.connect(f"file:{backup_dir / 'temporal.db'}?mode=ro", uri=True) as bk:
                log(f"backup PRAGMA integrity_check: {bk.execute('PRAGMA integrity_check').fetchone()[0]}")
            hang.unlink()
            out1 = await asyncio.wait_for(h.result(), 30)
            log(f"original timeline result: {out1}")
            assert out1.status == "completed" and len(tickets(url)) == 1

            # Disaster: lose the Temporal store, restore the backup. The platform DB and the external
            # ticket system are NOT rolled back (they have their own, independent lifecycle).
            srv.proc.kill9(); wfw.kill9(); act.kill9()
            for suffix in ("", "-wal", "-shm", "-journal"):
                Path(str(db_file) + suffix).unlink(missing_ok=True)
            restored = copy_sqlite_set(backup_dir / "temporal.db", db_file)
            log(f"restored Temporal DB from backup: {restored}")
            srv = DevServer(d, db_file, port=srv.port).start()
            c = await Client.connect(srv.address)
            h = c.get_workflow_handle(wf, result_type=SecureOutcome)
            desc = await h.describe()
            log(f"after restore: workflow status={desc.status.name} (original timeline had completed)")
            t0 = time.monotonic()
            start_secure_worker(d, srv.address, q, "wf-worker-2", platform_db=pdb, ticket_url=url, role="workflow")
            act2 = start_secure_worker(d, srv.address, q, "act-2", platform_db=pdb, ticket_url=url,
                                       role="activity", env=env)
            out2 = await asyncio.wait_for(h.result(), 60)
            log(f"restored timeline result {time.monotonic() - t0:.1f}s after workers restarted: {out2}")
            for ln in grep_log(act2.logfile, "EFFECT APPLIED", "adopt", "ACTIVITY", "STALE"):
                log(f"    act-2: {ln}")
            for ln in activity_attempts(await h.fetch_history()):
                log(f"    history {ln}")
            t = tickets(url)
            log(f"external tickets: {len(t)} {[x['id'] for x in t]}")
            show_sdb(pdb, ("execution_intents", "execution_results", "workflow_events"))
            completed_events = [e for e in sdb.dump(pdb, "workflow_events") if e["event"] == "completed"]
            log(f"platform DB 'completed' events for this action: {len(completed_events)}")
            assert desc.status.name == "RUNNING"
            if mode == "platform":
                assert len(t) == 1 and out2.ticket_id == out1.ticket_id
            else:
                assert len(t) == 2
        finally:
            if hang.exists():
                hang.unlink()
            ts.stop()
            srv.proc.stop()
    run(body())
