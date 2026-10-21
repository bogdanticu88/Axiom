"""Scenario tests. Every process (Temporal server, ticket service, workers) is a real OS process;
'kill' means SIGKILL to the process group."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from temporalio.client import Client

from harness import (
    TemporalServer, fresh_dir, log, start_ticket_service, start_worker, tickets, wait_status,
)
from spike import platform_db
from spike.activities import HANG_ENV, NAIVE_ENV, digest_of
from spike.models import Approval, OperatorResolution, RemediationInput, WorkflowOutcome
from spike.workflows import RemediationWorkflow

PROPOSAL = {
    "action": "open_remediation_ticket",
    "finding_id": "VULN-2026-0042",
    "asset": "api-gw-prod-01",
    "severity": "high",
    "summary": "Upgrade openssl to patched version",
}


def approval(digest: str, valid_for: timedelta = timedelta(minutes=10)) -> Approval:
    return Approval(approver="alice@example.test", payload_digest=digest,
                    expires_at=(datetime.now(timezone.utc) + valid_for).isoformat())


def show_db(db: str) -> None:
    for table in ("proposals", "execution_intents", "execution_results", "workflow_events"):
        rows = platform_db.dump(db, table)
        log(f"platform_db.{table}: {len(rows)} row(s)")
        for r in rows:
            r = {k: (v[:16] + "..." if isinstance(v, str) and len(v) > 40 else v) for k, v in r.items()}
            log(f"    {json.dumps(r)}")


async def start_wf(client: Client, queue: str, workdir, ticket_url: str, window: float = 3600):
    wf_id = f"remediation-{uuid.uuid4().hex[:8]}"
    inp = RemediationInput(proposal=PROPOSAL, platform_db=str(workdir / "platform.db"),
                           ticket_url=ticket_url, approval_window_seconds=window)
    h = await client.start_workflow(RemediationWorkflow.run, inp, id=wf_id, task_queue=queue)
    log(f"started workflow {wf_id}")
    return h, inp


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------------------------
# 1 + 2. Approval wait survives a SIGKILLed worker; exactly one ticket results.
def test_worker_sigkill_while_awaiting_approval(temporal_server):
    async def body():
        d = fresh_dir("worker-restart")
        q = f"q-{uuid.uuid4().hex[:6]}"
        ts, url = start_ticket_service(d)
        w1 = start_worker(d, temporal_server.address, q, 1)
        client = await Client.connect(temporal_server.address)
        try:
            h, inp = await start_wf(client, q, d, url)
            await wait_status(h, "awaiting_approval")
            log("workflow is awaiting approval; SIGKILL worker-1")
            w1.kill9()
            await asyncio.sleep(2)
            w2 = start_worker(d, temporal_server.address, q, 2)
            t0 = time.monotonic()
            await h.signal(RemediationWorkflow.approve, approval(digest_of(PROPOSAL)))
            out: WorkflowOutcome = await asyncio.wait_for(h.result(), 90)
            log(f"result after {time.monotonic() - t0:.1f}s: {out}")
            assert out.status == "completed" and out.detail == "created"
            hist = await h.fetch_history()
            kinds = [e.WhichOneof("attributes").removesuffix("_event_attributes") for e in hist.events]
            log(f"history events: {kinds}")
            t = tickets(url)
            log(f"external tickets: {t}")
            assert len(t) == 1 and t[0]["id"] == out.ticket_id
            show_db(inp.platform_db)
            w2.stop()
        finally:
            ts.stop()
    run(body())


# 1a. Digest substitution: approval for a different payload must not execute.
def test_approval_digest_mismatch_does_not_execute(temporal_server):
    async def body():
        d = fresh_dir("digest-mismatch")
        q = f"q-{uuid.uuid4().hex[:6]}"
        ts, url = start_ticket_service(d)
        w = start_worker(d, temporal_server.address, q, 1)
        client = await Client.connect(temporal_server.address)
        try:
            h, inp = await start_wf(client, q, d, url)
            await wait_status(h, "awaiting_approval")
            tampered = {**PROPOSAL, "asset": "*"}  # argument substitution
            await h.signal(RemediationWorkflow.approve, approval(digest_of(tampered)))
            out = await asyncio.wait_for(h.result(), 30)
            log(f"result: {out}")
            assert out.status == "approval_mismatch"
            assert tickets(url) == []
            assert platform_db.dump(inp.platform_db, "execution_intents") == []
            ev = [e["event"] for e in platform_db.dump(inp.platform_db, "workflow_events")]
            assert ev == ["approval_mismatch"]
            show_db(inp.platform_db)
        finally:
            w.stop(); ts.stop()
    run(body())


# 1b. Expired approval must not be used.
def test_expired_approval_is_not_used(temporal_server):
    async def body():
        d = fresh_dir("expired-approval")
        q = f"q-{uuid.uuid4().hex[:6]}"
        ts, url = start_ticket_service(d)
        w = start_worker(d, temporal_server.address, q, 1)
        client = await Client.connect(temporal_server.address)
        try:
            h, inp = await start_wf(client, q, d, url)
            await wait_status(h, "awaiting_approval")
            await h.signal(RemediationWorkflow.approve, approval(digest_of(PROPOSAL), timedelta(seconds=-5)))
            out = await asyncio.wait_for(h.result(), 30)
            log(f"result: {out}")
            assert out.status == "approval_expired"
            assert tickets(url) == []
            assert platform_db.dump(inp.platform_db, "execution_intents") == []
        finally:
            w.stop(); ts.stop()
    run(body())


# 1c. Approval deadline is a durable workflow timer.
def test_approval_deadline_timer(temporal_server):
    async def body():
        d = fresh_dir("approval-deadline")
        q = f"q-{uuid.uuid4().hex[:6]}"
        ts, url = start_ticket_service(d)
        w = start_worker(d, temporal_server.address, q, 1)
        client = await Client.connect(temporal_server.address)
        try:
            h, inp = await start_wf(client, q, d, url, window=3)
            t0 = time.monotonic()
            out = await asyncio.wait_for(h.result(), 30)
            log(f"result after {time.monotonic() - t0:.1f}s: {out}")
            assert out.status == "approval_deadline_exceeded"
            assert tickets(url) == []
            # Late approval after the workflow closed is rejected by the server.
            try:
                await h.signal(RemediationWorkflow.approve, approval(digest_of(PROPOSAL)))
                late = "accepted"
            except Exception as e:  # noqa: BLE001
                late = f"{type(e).__name__}: {e}"
            log(f"late approval signal -> {late}")
            assert late != "accepted"
            # Timer appears in history as TimerStarted/TimerFired.
            hist = await h.fetch_history()
            kinds = [e.WhichOneof("attributes") for e in hist.events]
            log(f"timer events: {[k for k in kinds if 'timer' in k]}")
            assert "timer_fired_event_attributes" in kinds
        finally:
            w.stop(); ts.stop()
    run(body())


# 3 + 4. Lost acknowledgement: ticket created, worker SIGKILLed before the activity returns.
def test_lost_ack_reconciles_by_lookup(temporal_server):
    async def body():
        d = fresh_dir("lost-ack-lookup")
        q = f"q-{uuid.uuid4().hex[:6]}"
        hang = d / "hang-after-create"
        hang.touch()
        ts, url = start_ticket_service(d)
        w1 = start_worker(d, temporal_server.address, q, 1, {HANG_ENV: str(hang)})
        client = await Client.connect(temporal_server.address)
        try:
            h, inp = await start_wf(client, q, d, url)
            await wait_status(h, "awaiting_approval")
            await h.signal(RemediationWorkflow.approve, approval(digest_of(PROPOSAL)))
            w1.wait_for_log("EFFECT APPLIED", 30)
            assert len(tickets(url)) == 1
            log("ticket exists, activity has not returned; SIGKILL worker-1")
            w1.kill9()
            assert platform_db.dump(inp.platform_db, "execution_results") == []  # outcome unknown
            hang.unlink()
            w2 = start_worker(d, temporal_server.address, q, 2, {HANG_ENV: str(hang)})
            t0 = time.monotonic()
            out = await asyncio.wait_for(h.result(), 90)
            log(f"result {time.monotonic() - t0:.1f}s after restart: {out}")
            t = tickets(url)
            log(f"external tickets: {t}")
            assert out.status == "completed" and out.detail == "adopted"
            assert len(t) == 1 and t[0]["id"] == out.ticket_id
            assert t[0]["idempotency_key"] == out.operation_key
            intents = platform_db.dump(inp.platform_db, "execution_intents")
            results = platform_db.dump(inp.platform_db, "execution_results")
            assert [i["attempt"] for i in intents] == [1, 2]
            assert [(r["outcome"], r["attempt"]) for r in results] == [("adopted", 2)]
            show_db(inp.platform_db)
            w2.stop()
        finally:
            ts.stop()
    run(body())


# 3-control. Same crash with the reconcile lookup disabled: proves the lookup is what prevents
# the duplicate (Temporal itself retries the activity and the second attempt creates again).
def test_negative_control_naive_retry_duplicates(temporal_server):
    async def body():
        d = fresh_dir("lost-ack-naive")
        q = f"q-{uuid.uuid4().hex[:6]}"
        hang = d / "hang-after-create"
        hang.touch()
        env = {HANG_ENV: str(hang), NAIVE_ENV: "1"}
        ts, url = start_ticket_service(d)
        w1 = start_worker(d, temporal_server.address, q, 1, env)
        client = await Client.connect(temporal_server.address)
        try:
            h, inp = await start_wf(client, q, d, url)
            await wait_status(h, "awaiting_approval")
            await h.signal(RemediationWorkflow.approve, approval(digest_of(PROPOSAL)))
            w1.wait_for_log("EFFECT APPLIED", 30)
            w1.kill9()
            hang.unlink()
            w2 = start_worker(d, temporal_server.address, q, 2, env)
            out = await asyncio.wait_for(h.result(), 90)
            t = tickets(url)
            log(f"result: status={out.status} detail={out.detail}; external ticket count={len(t)}: {[x['id'] for x in t]}")
            assert out.status == "completed" and len(t) == 2  # duplicate effect, as expected
            w2.stop()
        finally:
            ts.stop()
    run(body())


# 3b. Same crash, but the external system cannot be searched: park for an operator.
def test_lost_ack_without_lookup_needs_operator(temporal_server):
    async def body():
        d = fresh_dir("lost-ack-no-lookup")
        q = f"q-{uuid.uuid4().hex[:6]}"
        hang = d / "hang-after-create"
        hang.touch()
        ts, url = start_ticket_service(d, no_lookup=True)
        w1 = start_worker(d, temporal_server.address, q, 1, {HANG_ENV: str(hang)})
        client = await Client.connect(temporal_server.address)
        try:
            h, inp = await start_wf(client, q, d, url)
            await wait_status(h, "awaiting_approval")
            await h.signal(RemediationWorkflow.approve, approval(digest_of(PROPOSAL)))
            w1.wait_for_log("EFFECT APPLIED", 30)
            w1.kill9()
            hang.unlink()
            w2 = start_worker(d, temporal_server.address, q, 2, {HANG_ENV: str(hang)})
            waited = await wait_status(h, "needs_operator_reconciliation", 60)
            log(f"workflow reached needs_operator_reconciliation after {waited:.1f}s")
            await asyncio.sleep(5)  # prove it is parked, not retrying
            t = tickets(url)
            assert len(t) == 1, t
            assert await h.query("status") == "needs_operator_reconciliation"
            log(f"after 5s parked: tickets={len(t)}, status still needs_operator_reconciliation")
            # Operator checks the external system out of band and adopts the existing ticket.
            await h.signal(RemediationWorkflow.operator_resolve,
                           OperatorResolution(decision="adopt", ticket_id=t[0]["id"], operator="bob"))
            out = await asyncio.wait_for(h.result(), 30)
            log(f"result: {out}")
            assert out.status == "completed" and out.detail == "operator_adopted"
            assert len(tickets(url)) == 1
            results = platform_db.dump(inp.platform_db, "execution_results")
            assert [r["outcome"] for r in results] == ["operator_adopted"]
            show_db(inp.platform_db)
            w2.stop()
        finally:
            ts.stop()
    run(body())


# 5. Temporal server SIGKILLed and restarted (same SQLite file) while the workflow waits.
def test_server_sigkill_restart_while_awaiting_approval():
    async def body():
        d = fresh_dir("server-restart")
        srv = TemporalServer(d, d / "temporal.db").start()
        q = f"q-{uuid.uuid4().hex[:6]}"
        ts, url = start_ticket_service(d)
        w1 = start_worker(d, srv.address, q, 1)
        try:
            client = await Client.connect(srv.address)
            h, inp = await start_wf(client, q, d, url)
            wf_id = h.id
            await wait_status(h, "awaiting_approval")
            log("SIGKILL temporal server and worker-1")
            srv.proc.kill9()
            w1.kill9()
            srv = TemporalServer(d, d / "temporal.db", port=srv.port).start()
            w2 = start_worker(d, srv.address, q, 2)
            client = await Client.connect(srv.address)
            h = client.get_workflow_handle(wf_id, result_type=WorkflowOutcome)
            desc = await h.describe()
            log(f"after server restart: workflow {wf_id} status={desc.status.name}")
            await wait_status(h, "awaiting_approval", 60)
            await h.signal(RemediationWorkflow.approve, approval(digest_of(PROPOSAL)))
            out = await asyncio.wait_for(h.result(), 90)
            log(f"result: {out}")
            t = tickets(url)
            log(f"external ticket count={len(t)}")
            assert out.status == "completed"
            assert len(t) == 1
            w2.stop()
        finally:
            ts.stop()
            srv.proc.stop()
    run(body())


# 6. Determinism / versioning: replay a real recorded history against changed workflow code.
def test_replay_detects_unpatched_change(temporal_server):
    from temporalio.worker import Replayer

    from changed_workflows import PatchedChange, UnpatchedChange

    async def body():
        d = fresh_dir("replay")
        q = f"q-{uuid.uuid4().hex[:6]}"
        ts, url = start_ticket_service(d)
        w = start_worker(d, temporal_server.address, q, 1)
        client = await Client.connect(temporal_server.address)
        try:
            h, _ = await start_wf(client, q, d, url)
            await wait_status(h, "awaiting_approval")
            await h.signal(RemediationWorkflow.approve, approval(digest_of(PROPOSAL)))
            await asyncio.wait_for(h.result(), 30)
            history = await h.fetch_history()
            log(f"recorded history: {len(history.events)} events")
            results = {}
            for name, cls in [("original", RemediationWorkflow), ("unpatched_change", UnpatchedChange),
                              ("patched_change", PatchedChange)]:
                r = await Replayer(workflows=[cls]).replay_workflow(history, raise_on_replay_failure=False)
                results[name] = None if r.replay_failure is None else \
                    f"{type(r.replay_failure).__name__}: {str(r.replay_failure)[:200]}"
                log(f"replay with {name}: {results[name] or 'OK'}")
            assert results["original"] is None
            assert results["unpatched_change"] is not None
            assert results["patched_change"] is None
        finally:
            w.stop(); ts.stop()
    run(body())
