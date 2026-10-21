"""Q3 (noisy tenant vs. per-tenant task queues, worker limits, server-side task-queue rate limit,
fairness keys) and Q4 (retention settings, deletion of a tenant's executions, what remains on disk).
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import statistics
import sys
import time
import uuid
from pathlib import Path

from temporalio.client import Client
from temporalio.common import SearchAttributeKey, SearchAttributePair, TypedSearchAttributes

from harness import Proc, fresh_dir, log
from secure_fixtures import SEC_SERVER_FLAGS
from secure_harness import DevServer, cli, copy_sqlite_set, count_in_files
from spike.tenant_load import TenantBatchWorkflow

FLOOD_N, FLOOD_MS = 40, 500  # noisy tenant: 40 activities x 500 ms
B_N, B_MS = 3, 200  # quiet tenant: 3 workflows x 1 activity x 200 ms
SLOTS = 4  # max_concurrent_activities per worker


def run(coro):
    return asyncio.run(coro)


def start_load_worker(d: Path, address: str, name: str, queues: list[str], slots: int = SLOTS) -> Proc:
    cmd = [sys.executable, "-m", "spike.tenant_load", "--address", address, "--max-concurrent-activities", str(slots)]
    for q in queues:
        cmd += ["--task-queue", q]
    p = Proc(name, cmd, d / f"{name}.log")
    p.wait_for_log("WORKER READY")
    return p


async def timed(client: Client, queue: str, n: int, ms: int, fairness_key: str = "") -> float:
    t0 = time.monotonic()
    await client.execute_workflow(TenantBatchWorkflow.run, args=[n, ms, fairness_key],
                                  id=f"load-{uuid.uuid4().hex[:8]}", task_queue=queue)
    return time.monotonic() - t0


async def noisy_neighbour(client: Client, q_a: str, q_b: str, fair: bool = False) -> dict:
    flood = asyncio.create_task(timed(client, q_a, FLOOD_N, FLOOD_MS, "tenant-a" if fair else ""))
    await asyncio.sleep(0.5)  # let the flood fill the queue first
    b = await asyncio.gather(*(timed(client, q_b, 1, B_MS, "tenant-b" if fair else "") for _ in range(B_N)))
    a = await flood
    return {"tenant_a_flood_s": round(a, 2), "tenant_b_latencies_s": [round(x, 2) for x in b],
            "tenant_b_max_s": round(max(b), 2), "tenant_b_median_s": round(statistics.median(b), 2)}


# =================================================================================================
def test_q3_noisy_tenant_isolation():
    async def body():
        d = fresh_dir("q3-tenancy")
        srv = DevServer(d, d / "temporal.db").start()
        procs: list[Proc] = []
        results = {}
        try:
            c = await Client.connect(srv.address)
            # Warm-up (first workflow on a fresh server pays one-off costs).
            w = start_load_worker(d, srv.address, "warm", ["warm"]); procs.append(w)
            await timed(c, "warm", 1, 10)

            # S1. Shared task queue, one worker pool for both tenants.
            procs.append(start_load_worker(d, srv.address, "shared-worker", ["shared"]))
            results["S1_shared_queue"] = await noisy_neighbour(c, "shared", "shared")
            log(f"S1 shared queue, {SLOTS} slots: {results['S1_shared_queue']}")

            # S2. Per-tenant task queues, one worker pool each (same slot count).
            procs.append(start_load_worker(d, srv.address, "worker-tenant-a", ["tq-tenant-a"]))
            procs.append(start_load_worker(d, srv.address, "worker-tenant-b", ["tq-tenant-b"]))
            results["S2_per_tenant_queues"] = await noisy_neighbour(c, "tq-tenant-a", "tq-tenant-b")
            log(f"S2 per-tenant queues, {SLOTS} slots each: {results['S2_per_tenant_queues']}")

            # S2b. Per-tenant task queues but ONE worker process polling both (shared slots).
            procs.append(start_load_worker(d, srv.address, "worker-both", ["tq2-tenant-a", "tq2-tenant-b"]))
            results["S2b_per_tenant_queues_one_process"] = await noisy_neighbour(c, "tq2-tenant-a", "tq2-tenant-b")
            log(f"S2b per-tenant queues polled by one process (one Worker per queue, {SLOTS} slots each): "
                f"{results['S2b_per_tenant_queues_one_process']}")

            # S3. Server-side task-queue rate limit on tenant-a's activity queue.
            procs.append(start_load_worker(d, srv.address, "worker-rl", ["tq-rl-a"], slots=50))
            before = await timed(c, "tq-rl-a", 10, 50)
            r = cli(srv.address, "task-queue", "config", "set", "--task-queue", "tq-rl-a", "--task-queue-type",
                    "activity", "--queue-rps-limit", "2", "--queue-rps-limit-reason", "noisy tenant", check=True)
            log(f"    {r.stdout.strip()[:200]}")
            await asyncio.sleep(1)
            after = await timed(c, "tq-rl-a", 10, 50)
            b_during = await asyncio.gather(timed(c, "tq-rl-a", 10, 50), timed(c, "tq-tenant-b", 1, B_MS))
            results["S3_rate_limit"] = {"10x50ms_no_limit_s": round(before, 2), "10x50ms_limit_2rps_s": round(after, 2),
                                        "tenant_b_while_a_limited_s": round(b_during[1], 2)}
            log(f"S3 task-queue rate limit 2 rps on tenant-a activities: {results['S3_rate_limit']}")
            cli(srv.address, "task-queue", "config", "set", "--task-queue", "tq-rl-a", "--task-queue-type",
                "activity", "--queue-rps-limit", "default", "--queue-rps-limit-reason", "reset", check=True)
        finally:
            for p in procs:
                p.stop()
            srv.proc.stop()

        # S4. Shared queue with fairness keys (separate server: fairness is a server-wide matching setting).
        d2 = fresh_dir("q3-fairness")
        srv2 = DevServer(d2, d2 / "temporal.db", ["--dynamic-config-value", "matching.enableFairness=true"]).start()
        procs = []
        try:
            c2 = await Client.connect(srv2.address)
            procs.append(start_load_worker(d2, srv2.address, "warm", ["warm"]))
            await timed(c2, "warm", 1, 10)
            procs.append(start_load_worker(d2, srv2.address, "shared-worker-fair", ["shared-fair"]))
            results["S4_shared_queue_fairness_keys"] = await noisy_neighbour(c2, "shared-fair", "shared-fair", fair=True)
            log(f"S4 shared queue + fairness keys (matching.enableFairness=true): "
                f"{results['S4_shared_queue_fairness_keys']}")
            procs.append(start_load_worker(d2, srv2.address, "shared-worker-nofair", ["shared-nofair"]))
            results["S4ctl_same_server_no_keys"] = await noisy_neighbour(c2, "shared-nofair", "shared-nofair")
            log(f"S4 control, same server, no fairness keys: {results['S4ctl_same_server_no_keys']}")
        finally:
            for p in procs:
                p.stop()
            srv2.proc.stop()

        (d / "q3-results.json").write_text(json.dumps(results, indent=2))
        s1, s2 = results["S1_shared_queue"], results["S2_per_tenant_queues"]
        assert s2["tenant_b_max_s"] < 1.5, s2  # isolated queue: roughly the 200 ms of work
        assert s1["tenant_b_max_s"] > 2 * s2["tenant_b_max_s"], (s1, s2)  # shared queue: waits behind the flood
        assert results["S3_rate_limit"]["10x50ms_limit_2rps_s"] > 3.0
    run(body())


# =================================================================================================
def test_q4_retention_and_tenant_deletion():
    async def body():
        d = fresh_dir("q4-deletion")
        db_file = d / "temporal.db"
        srv = DevServer(d, db_file, SEC_SERVER_FLAGS).start()
        try:
            # Retention settings the server accepts.
            for ret in ("1m", "1h", "720h"):
                r = cli(srv.address, "operator", "namespace", "create", "-n", f"ret-{ret}", "--retention", ret)
                log(f"    retention {ret}: rc={r.returncode} {(r.stdout + r.stderr).strip()[:150]}")
            r = cli(srv.address, "operator", "namespace", "describe", "-n", "ret-720h", "-o", "json", check=True)
            ns = json.loads(r.stdout)
            log(f"    ret-720h: retention={ns['config']['workflowExecutionRetentionTtl']} "
                f"historyArchival={ns['config']['historyArchivalState']} "
                f"visibilityArchival={ns['config']['visibilityArchivalState']}")

            c = await Client.connect(srv.address)
            key = SearchAttributeKey.for_keyword("TenantId")
            markers: dict[str, list[str]] = {"tenant-a": [], "tenant-b": []}
            handles = {"tenant-a": [], "tenant-b": []}
            for tenant, n in (("tenant-a", 3), ("tenant-b", 2)):
                for i in range(n):
                    m = f"DELMARK-{tenant}-{uuid.uuid4().hex[:10]}"
                    markers[tenant].append(m)
                    # No worker polls this queue: executions stay Running with the marker in their input.
                    h = await c.start_workflow("EvidenceHolder", m, id=f"axiom.{tenant}.del{i}-{uuid.uuid4().hex[:4]}",
                                               task_queue="no-worker", search_attributes=TypedSearchAttributes(
                                                   [SearchAttributePair(key, tenant)]))
                    handles[tenant].append(h)
            await handles["tenant-a"][0].terminate("closed before deletion")  # one closed, two running
            await asyncio.sleep(2)  # visibility is eventually consistent
            files = [db_file, Path(str(db_file) + "-wal"), Path(str(db_file) + "-journal")]

            def raw_counts(tenant):
                return {m: sum(count_in_files(files, m.encode()).values()) for m in markers[tenant]}

            log(f"before delete: raw-file occurrences tenant-a={raw_counts('tenant-a')} "
                f"tenant-b={raw_counts('tenant-b')}")
            r = cli(srv.address, "workflow", "count", "--query", 'TenantId="tenant-a"')
            log(f"    count tenant-a: {r.stdout.strip()}")

            t0 = time.monotonic()
            r = cli(srv.address, "workflow", "delete", "--query", 'TenantId="tenant-a"', "--reason",
                    "A20 tenant deletion", "--yes", check=True)
            log(f"    {r.stdout.strip()[:300]}")
            gone = None
            first_gone: dict[str, float] = {}
            res: list[str] = []
            while time.monotonic() - t0 < 180:
                res = []
                for h in handles["tenant-a"]:
                    try:
                        desc = await h.describe()
                        res.append(f"present:{desc.status.name}")
                    except Exception as e:  # noqa: BLE001
                        res.append(type(e).__name__)
                        first_gone.setdefault(h.id, round(time.monotonic() - t0, 1))
                if all(not x.startswith("present") for x in res):
                    gone = time.monotonic() - t0
                    break
                await asyncio.sleep(1)
            log(f"tenant-a executions: last describe results {res}; seconds until NotFound per execution "
                f"{first_gone} (closed one = {handles['tenant-a'][0].id})")
            await asyncio.sleep(2)
            r = cli(srv.address, "workflow", "count", "--query", 'TenantId="tenant-a"')
            log(f"    count tenant-a after delete: {r.stdout.strip()}")
            r = cli(srv.address, "workflow", "count", "--query", 'TenantId="tenant-b"')
            log(f"    count tenant-b after delete: {r.stdout.strip()}")
            r = cli(srv.address, "batch", "list", "-o", "json")
            try:
                log(f"    batch list: {json.dumps(json.loads(r.stdout))[:500]}")
            except ValueError:
                log(f"    batch list (raw): {r.stdout.strip()[:500]!r}")
            for h in handles["tenant-b"]:
                desc = await h.describe()
                assert desc.status.name == "RUNNING"
            after_api = raw_counts("tenant-a")
            log(f"after delete (server running): raw-file occurrences tenant-a={after_api} "
                f"tenant-b={raw_counts('tenant-b')}")

            # Single-execution delete of a running workflow (terminates, then deletes).
            r = cli(srv.address, "workflow", "delete", "--workflow-id", handles["tenant-b"][1].id, "--yes",
                    check=True)
            log(f"    {r.stdout.strip()[:200]}")
            await asyncio.sleep(2)
            try:
                await handles["tenant-b"][1].describe()
                single = "still present"
            except Exception as e:  # noqa: BLE001
                single = type(e).__name__
            log(f"single delete of a running execution -> describe: {single}")

            # Stop the server and look at the file again, then VACUUM a copy.
            srv.proc.stop()
            after_stop = raw_counts("tenant-a")
            vac = d / "vacuum-copy.db"
            copy_sqlite_set(db_file, vac)
            with sqlite3.connect(vac) as conn:
                conn.execute("VACUUM")
            after_vacuum = {m: vac.read_bytes().count(m.encode()) for m in markers["tenant-a"]}
            log(f"after server stop: raw-file occurrences tenant-a={after_stop}")
            log(f"after VACUUM of a copy: tenant-a={after_vacuum} "
                f"tenant-b={ {m: vac.read_bytes().count(m.encode()) for m in markers['tenant-b']} }")
            assert gone is not None
            assert single != "still present"
        finally:
            if srv.proc and srv.proc.p.poll() is None:
                srv.proc.stop()
    run(body())
