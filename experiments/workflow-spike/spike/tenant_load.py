"""Tenant load generator for the noisy-neighbour experiment.

TenantBatchWorkflow(n, work_ms, fairness_key) runs n activities in parallel, each sleeping work_ms, on
the workflow's own task queue (with Priority(fairness_key) when given); the test measures latency.

python -m spike.tenant_load --address H:P --task-queue q [--task-queue q2 ...] \
    --max-concurrent-activities N [--max-task-queue-aps R]
"""

from __future__ import annotations

import argparse
import asyncio
import os
from datetime import timedelta

from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.common import Priority
from temporalio.worker import Worker


@activity.defn
async def tenant_work(work_ms: int) -> int:
    await asyncio.sleep(work_ms / 1000)
    return work_ms


@workflow.defn
class TenantBatchWorkflow:
    @workflow.run
    async def run(self, n: int, work_ms: int, fairness_key: str = "") -> int:
        prio = Priority(fairness_key=fairness_key) if fairness_key else Priority.default
        handles = [workflow.execute_activity(tenant_work, work_ms, start_to_close_timeout=timedelta(minutes=5),
                                             priority=prio)
                   for _ in range(n)]
        return sum(await asyncio.gather(*handles))


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--address", required=True)
    ap.add_argument("--namespace", default="default")
    ap.add_argument("--task-queue", action="append", required=True)
    ap.add_argument("--max-concurrent-activities", type=int, default=4)
    ap.add_argument("--max-task-queue-aps", type=float, default=None)
    args = ap.parse_args()
    client = await Client.connect(args.address, namespace=args.namespace)
    workers = [Worker(client, task_queue=q, workflows=[TenantBatchWorkflow], activities=[tenant_work],
                      max_concurrent_activities=args.max_concurrent_activities,
                      max_task_queue_activities_per_second=args.max_task_queue_aps)
               for q in args.task_queue]
    print(f"WORKER READY pid={os.getpid()} queues={args.task_queue} "
          f"max_concurrent_activities={args.max_concurrent_activities} "
          f"max_task_queue_aps={args.max_task_queue_aps}", flush=True)
    await asyncio.gather(*(w.run() for w in workers))


if __name__ == "__main__":
    asyncio.run(main())
