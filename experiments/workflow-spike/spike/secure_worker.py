"""Worker for the ids-only workflow.

python -m spike.secure_worker --address H:P --task-queue q --role both|workflow|activity \
    --platform-db path --ticket-url URL [--namespace ns] [--identity name]

Codec/failure-converter configuration is read from env (spike.codec.KEYS_ENV / ENCODE_FAILURES_ENV),
effect mode and test hooks from env (see spike.secure_activities).
"""

from __future__ import annotations

import argparse
import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from temporalio.client import Client
from temporalio.worker import Worker

from spike.codec import data_converter_from_env
from spike.secure_activities import SecureActivities
from spike.secure_workflow import SecureRemediationWorkflow


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--address", required=True)
    ap.add_argument("--namespace", default="default")
    ap.add_argument("--task-queue", required=True)
    ap.add_argument("--role", choices=["both", "workflow", "activity"], default="both")
    ap.add_argument("--platform-db", required=True)
    ap.add_argument("--ticket-url", required=True)
    ap.add_argument("--identity", default="")
    args = ap.parse_args()
    identity = args.identity or f"worker-{os.getpid()}"
    client = await Client.connect(args.address, namespace=args.namespace, identity=identity,
                                  data_converter=data_converter_from_env())
    acts = SecureActivities(args.platform_db, args.ticket_url, identity)
    workers = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        if args.role in ("both", "workflow"):
            workers.append(Worker(client, task_queue=args.task_queue, workflows=[SecureRemediationWorkflow],
                                  sticky_queue_schedule_to_start_timeout=timedelta(seconds=3)))
        if args.role in ("both", "activity"):
            workers.append(Worker(client, task_queue=args.task_queue + "-act",
                                  activities=[acts.check_proposal, acts.verify_approval, acts.record_event,
                                              acts.execute_effect],
                                  activity_executor=pool))
        print(f"WORKER READY pid={os.getpid()} identity={identity} role={args.role} queue={args.task_queue}",
              flush=True)
        await asyncio.gather(*(w.run() for w in workers))


if __name__ == "__main__":
    asyncio.run(main())
