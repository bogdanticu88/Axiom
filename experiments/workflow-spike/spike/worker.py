"""Worker process: python -m spike.worker --address 127.0.0.1:7233 --task-queue q"""

from __future__ import annotations

import argparse
import asyncio
import os
from concurrent.futures import ThreadPoolExecutor

from temporalio.client import Client
from temporalio.worker import Worker

from spike import activities as acts
from spike.workflows import RemediationWorkflow


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--address", required=True)
    ap.add_argument("--task-queue", required=True)
    args = ap.parse_args()
    client = await Client.connect(args.address)
    with ThreadPoolExecutor(max_workers=8) as pool:
        worker = Worker(
            client,
            task_queue=args.task_queue,
            workflows=[RemediationWorkflow],
            activities=[acts.persist_proposal, acts.record_workflow_event,
                        acts.record_operator_resolution, acts.execute_ticket_effect],
            activity_executor=pool,
        )
        print(f"WORKER READY pid={os.getpid()} queue={args.task_queue}", flush=True)
        await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
