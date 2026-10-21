"""Child process for real-kill tests: runs one worker pass for one tenant, then exits.

usage: python jobs_child.py <app_dsn> <tenant_id> <tickets_file> <lookup:0|1> <hang_marker_or_->
"""
from __future__ import annotations

import sys
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parent))

from jobs_support import FileTickets, TicketHandler  # noqa: E402

from axiom.db import Database  # noqa: E402
from axiom.jobs import Worker, WorkerConfig  # noqa: E402


def main() -> None:
    dsn, tenant, tickets, lookup, marker = sys.argv[1:6]
    db = Database(dsn, min_size=1, max_size=3, name="child")
    db.open()
    adapter = FileTickets(Path(tickets), lookup_supported=lookup == "1",
                          hang_after_create=None if marker == "-" else Path(marker))
    worker = Worker(db, [TicketHandler(adapter)], worker_id="child",
                    config=WorkerConfig(lease_seconds=1.0, step_timeout_seconds=2.0))
    worker.run_once(only_tenants={UUID(tenant)})
    db.close()


if __name__ == "__main__":
    main()
