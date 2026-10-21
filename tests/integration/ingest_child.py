"""Child process for the real-kill ingestion test. Not a pytest module (no test_ prefix)."""
import json
import os
import signal
import sys
from uuid import UUID

from axiom.db import Database
from axiom.domains.evidence.objectstore import FilesystemObjectStore
from axiom.ingestion.pipeline import IngestionService

mode = sys.argv[1]
db = Database(os.environ["CHILD_DSN"], min_size=1, max_size=2)
db.open()
svc = IngestionService(db, FilesystemObjectStore(os.environ["CHILD_STORE"]), page_size=7, lease_seconds=60)
kill_after = int(sys.argv[2]) if mode == "kill-after-page" else None


def hook(page):
    if kill_after is not None and page == kill_after:
        os.kill(os.getpid(), signal.SIGKILL)   # real abrupt death: no cleanup, no rollback of committed pages


row = svc.execute(UUID(os.environ["CHILD_TENANT"]), UUID(os.environ["CHILD_SYSTEM"]), UUID(os.environ["CHILD_RUN"]),
                  worker_id=f"child-{os.getpid()}", on_page_committed=hook)
print(json.dumps({"status": row["status"], "counts": row["counts"]}))
