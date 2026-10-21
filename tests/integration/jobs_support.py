"""Test doubles for the job runner: a file-backed fake ticket system shared across processes, and a handler.

The fake records every ticket it creates in a JSON-lines file, so tests can count real duplicate effects even
when the creating process was SIGKILLed. It is a stand-in for an external system, not a model of any vendor API.
"""
from __future__ import annotations

import fcntl
import json
import os
import time
from pathlib import Path
from typing import Any

from axiom.jobs import Done, EffectGate, JobContext
from axiom.jobs.effects import DefinitelyNotApplied, PermanentFailure, UnknownOutcome


class FileTickets:
    integration = "fake_tickets"

    def __init__(self, path: Path, *, lookup_supported: bool, failures: list[str] | None = None,
                 hang_after_create: Path | None = None):
        self.path = Path(path)
        self.lookup_supported = lookup_supported
        self.failures = list(failures or [])   # queued behaviours for successive create calls
        self.hang_after_create = hang_after_create
        self.path.touch(exist_ok=True)
        self.lookups = 0

    def tickets(self) -> list[dict]:
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def lookup(self, operation_key: str) -> str | None:
        self.lookups += 1
        if not self.lookup_supported:
            raise AssertionError("lookup called on an integration without lookup")
        for t in self.tickets():
            if t["operation_key"] == operation_key:
                return t["ref"]
        return None

    def create(self, operation_key: str, request: dict[str, Any], fencing_token: int) -> str:
        mode = self.failures.pop(0) if self.failures else "ok"
        if mode == "not_applied":
            raise DefinitelyNotApplied("rejected before processing (429)")
        if mode == "permanent":
            raise PermanentFailure("400 invalid project")
        with open(self.path, "a+") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            fh.seek(0)
            n = sum(1 for line in fh if line.strip())
            ref = f"TICKET-{n + 1}"
            fh.write(json.dumps({"ref": ref, "operation_key": operation_key, "title": request.get("title"),
                                 "fencing_token": fencing_token, "pid": os.getpid()}) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        if self.hang_after_create is not None:
            self.hang_after_create.write_text(ref)
            time.sleep(120)            # the test SIGKILLs us here: effect done, outcome never recorded
        if mode == "lost_ack":
            raise UnknownOutcome("connection reset after the request was sent")
        return ref


class TicketHandler:
    kind = "test.ticket"
    versions = frozenset({1})
    current_version = 1

    def __init__(self, adapter: FileTickets, revalidate=None, before_effect=None):
        self.adapter = adapter
        self.revalidate = revalidate or (lambda conn: None)
        self.before_effect = before_effect

    def step(self, jc: JobContext):
        if self.before_effect:
            self.before_effect(jc)
        outcome = EffectGate(jc).run(self.adapter, {"title": jc.job["payload"]["title"]}, self.revalidate)
        return outcome.step


class ScriptedHandler:
    """Returns the scripted results in order (callables receive the JobContext)."""
    kind = "test.scripted"
    current_version = 1

    def __init__(self, script, versions=frozenset({1})):
        self.script = list(script)
        self.versions = versions
        self.calls = 0

    def step(self, jc: JobContext):
        self.calls += 1
        item = self.script.pop(0) if self.script else Done({"calls": self.calls})
        return item(jc) if callable(item) else item
