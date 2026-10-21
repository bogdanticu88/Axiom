"""Helpers for the security/recovery tests: configurable dev server, secure workers, CLI calls."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from temporalio.client import Client

from harness import ALL_PROCS, SPIKE_DIR, TEMPORAL_BIN, Proc, free_port, log
from spike import secure_db as sdb
from spike.codec import workflow_id_for

PROPOSAL = {
    "action": "open_remediation_ticket",
    "finding_id": "VULN-2026-0042",
    "asset": "api-gw-prod-01",
    "severity": "high",
    "summary": "Upgrade openssl to patched version",
    # A distinctive string standing in for raw evidence; tests grep Temporal's history and DB for it.
    "evidence_excerpt": "EVIDENCE-SECRET-7f3a: curl -k https://10.20.30.40/admin -> 200 OK",
}
SECRET_MARKERS = ["EVIDENCE-SECRET-7f3a", "api-gw-prod-01", "openssl"]


class DevServer:
    """`temporal server start-dev` with extra flags (search attributes, namespaces, dynamic config)."""

    def __init__(self, workdir: Path, db_file: Path, extra: list[str] | None = None, port: int | None = None):
        self.workdir, self.db_file, self.extra = workdir, db_file, extra or []
        self.port = port or free_port()
        self.address = f"127.0.0.1:{self.port}"
        self.proc: Proc | None = None

    def start(self) -> "DevServer":
        self.proc = Proc(
            f"temporal-server:{self.port}",
            [str(TEMPORAL_BIN), "server", "start-dev", "--headless", "--ip", "127.0.0.1",
             "--port", str(self.port), "--db-filename", str(self.db_file), "--log-level", "warn", *self.extra],
            self.workdir / f"temporal-{self.port}.log",
        )
        with concurrent.futures.ThreadPoolExecutor(1) as ex:
            ex.submit(asyncio.run, self._wait_ready()).result()
        return self

    async def _wait_ready(self, timeout: float = 60) -> None:
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                await Client.connect(self.address)
                log(f"temporal server ready at {self.address} extra={self.extra}")
                return
            except Exception as e:  # noqa: BLE001
                last = e
                await asyncio.sleep(0.5)
        raise TimeoutError(f"temporal server not ready: {last}")


def cli(address: str, *args: str, check: bool = False, timeout: float = 60) -> subprocess.CompletedProcess:
    cmd = [str(TEMPORAL_BIN), *args, "--address", address]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=SPIKE_DIR)
    shown = " ".join(a if " " not in a else repr(a) for a in ["temporal", *args])
    log(f"$ {shown}  -> rc={r.returncode}")
    if check and r.returncode != 0:
        raise RuntimeError(f"{shown} failed rc={r.returncode}\n{r.stdout}\n{r.stderr}")
    return r


def start_secure_worker(workdir: Path, address: str, queue: str, name: str, *, platform_db: str, ticket_url: str,
                        role: str = "both", env: dict | None = None, namespace: str = "default") -> Proc:
    p = Proc(name, [sys.executable, "-m", "spike.secure_worker", "--address", address, "--namespace", namespace,
                    "--task-queue", queue, "--role", role, "--platform-db", platform_db,
                    "--ticket-url", ticket_url, "--identity", name],
             workdir / f"{name}.log", env)
    p.wait_for_log("WORKER READY")
    return p


def sigstop(p: Proc) -> None:
    os.killpg(p.p.pid, signal.SIGSTOP)
    log(f"SIGSTOPped {p.name} pid={p.p.pid}")


def sigcont(p: Proc) -> None:
    os.killpg(p.p.pid, signal.SIGCONT)
    log(f"SIGCONTed {p.name} pid={p.p.pid}")


def new_action(platform_db: str, tenant: str, proposal: dict | None = None) -> tuple[str, str, str]:
    """API side: store the proposal; returns (run_id, digest, workflow_id)."""
    run_id = f"run{uuid.uuid4().hex[:8]}"
    digest = sdb.put_proposal(platform_db, tenant, run_id, proposal or PROPOSAL)
    return run_id, digest, workflow_id_for(tenant, run_id)


def api_approve(platform_db: str, tenant: str, run_id: str, digest: str,
                valid_for: timedelta = timedelta(minutes=10)) -> str:
    """API side: record an approval decision (RBAC/SoD would happen here) and return its id."""
    approval_id = f"apr-{uuid.uuid4().hex[:12]}"
    sdb.put_approval(platform_db, approval_id, tenant, run_id, digest, "alice@example.test",
                     (datetime.now(timezone.utc) + valid_for).isoformat())
    return approval_id


def show_sdb(platform_db: str, tables=("execution_intents", "execution_results", "workflow_events")) -> None:
    for table in tables:
        rows = sdb.dump(platform_db, table)
        log(f"platform_db.{table}: {len(rows)} row(s)")
        for r in rows:
            r = {k: (v[:16] + "..." if isinstance(v, str) and len(v) > 40 else v) for k, v in r.items()}
            log(f"    {json.dumps(r)}")


def history_json(address: str, workflow_id: str, namespace: str = "default") -> str:
    r = cli(address, "workflow", "show", "--workflow-id", workflow_id, "--namespace", namespace,
            "--output", "json", check=True)
    return r.stdout


def copy_sqlite_set(src: Path, dst: Path) -> list[str]:
    """Copy a SQLite db and its -wal/-shm companions (if present)."""
    copied = []
    for suffix in ("", "-wal", "-shm", "-journal"):
        s = Path(str(src) + suffix)
        if s.exists():
            shutil.copy2(s, Path(str(dst) + suffix))
            copied.append(s.name + f" ({s.stat().st_size} B)")
    return copied


def count_in_files(paths: list[Path], needle: bytes) -> dict[str, int]:
    out = {}
    for p in paths:
        if p.exists():
            out[p.name] = p.read_bytes().count(needle)
    return out


__all__ = ["ALL_PROCS", "DevServer", "PROPOSAL", "SECRET_MARKERS", "api_approve", "cli", "copy_sqlite_set",
           "count_in_files", "history_json", "new_action", "show_sdb", "sigcont", "sigstop",
           "start_secure_worker"]
