"""Process harness: real OS processes for the Temporal dev server, ticket service and workers."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from temporalio.client import Client

SPIKE_DIR = Path(__file__).resolve().parents[1]
TEMPORAL_BIN = SPIKE_DIR / ".bin" / "temporal"
RUN_DIR = SPIKE_DIR / ".run"


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def fresh_dir(name: str) -> Path:
    d = RUN_DIR / name
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    return d


ALL_PROCS: list["Proc"] = []  # every process we started, so a failing test cannot leak any


class Proc:
    def __init__(self, name: str, cmd: list[str], logfile: Path, env: dict | None = None):
        self.name, self.cmd, self.logfile = name, cmd, logfile
        self._fh = open(logfile, "ab")
        self.p = subprocess.Popen(cmd, cwd=SPIKE_DIR, stdout=self._fh, stderr=subprocess.STDOUT,
                                  env={**os.environ, **(env or {})}, start_new_session=True)
        ALL_PROCS.append(self)
        log(f"started {name} pid={self.p.pid}")

    def wait_for_log(self, text: str, timeout: float = 30) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if text in self.logfile.read_text(errors="replace"):
                return
            if self.p.poll() is not None:
                raise RuntimeError(f"{self.name} exited rc={self.p.returncode}:\n{self.logfile.read_text()[-3000:]}")
            time.sleep(0.1)
        raise TimeoutError(f"{self.name}: '{text}' not seen in {timeout}s")

    def kill9(self) -> None:
        """Real SIGKILL to the whole process group: no graceful shutdown, no cleanup code runs."""
        os.killpg(self.p.pid, signal.SIGKILL)
        rc = self.p.wait(10)
        log(f"SIGKILLed {self.name} pid={self.p.pid} rc={rc}")

    def stop(self) -> None:
        if self._fh.closed:
            return
        if self.p.poll() is None:
            os.killpg(self.p.pid, signal.SIGTERM)
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(self.p.pid, signal.SIGKILL)
                self.p.wait(10)
        self._fh.close()


class TemporalServer:
    def __init__(self, workdir: Path, db_file: Path, port: int | None = None):
        self.workdir, self.db_file = workdir, db_file
        self.port = port or free_port()
        self.address = f"127.0.0.1:{self.port}"
        self.proc: Proc | None = None

    def start(self) -> "TemporalServer":
        self.proc = Proc(
            f"temporal-server:{self.port}",
            [str(TEMPORAL_BIN), "server", "start-dev", "--headless", "--ip", "127.0.0.1",
             "--port", str(self.port), "--db-filename", str(self.db_file), "--log-level", "warn"],
            self.workdir / f"temporal-{self.port}.log",
        )
        # Run the readiness probe on its own thread/loop so start() works from sync and async callers.
        with concurrent.futures.ThreadPoolExecutor(1) as ex:
            ex.submit(asyncio.run, self._wait_ready()).result()
        return self

    async def _wait_ready(self, timeout: float = 60) -> None:
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                await Client.connect(self.address)  # non-lazy connect performs a GetSystemInfo RPC
                log(f"temporal server ready at {self.address}")
                return
            except Exception as e:  # noqa: BLE001
                last = e
                await asyncio.sleep(0.5)
        raise TimeoutError(f"temporal server not ready: {last}")


def start_ticket_service(workdir: Path, no_lookup: bool = False) -> tuple[Proc, str]:
    port = free_port()
    cmd = [sys.executable, "-m", "spike.ticket_service", "--port", str(port), "--db", str(workdir / "tickets.db")]
    if no_lookup:
        cmd.append("--no-lookup")
    p = Proc("ticket-service", cmd, workdir / "ticket-service.log")
    p.wait_for_log("TICKET SERVICE READY")
    return p, f"http://127.0.0.1:{port}"


def start_worker(workdir: Path, address: str, queue: str, n: int, env: dict | None = None) -> Proc:
    p = Proc(f"worker-{n}", [sys.executable, "-m", "spike.worker", "--address", address, "--task-queue", queue],
             workdir / f"worker-{n}.log", env)
    p.wait_for_log("WORKER READY")
    return p


def tickets(url: str) -> list[dict]:
    with urllib.request.urlopen(f"{url}/admin/tickets", timeout=5) as r:
        return json.loads(r.read())["tickets"]


async def wait_status(handle, expected: str, timeout: float = 60) -> float:
    t0 = time.monotonic()
    last = None
    while time.monotonic() - t0 < timeout:
        try:
            last = await handle.query("status")
        except Exception as e:  # noqa: BLE001  (query fails while no worker is polling)
            last = f"<query error: {type(e).__name__}>"
        if last == expected:
            return time.monotonic() - t0
        await asyncio.sleep(0.3)
    raise TimeoutError(f"status {expected!r} not reached; last={last!r}")
