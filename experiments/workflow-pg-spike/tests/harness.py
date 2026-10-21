"""Process and database harness: real OS processes (ticket service, workers), real signals,
throwaway databases named wfspike_<random> on the disposable test cluster."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import psycopg
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

from pgspike import api

SPIKE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SPIKE_DIR.parents[1]
RUN_DIR = SPIKE_DIR / ".run"
PG_BIN = Path("/usr/lib/postgresql/16/bin")
WORKER_ROLE = "wfspike_worker"


def log(msg: str) -> None:
    t = time.time()
    print(f"[{time.strftime('%H:%M:%S', time.localtime(t))}.{int(t * 1000) % 1000:03d}] {msg}", flush=True)


def load_env_test() -> dict[str, str]:
    env = {}
    for line in (REPO_ROOT / ".env.test").read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"')
    return env


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def fresh_dir(name: str) -> Path:
    d = RUN_DIR / name
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    return d


def wait_for(pred, timeout: float = 30, interval: float = 0.1, what: str = "condition"):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = pred()
        if last:
            return last
        time.sleep(interval)
    raise TimeoutError(f"{what} not reached in {timeout}s; last={last!r}")


ALL_PROCS: list["Proc"] = []


class Proc:
    def __init__(self, name: str, cmd: list[str], logfile: Path, env: dict | None = None):
        self.name, self.cmd, self.logfile = name, cmd, logfile
        self._fh = open(logfile, "ab")
        self.p = subprocess.Popen(cmd, cwd=SPIKE_DIR, stdout=self._fh, stderr=subprocess.STDOUT,
                                  env={**os.environ, **(env or {})}, start_new_session=True)
        ALL_PROCS.append(self)
        log(f"started {name} pid={self.p.pid}")

    def text(self) -> str:
        return self.logfile.read_text(errors="replace")

    def wait_for_log(self, text: str, timeout: float = 30) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if text in self.text():
                return
            if self.p.poll() is not None:
                raise RuntimeError(f"{self.name} exited rc={self.p.returncode}:\n{self.text()[-3000:]}")
            time.sleep(0.05)
        raise TimeoutError(f"{self.name}: '{text}' not seen in {timeout}s\n{self.text()[-2000:]}")

    def signal(self, sig: int) -> None:
        os.killpg(self.p.pid, sig)
        log(f"sent {signal.Signals(sig).name} to {self.name} pid={self.p.pid}")

    def kill9(self) -> None:
        """Real SIGKILL to the whole process group: no cleanup code runs."""
        os.killpg(self.p.pid, signal.SIGKILL)
        rc = self.p.wait(10)
        log(f"SIGKILLed {self.name} pid={self.p.pid} rc={rc}")

    def stop(self) -> None:
        if self._fh.closed:
            return
        if self.p.poll() is None:
            try:
                os.killpg(self.p.pid, signal.SIGCONT)
                os.killpg(self.p.pid, signal.SIGTERM)
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(self.p.pid, signal.SIGKILL)
                self.p.wait(10)
            except ProcessLookupError:
                pass
        self._fh.close()


# ---- databases -----------------------------------------------------------------------------------
class Cluster:
    """A PostgreSQL cluster we may create databases in: the shared disposable test cluster or our own."""

    def __init__(self, admin_dsn: str, host: str, port: int, worker_password: str):
        self.admin_dsn, self.host, self.port, self.worker_password = admin_dsn, host, port, worker_password

    def admin(self, dbname: str = "postgres") -> psycopg.Connection:
        return psycopg.connect(make_conninfo(self.admin_dsn, dbname=dbname), autocommit=True, row_factory=dict_row)

    def ensure_worker_role(self) -> None:
        with self.admin() as c:
            exists = c.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (WORKER_ROLE,)).fetchone()
            verb = "ALTER" if exists else "CREATE"
            c.execute(f"{verb} ROLE {WORKER_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS "
                      f"PASSWORD '{self.worker_password}'")

    def drop_worker_role(self) -> None:
        with self.admin() as c:
            left = c.execute("SELECT datname FROM pg_database WHERE datname LIKE 'wfspike\\_%'").fetchall()
            if not left:
                c.execute(f"DROP ROLE IF EXISTS {WORKER_ROLE}")
            else:
                log(f"not dropping {WORKER_ROLE}: databases remain {left}")

    def create_db(self, schema: bool = True) -> "SpikeDB":
        name = f"wfspike_{secrets.token_hex(4)}"
        with self.admin() as c:
            c.execute(f'CREATE DATABASE "{name}"')
            c.execute(f'REVOKE ALL ON DATABASE "{name}" FROM PUBLIC')
            c.execute(f'GRANT CONNECT ON DATABASE "{name}" TO {WORKER_ROLE}')
        db = SpikeDB(self, name)
        if schema:
            with db.conn() as c:
                api.install_schema(c, WORKER_ROLE)
        log(f"created database {name}")
        return db


class SpikeDB:
    def __init__(self, cluster: Cluster, name: str):
        self.cluster, self.name = cluster, name

    @property
    def worker_dsn(self) -> str:
        return (f"host={self.cluster.host} port={self.cluster.port} dbname={self.name} user={WORKER_ROLE} "
                f"password={self.cluster.worker_password} connect_timeout=3")

    def conn(self) -> psycopg.Connection:
        return self.cluster.admin(self.name)

    def drop(self) -> None:
        with self.cluster.admin() as c:
            c.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s", (self.name,))
            c.execute(f'DROP DATABASE IF EXISTS "{self.name}" WITH (FORCE)')
        log(f"dropped database {self.name}")

    def q(self, sql: str, params=()) -> list[dict]:
        with self.conn() as c:
            return c.execute(sql, params).fetchall()

    def run(self, run_id) -> dict:
        return self.q("SELECT * FROM wf.workflow_runs WHERE id=%s", (run_id,))[0]

    def state(self, run_id) -> str:
        return self.run(run_id)["state"]

    def wait_state(self, run_id, states, timeout: float = 30) -> float:
        states = {states} if isinstance(states, str) else set(states)
        t0 = time.monotonic()
        wait_for(lambda: self.state(run_id) in states, timeout, what=f"run {run_id} in {states}")
        return time.monotonic() - t0

    def show(self, run_id=None) -> None:
        where = "WHERE run_id=%s" if run_id else ""
        p = (run_id,) if run_id else ()
        for r in self.q(f"SELECT state, attempts, handler_version, detail FROM wf.workflow_runs "
                        f"{'WHERE id=%s' if run_id else ''} ORDER BY created_at", p):
            log(f"  run: {json.dumps(r, default=str)}")
        for t, cols in (("job_leases", "lease_owner, fencing_token, lease_expires_at"),
                        ("execution_intents", "left(operation_key,12) AS key, fencing_token, state, attempt"),
                        ("execution_results", "outcome, ticket_id, fencing_token, handler_version"),
                        ("run_events", "event, worker, fencing_token, detail")):
            rows = self.q(f"SELECT {cols} FROM wf.{t} {where} ORDER BY 1" if t == "job_leases"
                          else f"SELECT {cols} FROM wf.{t} {where} ORDER BY {'id' if t != 'execution_intents' else 'created_at'}", p)
            log(f"  wf.{t}: {len(rows)} row(s)")
            for r in rows:
                log(f"    {json.dumps(r, default=str)}")


# ---- external system and workers ---------------------------------------------------------------
def start_ticket_service(workdir: Path, *flags: str, db_name: str = "tickets.db", tag: str = "") -> tuple[Proc, str]:
    port = free_port()
    cmd = [sys.executable, "-m", "pgspike.ticket_service", "--port", str(port), "--db", str(workdir / db_name), *flags]
    p = Proc(f"ticket-service{tag}", cmd, workdir / f"ticket-service{tag}.log")
    p.wait_for_log("TICKET SERVICE READY")
    return p, f"http://127.0.0.1:{port}"


def start_worker(workdir: Path, db: SpikeDB, ticket_url: str, n: int | str, *, versions: str = "1",
                 lease_ttl: float = 3.0, env: dict | None = None, extra: list[str] | None = None) -> Proc:
    name = f"worker-{n}"
    cmd = [sys.executable, "-m", "pgspike.worker", "--name", name, "--ticket-url", ticket_url,
           "--handler-versions", versions, "--lease-ttl", str(lease_ttl), *(extra or [])]
    p = Proc(name, cmd, workdir / f"{name}.log", {"WFSPIKE_DSN": db.worker_dsn, **(env or {})})
    p.wait_for_log("WORKER READY")
    return p


def tickets(url: str) -> list[dict]:
    with urllib.request.urlopen(f"{url}/admin/tickets", timeout=5) as r:
        return json.loads(r.read())["tickets"]


# ---- a private, throwaway PostgreSQL cluster (scenario 13 only; the shared cluster is never restarted) --
class OwnCluster:
    DATA = Path("/var/tmp/wfspike-pg")
    SOCK = Path("/var/tmp/wfspike-pg-sock")
    PORT = 55499

    @staticmethod
    def as_pg(cmd: str) -> str:
        r = subprocess.run(["su", "postgres", "-s", "/bin/bash", "-c", cmd], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"{cmd}\nrc={r.returncode}\n{r.stdout}\n{r.stderr}")
        return r.stdout

    def init(self) -> None:
        self.destroy()
        for p in (self.DATA, self.SOCK):
            p.mkdir(parents=True)
            shutil.chown(p, "postgres")
        self.as_pg(f"{PG_BIN}/initdb -D {self.DATA} -U postgres --auth-local=trust --auth-host=scram-sha-256 >/dev/null")
        log(f"initdb done: {self.DATA}")

    def start(self) -> None:
        self.as_pg(f"{PG_BIN}/pg_ctl -D {self.DATA} -l {self.DATA}/server.log -w -t 60 -o "
                   f"\"-p {self.PORT} -k {self.SOCK} -c listen_addresses=127.0.0.1\" start >/dev/null")
        log(f"private cluster started on 127.0.0.1:{self.PORT} (postmaster pid {self.postmaster_pid()})")

    def postmaster_pid(self) -> int:
        return int((self.DATA / "postmaster.pid").read_text().splitlines()[0])

    def kill9(self) -> list[int]:
        """SIGKILL the postmaster and every child process at once (like the host losing the processes)."""
        pm = self.postmaster_pid()
        kids = []
        for st in Path("/proc").glob("[0-9]*/stat"):
            try:
                fields = st.read_text().rsplit(")", 1)[1].split()
                if int(fields[1]) == pm:
                    kids.append(int(st.parent.name))
            except (OSError, IndexError, ValueError):
                pass
        for pid in [pm, *kids]:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        wait_for(lambda: not Path(f"/proc/{pm}").exists() and not any(Path(f"/proc/{k}").exists() for k in kids),
                 10, what="postgres processes gone")
        log(f"SIGKILLed postmaster {pm} and {len(kids)} child processes")
        return [pm, *kids]

    def cluster(self, worker_password: str) -> "Cluster":
        return Cluster(f"host={self.SOCK} port={self.PORT} user=postgres dbname=postgres", "127.0.0.1", self.PORT,
                       worker_password)

    def server_log(self) -> str:
        return (self.DATA / "server.log").read_text(errors="replace")

    def destroy(self) -> None:
        if (self.DATA / "postmaster.pid").exists():
            try:
                self.as_pg(f"{PG_BIN}/pg_ctl -D {self.DATA} -m immediate stop >/dev/null")
            except RuntimeError as e:
                log(f"pg_ctl stop: {e}")
        shutil.rmtree(self.DATA, ignore_errors=True)
        shutil.rmtree(self.SOCK, ignore_errors=True)


def pg_dump(db: SpikeDB, out: Path) -> None:
    dsn = make_conninfo(db.cluster.admin_dsn, dbname=db.name)
    subprocess.run([str(PG_BIN / "pg_dump"), "-Fc", "-d", dsn, "-f", str(out)], check=True)


def pg_restore(dump: Path, db: SpikeDB) -> None:
    dsn = make_conninfo(db.cluster.admin_dsn, dbname=db.name)
    subprocess.run([str(PG_BIN / "pg_restore"), "--exit-on-error", "-d", dsn, str(dump)], check=True)
