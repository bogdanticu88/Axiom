"""Physical snapshot rollback drill (ADR 0010). Opt-in: AXIOM_RUN_DRILLS=1 (run by scripts/verify/restore-drill.sh).

Uses its own throwaway cluster on a free port. Stops it, copies the data directory (the "storage snapshot"),
performs an effect, restores the copied directory and restarts. The fingerprint (system identifier, timeline,
database OID) is unchanged after such a rollback, so only the external witness can detect it.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(os.environ.get("AXIOM_RUN_DRILLS") != "1", reason="set AXIOM_RUN_DRILLS=1")


def _free_port() -> int:
    import socket
    with socket.socket() as s:      # a fixed port collided with a leftover cluster once; pick a free one
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _env(tmp: Path) -> dict:
    stamp = uuid.uuid4().hex[:6]
    return {**os.environ, "AXIOM_TEST_PGDATA": f"/var/tmp/axiom-drill-pg-{stamp}", "AXIOM_TEST_PGPORT": str(_free_port()),
            "AXIOM_TEST_PGSOCK": f"/var/tmp/axiom-drill-sock-{stamp}", "AXIOM_TEST_ENV_FILE": str(tmp / "drill.env")}


def _db(env: dict, action: str) -> None:
    subprocess.run([str(ROOT / "scripts/dev/test-db.sh"), action], check=True, env=env, capture_output=True)


def _load(path: Path) -> dict:
    out = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v.strip().strip('"')
    return out


def test_storage_snapshot_rollback_is_caught_only_by_the_witness(tmp_path):
    import sys
    sys.path.insert(0, str(ROOT / "tests" / "integration"))
    from jobs_support import FileTickets, TicketHandler

    from axiom import migrate
    from axiom.db import Database, TenantContext
    from axiom.jobs import RestoreNotAcknowledged, Worker, WorkerConfig, enqueue
    from axiom.jobs.witness import FileWitness
    from axiom.provisioning import Provisioner

    env = _env(tmp_path)
    data = Path(env["AXIOM_TEST_PGDATA"])
    snapshot = Path(str(data) + "-snapshot")
    try:
        _db(env, "start")
        e = _load(Path(env["AXIOM_TEST_ENV_FILE"]))
        admin = e["AXIOM_TEST_ADMIN_DSN"]
        with psycopg.connect(admin, autocommit=True) as c:
            c.execute('CREATE DATABASE "drill" OWNER axiom_owner')
            c.execute('GRANT CONNECT ON DATABASE "drill" TO axiom_migrator, axiom_app, axiom_admin_cli')
        base = f"host=127.0.0.1 port={e['AXIOM_TEST_PORT']} dbname=drill"
        migrate.apply(f"{base} user=axiom_migrator password={e['AXIOM_TEST_MIGRATOR_PASSWORD']}")
        prov = Provisioner(f"{base} user=axiom_admin_cli password={e['AXIOM_TEST_ADMIN_CLI_PASSWORD']}")
        boot = prov.create_tenant(prov.ensure_installation("shared"), "drill", "Drill")
        app = f"{base} user=axiom_app password={e['AXIOM_TEST_APP_PASSWORD']}"
        ctx = TenantContext(boot.tenant_id, boot.system_principal_id, "workload", "drill")

        def fingerprint():
            with psycopg.connect(admin.replace("dbname=postgres", "dbname=drill"), row_factory=dict_row) as c:
                return c.execute("SELECT axiom.db_fingerprint() AS f").fetchone()["f"]

        db = Database(app, min_size=1, max_size=2)
        db.open()
        with db.tenant_tx(ctx) as conn:
            enqueue(conn, ctx, kind="test.ticket", version=1, payload={"title": "drill"})
        db.close()
        fp_before = fingerprint()
        _db(env, "stop")
        subprocess.run(["cp", "-a", str(data), str(snapshot)], check=True)        # the storage snapshot
        _db(env, "start")

        tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=False)
        witness = tmp_path / "witness"
        db = Database(app, min_size=1, max_size=2)
        db.open()
        Worker(db, [TicketHandler(tickets)], worker_id="w1",
               config=WorkerConfig(lease_seconds=1, step_timeout_seconds=2),
               witness=FileWitness(witness, "w1")).run_once()
        db.close()
        assert len(tickets.tickets()) == 1

        _db(env, "stop")
        shutil.rmtree(data)
        subprocess.run(["cp", "-a", str(snapshot), str(data)], check=True)        # roll back the volume
        _db(env, "start")
        assert fingerprint() == fp_before                                         # fingerprint blind spot
        db = Database(app, min_size=1, max_size=2)
        db.open()
        try:
            with pytest.raises(RestoreNotAcknowledged, match="behind the external witness"):
                Worker(db, [TicketHandler(tickets)], worker_id="w2",
                       config=WorkerConfig(lease_seconds=1, step_timeout_seconds=2),
                       witness=FileWitness(witness, "w2")).run_once()
            assert len(tickets.tickets()) == 1
            Worker(db, [TicketHandler(tickets)], worker_id="w3",                  # control: no witness
                   config=WorkerConfig(lease_seconds=1, step_timeout_seconds=2)).run_once()
            assert len(tickets.tickets()) == 2
        finally:
            db.close()
    finally:
        _db(env, "destroy")
        shutil.rmtree(snapshot, ignore_errors=True)
        shutil.rmtree(env["AXIOM_TEST_PGSOCK"], ignore_errors=True)
