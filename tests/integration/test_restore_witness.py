"""Restore detection: what the database fingerprint sees, what it cannot see, and the external witness (ADR 0010).

Each test builds its own scratch database (migrations, one tenant) so it can drop and recreate it with the same
OID, which makes the restored database's fingerprint identical to the original: the case a storage snapshot
rollback produces on the same cluster. A physical data-directory snapshot drill is in tests/drills/.
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

from axiom.db import Database
from axiom.jobs import RestoreNotAcknowledged, Worker, WorkerConfig, enqueue
from axiom.jobs.witness import FileWitness, database_watermark

from .jobs_support import FileTickets, TicketHandler

pytestmark = pytest.mark.db
FAST = WorkerConfig(lease_seconds=1.0, step_timeout_seconds=2.0, max_backoff_seconds=0.01)


class Scratch:
    def __init__(self, dbinfo, tmp_path: Path):
        self.dbinfo = dbinfo
        self.name = f"axiom_restore_{uuid.uuid4().hex[:8]}"
        self.server_admin = dbinfo.admin_dsn.replace(f"dbname={dbinfo.name}", "dbname=postgres")
        params = psycopg.conninfo.conninfo_to_dict(dbinfo.admin_dsn)
        self.env = {**os.environ, "PGHOST": params["host"], "PGPORT": str(params.get("port", 5432)),
                    "PGUSER": params["user"]}
        self.tmp = tmp_path
        self.create()
        from axiom import migrate
        migrate.apply(self.dsn("migrator"))
        from axiom.provisioning import Provisioner
        prov = Provisioner(self.dsn("admin_cli"))
        boot = prov.create_tenant(prov.ensure_installation("shared"), f"r-{uuid.uuid4().hex[:6]}", "Restore drill")
        self.tenant, self.system, self.root = boot.tenant_id, boot.system_principal_id, boot.root_scope_id
        provider = prov.ensure_identity_provider("https://idp.drill.invalid", "axiom-drill")
        self.operator = prov.create_principal("drill operator", provider_id=provider, subject=f"op-{uuid.uuid4()}")
        prov.add_membership(self.tenant, self.operator)
        prov.bootstrap_role(self.tenant, self.operator, "policy_admin", self.root, "restore drill operator")

    def dsn(self, who: str) -> str:
        base = {"migrator": self.dbinfo.migrator_dsn, "app": self.dbinfo.app_dsn,
                "admin_cli": self.dbinfo.admin_cli_dsn, "admin": self.dbinfo.admin_dsn}[who]
        return base.replace(f"dbname={self.dbinfo.name}", f"dbname={self.name}")

    def create(self, oid: int | None = None):
        with psycopg.connect(self.server_admin, autocommit=True) as c:
            c.execute(f'CREATE DATABASE "{self.name}" OWNER axiom_owner' + (f" OID = {oid}" if oid else ""))
            c.execute(f'REVOKE ALL ON DATABASE "{self.name}" FROM PUBLIC')
            c.execute(f'GRANT CONNECT ON DATABASE "{self.name}" TO axiom_migrator, axiom_app, axiom_relay_app, axiom_admin_cli')

    def oid(self) -> int:
        with psycopg.connect(self.server_admin, autocommit=True) as c:
            return c.execute("SELECT oid FROM pg_database WHERE datname = %s", (self.name,)).fetchone()[0]

    def dump(self) -> Path:
        out = self.tmp / f"{self.name}-{uuid.uuid4().hex[:4]}.dump"
        subprocess.run(["pg_dump", "-Fc", "-f", str(out), "-d", self.name], check=True, env=self.env)
        return out

    def restore_same_oid(self, dump: Path):
        oid = self.oid()
        self.drop()
        self.create(oid)
        subprocess.run(["pg_restore", "--exit-on-error", "-d", self.name, str(dump)], check=True, env=self.env)

    def drop(self):
        with psycopg.connect(self.server_admin, autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{self.name}" WITH (FORCE)')

    def fingerprint(self) -> str:
        with psycopg.connect(self.dsn("admin"), row_factory=dict_row) as c:
            return c.execute("SELECT axiom.db_fingerprint() AS f").fetchone()["f"]

    def app(self) -> Database:
        db = Database(self.dsn("app"), min_size=1, max_size=3, name="scratch")
        db.open()
        return db

    def ctx(self):
        from axiom.db import TenantContext
        return TenantContext(self.tenant, self.system, "workload", f"drill-{uuid.uuid4()}")

    def operator_ctx(self):
        from axiom.db import TenantContext
        return TenantContext(self.tenant, self.operator, "human", f"drill-op-{uuid.uuid4()}")

    def enqueue_ticket(self, db: Database) -> uuid.UUID:
        ctx = self.ctx()
        with db.tenant_tx(ctx) as conn:
            return enqueue(conn, ctx, kind="test.ticket", version=1, payload={"title": "restore drill"})["id"]


@pytest.fixture()
def scratch(dbinfo, tmp_path):
    s = Scratch(dbinfo, tmp_path)
    yield s
    s.drop()


def test_same_identity_restore_fools_the_fingerprint_but_not_the_witness(scratch, tmp_path):
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=False)
    witness_dir = tmp_path / "witness"
    db = scratch.app()
    scratch.enqueue_ticket(db)
    backup = scratch.dump()                                     # backup taken while the job is still queued
    fp_before = scratch.fingerprint()
    Worker(db, [TicketHandler(tickets)], worker_id="w1", config=FAST,
           witness=FileWitness(witness_dir, "w1")).run_once()
    assert len(tickets.tickets()) == 1
    db.close()

    scratch.restore_same_oid(backup)                            # roll the database back
    assert scratch.fingerprint() == fp_before                   # blind spot: the fingerprint is identical
    db = scratch.app()
    try:
        with db.unbound_tx() as conn:
            assert database_watermark(conn) == 0                # restored sequence predates the effect
        guarded = Worker(db, [TicketHandler(tickets)], worker_id="w2", config=FAST,
                         witness=FileWitness(witness_dir, "w2"))
        with pytest.raises(RestoreNotAcknowledged, match="behind the external witness"):
            guarded.run_once()
        assert len(tickets.tickets()) == 1                      # nothing repeated
        # control: the same restored database without a witness repeats the effect
        Worker(db, [TicketHandler(tickets)], worker_id="w3", config=FAST).run_once()
        assert len(tickets.tickets()) == 2
    finally:
        db.close()


def test_witness_restored_together_with_the_database_is_blind(scratch, tmp_path):
    """A marker restored alongside the database is not sufficient: if the witness is rolled back too, the
    rollback is invisible and the effect repeats. The witness must live in a separate backup domain."""
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=False)
    witness_dir, witness_backup = tmp_path / "witness", tmp_path / "witness-backup"
    db = scratch.app()
    scratch.enqueue_ticket(db)
    Worker(db, [], worker_id="w0", config=FAST, witness=FileWitness(witness_dir, "w0")).run_once()
    backup = scratch.dump()
    shutil.copytree(witness_dir, witness_backup)               # "snapshot" of the witness at the same moment
    Worker(db, [TicketHandler(tickets)], worker_id="w1", config=FAST,
           witness=FileWitness(witness_dir, "w1")).run_once()
    db.close()
    scratch.restore_same_oid(backup)
    shutil.rmtree(witness_dir)
    shutil.copytree(witness_backup, witness_dir)               # restore the witness too
    db = scratch.app()
    try:
        Worker(db, [TicketHandler(tickets)], worker_id="w2", config=FAST,
               witness=FileWitness(witness_dir, "w2")).run_once()
    finally:
        db.close()
    assert len(tickets.tickets()) == 2                          # undetected duplicate: documented blind spot


def test_lost_witness_is_detected_and_acknowledgement_reseeds_it(scratch, tmp_path):
    from axiom.provisioning import Provisioner
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=False)
    witness_dir = tmp_path / "witness"
    db = scratch.app()
    try:
        scratch.enqueue_ticket(db)
        Worker(db, [TicketHandler(tickets)], worker_id="w1", config=FAST,
               witness=FileWitness(witness_dir, "w1")).run_once()
        shutil.rmtree(witness_dir)
        guarded = Worker(db, [TicketHandler(tickets)], worker_id="w2", config=FAST,
                         witness=FileWitness(witness_dir, "w2"))
        with pytest.raises(RestoreNotAcknowledged, match="witness is empty"):
            guarded.run_once()
        prov = Provisioner(scratch.dsn("admin_cli"))
        status = prov.recovery_status(FileWitness(witness_dir, "op"))
        assert status["witness_problem"] and status["database_watermark"] >= 1
        prov.acknowledge_recovery("drill-operator", "witness volume replaced; no effects pending",
                                  FileWitness(witness_dir, "op"))
        guarded.run_once()                                       # runs again
    finally:
        db.close()


def test_acknowledging_a_rollback_moves_the_sequence_past_the_witness(scratch, tmp_path):
    from axiom.provisioning import Provisioner
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=False)
    witness_dir = tmp_path / "witness"
    db = scratch.app()
    scratch.enqueue_ticket(db)
    backup = scratch.dump()
    Worker(db, [TicketHandler(tickets)], worker_id="w1", config=FAST, witness=FileWitness(witness_dir, "w1")).run_once()
    db.close()
    scratch.restore_same_oid(backup)
    prov = Provisioner(scratch.dsn("admin_cli"))
    prov.acknowledge_recovery("drill-operator", "reconciled: TICKET-1 exists for the queued job; job cancelled",
                              FileWitness(witness_dir, "op"))
    db = scratch.app()
    try:
        with db.unbound_tx() as conn:
            assert database_watermark(conn) >= FileWitness(witness_dir, "x").high_water()
        Worker(db, [], worker_id="w2", config=FAST, witness=FileWitness(witness_dir, "w2")).preflight()
    finally:
        db.close()


def test_witness_write_failure_means_nothing_is_sent(scratch, tmp_path):
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=False)

    class BrokenWitness(FileWitness):
        def advance(self, watermark):
            raise OSError("witness volume unavailable")
    db = scratch.app()
    try:
        job_id = scratch.enqueue_ticket(db)
        Worker(db, [TicketHandler(tickets)], worker_id="w1", config=FAST,
               witness=BrokenWitness(tmp_path / "witness", "w1")).run_once()
        assert tickets.tickets() == []
        with db.tenant_tx(scratch.ctx()) as conn:
            job = conn.execute("SELECT state, last_error FROM axiom.jobs WHERE id = %s", (job_id,)).fetchone()
            intent = conn.execute("SELECT state FROM axiom.effect_intents WHERE job_id = %s", (job_id,)).fetchone()
        assert job["state"] == "queued" and "witness volume unavailable" in job["last_error"]
        assert intent["state"] == "prepared"                     # never marked executing, so a retry is safe
    finally:
        db.close()


def test_acknowledging_a_restore_does_not_authorise_replay(scratch, tmp_path):
    """After a same-fingerprint rollback is acknowledged, the job carried across the restore still parks; only an
    explicit reconciliation of that job lets it finish. Jobs created after the acknowledgement run normally."""
    from axiom.access import Authorizer
    from axiom.jobs import JobOperations
    from axiom.provisioning import Provisioner
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=False)
    witness_dir = tmp_path / "witness"
    db = scratch.app()
    job_id = scratch.enqueue_ticket(db)
    backup = scratch.dump()
    Worker(db, [TicketHandler(tickets)], worker_id="w1", config=FAST, witness=FileWitness(witness_dir, "w1")).run_once()
    db.close()
    assert len(tickets.tickets()) == 1
    scratch.restore_same_oid(backup)
    Provisioner(scratch.dsn("admin_cli")).acknowledge_recovery(
        "drill-operator", "restore acknowledged; carried jobs still need reconciliation", FileWitness(witness_dir, "op"))
    db = scratch.app()
    try:
        w = Worker(db, [TicketHandler(tickets)], worker_id="w2", config=FAST, witness=FileWitness(witness_dir, "w2"))
        w.run_once()
        with db.tenant_tx(scratch.ctx()) as conn:
            job = conn.execute("SELECT state, operator_reason FROM axiom.jobs WHERE id = %s", (job_id,)).fetchone()
        assert job["state"] == "needs_operator" and "predates the latest recovery acknowledgement" in \
            job["operator_reason"]
        assert len(tickets.tickets()) == 1                           # acknowledgement did not authorise a replay
        w.run_once()                                                 # nor does running again
        assert len(tickets.tickets()) == 1
        op = scratch.operator_ctx()
        with db.tenant_tx(op) as conn:
            JobOperations(conn, op, Authorizer(conn, op)).retry(job_id, "just try again")
        w.run_once()                                                 # a plain retry is not a reconciliation
        assert len(tickets.tickets()) == 1
        with db.tenant_tx(op) as conn:
            JobOperations(conn, op, Authorizer(conn, op)).resolve_effect(
                job_id, resolution="adopt", rationale="TICKET-1 exists for this job", external_ref="TICKET-1")
        w.run_once()                                                 # the re-queued job finishes from the adopted intent
        with db.tenant_tx(scratch.ctx()) as conn:
            assert conn.execute("SELECT state FROM axiom.jobs WHERE id = %s", (job_id,)).fetchone()["state"] == "succeeded"
        new_job = scratch.enqueue_ticket(db)                         # created after the acknowledgement
        w.run_once()
        with db.tenant_tx(scratch.ctx()) as conn:
            assert conn.execute("SELECT state FROM axiom.jobs WHERE id = %s", (new_job,)).fetchone()["state"] == \
                "succeeded"
        assert len(tickets.tickets()) == 2
    finally:
        db.close()


def test_unreadable_witness_retries_instead_of_sending(scratch, tmp_path):
    from axiom.jobs.witness import WitnessUnavailable
    tickets = FileTickets(tmp_path / "t.jsonl", lookup_supported=False)

    class Down(FileWitness):
        def high_water(self):
            raise WitnessUnavailable("storage unreachable")
    db = scratch.app()
    try:
        job_id = scratch.enqueue_ticket(db)
        handler = TicketHandler(tickets)
        w = Worker(db, [handler], worker_id="w1", config=FAST, witness=Down(tmp_path / "w", "w1"))
        with pytest.raises(WitnessUnavailable):
            w.preflight()                                             # the worker's pass stops early
        from axiom.jobs.core import JobContext
        from axiom.jobs.effects import EffectGate
        [(job, token)] = w.claim(scratch.ctx())
        jc = JobContext(db, scratch.ctx(), job, token, "w1", Down(tmp_path / "w", "w1"))
        out = EffectGate(jc).run(tickets, {"title": "x"}, lambda c: None)
        assert type(out.step).__name__ == "Retry" and "witness unavailable" in out.step.error
        assert tickets.tickets() == []
    finally:
        db.close()
