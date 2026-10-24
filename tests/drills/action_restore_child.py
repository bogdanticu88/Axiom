"""Child of test_action_restore_boundary.py: runs against the throwaway cluster that test started (AXIOM_TEST_ENV_FILE
points at it) and stops, rolls back and restarts that cluster itself. Not collected on its own (the name does not
start with ``test_``), and skipped unless AXIOM_DRILL_CHILD=1."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import psycopg
import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(os.environ.get("AXIOM_DRILL_CHILD") != "1", reason="run by the restore drill")


def _cluster(action: str) -> None:
    subprocess.run([str(ROOT / "scripts/dev/test-db.sh"), action], check=True, capture_output=True)


def test_approval_use_across_a_physical_rollback(db, dbinfo, world, ctx_for, run, tmp_path):
    from integration.test_actions import Env
    from axiom.domains.actions.jobs import ActionExecuteHandler
    from axiom.errors import Conflict
    from axiom.jobs import RestoreNotAcknowledged, Worker, WorkerConfig
    from axiom.jobs.witness import FileWitness
    from axiom.provisioning import Provisioner

    env = Env(db, world, ctx_for, dbinfo, run)
    config = WorkerConfig(lease_seconds=30, step_timeout_seconds=60, max_backoff_seconds=0.01)
    witness_dir = tmp_path / "witness"
    data = Path(os.environ["AXIOM_TEST_PGDATA"])
    snapshot = Path(str(data) + "-actions-snapshot")

    def worker(name):
        return Worker(db, [ActionExecuteHandler(env.adapter)], worker_id=name, config=config,
                      witness=FileWitness(witness_dir, name))

    def state(e, a):
        with psycopg.connect(dbinfo.admin_dsn) as c:
            ex = c.execute("SELECT state FROM axiom.action_executions WHERE id = %s", (e["id"],)).fetchone()[0]
            job = c.execute("SELECT state, operator_reason FROM axiom.jobs WHERE id = %s", (e["job_id"],)).fetchone()
            res = c.execute("SELECT status FROM axiom.approval_reservations WHERE execution_id = %s",
                            (e["id"],)).fetchone()[0]
            uses = c.execute("SELECT uses_reserved, uses_released FROM axiom.approvals WHERE id = %s",
                             (a["id"],)).fetchone()
            intent = c.execute("SELECT state FROM axiom.effect_intents WHERE operation_key = %s",
                               (e["external_operation_id"],)).fetchone()
        return {"execution": ex, "job": job[0], "reservation": res, "uses": tuple(uses),
                "intent": intent[0] if intent else None, "tickets": len(env.fake.issues)}, job[1]

    p = env.propose()
    a = env.approve(p, max_uses=1)
    e = env.execute(p, a)

    _cluster("stop")                                            # storage snapshot: execution requested, no intent yet
    shutil.rmtree(snapshot, ignore_errors=True)
    subprocess.run(["cp", "-a", str(data), str(snapshot)], check=True)
    _cluster("start")
    try:
        # the pool's connections died with the server; checkout replaces them (check_connection)
        worker("w1").run_once(only_tenants={world.a.id})
        before, _ = state(e, a)
        print("BEFORE_ROLLBACK", before)
        assert before == {"execution": "succeeded", "job": "succeeded", "reservation": "consumed", "uses": (1, 0),
                          "intent": "succeeded", "tickets": 1}

        survivor = psycopg.connect(dbinfo.app_dsn)                # an application session open across the rollback
        survivor.execute("SELECT 1")                              # (inside a transaction: autocommit is off)
        _cluster("stop")
        shutil.rmtree(data)
        subprocess.run(["cp", "-a", str(snapshot), str(data)], check=True)      # roll the volume back
        _cluster("start")
        with pytest.raises(psycopg.OperationalError):
            survivor.execute("SELECT 1")                          # the session did not survive the restart
        survivor.close()

        rolled, _ = state(e, a)
        print("AFTER_ROLLBACK", rolled)
        assert rolled == {"execution": "prepared", "job": "queued", "reservation": "reserved", "uses": (1, 0),
                          "intent": None, "tickets": 1}           # the database lost the intent; the ticket exists

        env.svc("analyst", lambda s: s.cancel_execution(e["id"], "no longer wanted"))
        after_cancel, _ = state(e, a)
        print("AFTER_API_CANCEL", after_cancel)
        with pytest.raises(RestoreNotAcknowledged, match="behind the external witness"):
            worker("w2").run_once(only_tenants={world.a.id})
        claimed = worker("w3").claim(ctx_for("system"))           # a worker that passed its preflight before
        after_claim, reason = state(e, a)
        print("AFTER_WORKER_CLAIM", after_claim, "|", reason, "| claimed:", len(claimed))

        Provisioner(dbinfo.admin_cli_dsn).acknowledge_recovery(
            "drill-operator", "physical rollback; external effects not yet reconciled", FileWitness(witness_dir, "op"))
        try:
            e2 = env.execute(p, a)
            second = "allowed"
            for _ in range(4):
                worker("w4").run_once(only_tenants={world.a.id})
        except Conflict as exc:
            second = f"refused:{exc.code}"
        final, _ = state(e, a)
        print("AFTER_ACKNOWLEDGEMENT", final, "| second execution:", second)

        assert after_cancel == {**rolled}, "the API changed the reservation without restore-witness clearance"
        assert claimed == [] and after_claim == {**rolled, "execution": "reconciling", "job": "needs_operator"}
        assert "behind the external witness" in reason
        assert second == "refused:approval_exhausted"
        assert final["tickets"] == 1 and final["reservation"] == "reserved" and final["uses"] == (1, 0)
    finally:
        shutil.rmtree(snapshot, ignore_errors=True)
