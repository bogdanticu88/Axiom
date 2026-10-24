"""Approval use across a physical rollback (ADR 0010 amendment of 2026-10-25). Opt-in: AXIOM_RUN_DRILLS=1.

The supported restores this covers are the ones the drills exercise: the cluster is stopped and its data directory
rolled back (fingerprint unchanged, only the external witness can tell). The child test runs the real action path
against its own throwaway cluster, keeps an application session open across the rollback, and checks that the
cancellation of an execution whose intent the rollback lost never returns the use, and that a fresh execution of the
single-use approval stays refused after the recovery is acknowledged."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from .test_physical_snapshot import ROOT, _db, _env

pytestmark = pytest.mark.skipif(os.environ.get("AXIOM_RUN_DRILLS") != "1", reason="set AXIOM_RUN_DRILLS=1")


def test_cancellation_never_returns_a_use_whose_intent_a_rollback_lost(tmp_path):
    env = _env(tmp_path)
    try:
        _db(env, "start")
        child = subprocess.run(
            ["uv", "run", "--frozen", "pytest", "-q", "-s", "-p", "no:cacheprovider",
             str(ROOT / "tests/drills/action_restore_child.py")],
            env={**env, "AXIOM_DRILL_CHILD": "1"}, cwd=ROOT, capture_output=True, text=True, timeout=600)
        out = child.stdout + child.stderr
        (tmp_path / "child.log").write_text(out)
        print("\n".join(line for line in out.splitlines()
                        if line.startswith(("BEFORE_", "AFTER_")) or " passed" in line or " failed" in line))
        assert child.returncode == 0, out[-4000:]
        assert "1 passed" in out
    finally:
        _db(env, "destroy")
        shutil.rmtree(env["AXIOM_TEST_PGSOCK"], ignore_errors=True)
        shutil.rmtree(str(Path(env["AXIOM_TEST_PGDATA"])) + "-actions-snapshot", ignore_errors=True)
