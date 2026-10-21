import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness import ALL_PROCS, TEMPORAL_BIN, TemporalServer, fresh_dir  # noqa: E402


@pytest.fixture(scope="session")
def temporal_server():
    if not TEMPORAL_BIN.exists():
        pytest.fail(f"{TEMPORAL_BIN} missing: run scripts/fetch_temporal_cli.sh first")
    d = fresh_dir("shared-server")
    srv = TemporalServer(d, d / "temporal.db").start()
    yield srv
    srv.proc.stop()


@pytest.fixture(autouse=True)
def _reap_test_processes():
    """Stop every process a test started (workers, ticket services, private servers), pass or fail."""
    before = len(ALL_PROCS)
    yield
    for p in ALL_PROCS[before:]:
        p.stop()
