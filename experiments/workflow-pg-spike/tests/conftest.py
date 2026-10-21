import os
import secrets
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness import ALL_PROCS, Cluster, load_env_test, log  # noqa: E402


@pytest.fixture(scope="session")
def cluster():
    """The shared disposable test cluster (scripts/dev/test-db.sh). We only create wfspike_* databases
    and the wfspike_worker role in it, and remove both afterwards."""
    env = load_env_test()
    c = Cluster(env["AXIOM_TEST_ADMIN_DSN"], env["AXIOM_TEST_HOST"], int(env["AXIOM_TEST_PORT"]), secrets.token_urlsafe(18))
    c.ensure_worker_role()
    yield c
    c.drop_worker_role()


@pytest.fixture
def db(cluster):
    d = cluster.create_db()
    yield d
    for p in ALL_PROCS:  # workers must be gone before the database can be dropped cleanly
        p.stop()
    if os.environ.get("WFSPIKE_KEEP_DB") == "1":
        log(f"keeping database {d.name}")
    else:
        d.drop()


@pytest.fixture(autouse=True)
def _reap_test_processes():
    before = len(ALL_PROCS)
    yield
    for p in ALL_PROCS[before:]:
        p.stop()
