"""Fixtures for the security/recovery/tenancy tests (imported into those test modules)."""

from __future__ import annotations

import pytest

from harness import TEMPORAL_BIN, fresh_dir
from secure_harness import DevServer

SEC_SERVER_FLAGS = ["--search-attribute", "TenantId=Keyword", "--namespace", "tenant-a", "--namespace", "tenant-b"]


@pytest.fixture(scope="module")
def sec_server(request):
    if not TEMPORAL_BIN.exists():
        pytest.fail(f"{TEMPORAL_BIN} missing: run scripts/fetch_temporal_cli.sh first")
    d = fresh_dir(f"sec-server-{request.module.__name__}")
    srv = DevServer(d, d / "temporal.db", SEC_SERVER_FLAGS).start()
    yield srv
    srv.proc.stop()
