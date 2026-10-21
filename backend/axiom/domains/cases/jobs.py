"""Scheduled risk-acceptance expiry sweep (A11) on the job runner."""
from __future__ import annotations

from ...access import Authorizer
from ...jobs import Done, JobContext
from .service import expire_risk_acceptances

KIND = "cases.risk_expiry_sweep"


class RiskExpirySweepHandler:
    kind = KIND
    versions = frozenset({1})
    current_version = 1

    def step(self, jc: JobContext):
        with jc.db.tenant_tx(jc.ctx) as conn:
            jc.fenced(conn)      # the sweep's writes commit only while this worker holds the lease
            expired = expire_risk_acceptances(conn, jc.ctx, Authorizer(conn, jc.ctx))
        return Done({"expired": [str(x) for x in expired]})
