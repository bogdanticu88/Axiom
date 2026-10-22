"""Scheduled risk-acceptance expiry sweep (A11) on the job runner."""
from __future__ import annotations

from ...access import Authorizer
from ...jobs import Done, JobContext
from .risk import risk_sweep
from .service import expire_risk_acceptances

KIND = "cases.risk_expiry_sweep"


class RiskExpirySweepHandler:
    kind = KIND
    versions = frozenset({1})
    current_version = 1

    def step(self, jc: JobContext):
        with jc.db.tenant_tx(jc.ctx) as conn:
            jc.fenced(conn)      # the sweep's writes commit only while this worker holds the lease
            authz = Authorizer(conn, jc.ctx)
            swept = risk_sweep(conn, jc.ctx, authz)
            expired = expire_risk_acceptances(conn, jc.ctx, authz)
        return Done({"expired": [str(x) for x in expired], "lapsed": [str(x) for x in swept["lapsed"]],
                     "reassessment_notices": [str(x) for x in swept["reassessment_notices"]]})
