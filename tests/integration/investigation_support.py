"""Shared fixtures for investigation tests.

Findings come from importing the real Trivy fixture (or labelled modifications of it). Model routes use the
deterministic fake provider (``fake-rules-v1`` or ``fake-adversarial:<behaviour>``), which is a rule-based stand-in,
not a language model.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable

import pytest

from axiom.access import Authorizer
from axiom.investigation.runner import InvestigationHandler
from axiom.investigation.service import TERMINAL, InvestigationService
from axiom.jobs import Worker, WorkerConfig

from .test_ingestion import TRIVY, importer, ingest  # noqa: F401 - fixtures


def trivy_doc() -> dict:
    return json.loads(TRIVY.read_bytes())


@dataclass
class Inv:
    db: object
    world: object
    ctx_for: Callable
    run: Callable
    importer: Callable
    store: object
    admin_conn: object
    routes: dict = field(default_factory=dict)
    handler: InvestigationHandler | None = None

    def svc(self, who: str, fn):
        ctx = self.ctx_for(who)
        with self.db.tenant_tx(ctx) as conn:
            return fn(InvestigationService(conn, ctx, Authorizer(conn, ctx)))

    def route(self, model: str = "fake-rules-v1", *, name: str | None = None, max_classification="confidential",
              retries: int = 1, timeout: int = 5) -> dict:
        name = name or model.replace(":", "-").replace("_", "-")
        if name in self.routes:
            return self.routes[name]
        r = self.svc("admin", lambda s: s.propose_route(
            name=name, provider="deterministic_fake", model=model, endpoint=f"fake://{name}", region="local",
            max_classification=max_classification, rationale="test route (deterministic fake)",
            max_retries=retries, timeout_seconds=timeout))
        r = self.svc("auditor", lambda s: s.approve_route(r["id"], rationale="reviewed"))
        self.routes[name] = r
        return r

    def start(self, case_id, model="fake-rules-v1", *, who="analyst", questions=None, **kw) -> dict:
        r = self.route(model, **{k: kw.pop(k) for k in ("max_classification", "retries", "timeout") if k in kw})
        return self.svc(who, lambda s: s.start(case_id, questions=questions or ["Is the reported vulnerability present "
                                                                               "in the deployed image?"],
                                               route=r["name"], **kw))

    def drive(self, run_id, *, rounds: int = 40, handler: InvestigationHandler | None = None) -> dict:
        h = handler or self.handler or InvestigationHandler(store=self.store, retry_delay_seconds=0)
        w = Worker(self.db, [h], config=WorkerConfig(lease_seconds=10, step_timeout_seconds=10))
        for _ in range(rounds):
            got = self.get(run_id)
            if got["status"] in TERMINAL:
                return got
            w.run_once(only_tenants={self.world.a.id})
        return self.get(run_id)

    def get(self, run_id) -> dict:
        return self.svc("analyst", lambda s: s.get(run_id))

    def case_for(self, vuln: str | None = None, severity: bool = True) -> dict:
        return self.run(self.ctx_for("analyst"), lambda s: s.conn.execute(
            """SELECT c.*, o.vulnerability_ref, av.asset_id FROM axiom.finding_cases c
                 JOIN axiom.case_occurrence_links l ON l.case_id = c.id JOIN axiom.finding_occurrences o ON o.id = l.occurrence_id
                 JOIN axiom.asset_versions av ON av.id = o.asset_version_id
                WHERE (%s::text IS NULL OR o.vulnerability_ref = %s) AND (NOT %s OR o.source_severity IS NOT NULL)
                ORDER BY o.vulnerability_ref LIMIT 1""", (vuln, vuln, severity)).fetchone())

    def investigate_case(self, case):
        """Move a case to investigating so it can be assessed afterwards."""
        return self.run(self.ctx_for("analyst"), lambda s: s.cases.start_investigation(
            case["id"], case["record_version"], "investigate"))


@pytest.fixture()
def inv(db, world, ctx_for, run, importer, object_store, dbinfo, admin_conn):  # noqa: F811
    from axiom.provisioning import Provisioner
    p = Provisioner(dbinfo.admin_cli_dsn)
    for who in ("admin", "auditor"):
        p.bootstrap_role(world.a.id, world[who], "policy_admin", world.a.root, "investigation tests: model routes")
    return Inv(db, world, ctx_for, run, importer, object_store, admin_conn)
