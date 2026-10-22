"""Opt-in: one investigation against the real Anthropic Messages API.

Skipped unless all of these are set (running it sends case data from the test fixture to an external service, so
it needs explicit authorisation):

    AXIOM_TEST_REAL_MODEL=1
    AXIOM_TEST_ANTHROPIC_MODEL=<model id>
    ANTHROPIC_API_KEY=<key>                     # read through secretref:env/ANTHROPIC_API_KEY

Status in this project: **never run** (no credentials or external access authorised). Until it has been run and its
result recorded in docs/VERIFICATION.md, the real-provider path is unverified.
"""
from __future__ import annotations

import json
import os

import pytest

from axiom.investigation.runner import InvestigationHandler

from .investigation_support import inv, trivy_doc  # noqa: F401
from .test_ingestion import importer, ingest  # noqa: F401

pytestmark = [pytest.mark.db, pytest.mark.skipif(
    not (os.environ.get("AXIOM_TEST_REAL_MODEL") == "1" and os.environ.get("AXIOM_TEST_ANTHROPIC_MODEL")
         and os.environ.get("ANTHROPIC_API_KEY")),
    reason="real-provider test is opt-in (AXIOM_TEST_REAL_MODEL=1, AXIOM_TEST_ANTHROPIC_MODEL, ANTHROPIC_API_KEY)")]

ORIGIN = "https://api.anthropic.com"


def test_real_provider_investigation(inv):
    from axiom.access import Authorizer
    from axiom.investigation.service import InvestigationService
    inv.importer(json.dumps(trivy_doc()).encode(), "trivy_json")
    case = inv.case_for()
    dest = frozenset({ORIGIN})

    def svc(who, fn):
        ctx = inv.ctx_for(who)
        with inv.db.tenant_tx(ctx) as conn:
            return fn(InvestigationService(conn, ctx, Authorizer(conn, ctx), model_destinations=dest))
    r = svc("admin", lambda s: s.propose_route(
        name="anthropic-optin", provider="anthropic_messages", model=os.environ["AXIOM_TEST_ANTHROPIC_MODEL"],
        endpoint=ORIGIN, region="provider-default", max_classification="internal",
        credential_ref="secretref:env/ANTHROPIC_API_KEY", rationale="opt-in verification", max_retries=1,
        timeout_seconds=120))
    svc("auditor", lambda s: s.approve_route(r["id"], rationale="opt-in verification"))
    run = svc("analyst", lambda s: s.start(case["id"], questions=["Is the reported vulnerability present in the "
                                                                    "deployed image?"], route="anthropic-optin",
                                           budget={"max_rounds": 3, "max_model_calls": 4}))
    h = InvestigationHandler(store=inv.store, model_destinations=dest, retry_delay_seconds=2)
    got = inv.drive(run["id"], handler=h)
    print(json.dumps({k: got[k] for k in ("status", "outcome_reason", "model_calls", "input_tokens", "output_tokens")},
                     default=str))
    assert got["status"] in ("completed", "incomplete")
    assert all(c["validation"] in ("references_checked", "downgraded", "rejected") for c in got["claims"])
