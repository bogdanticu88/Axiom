"""API routes for the action protocol, two-step risk acceptance and job operations.

Idempotency (API-07): ``Idempotency-Key`` is **required** on execution requests (the external-effect command) and
honoured on the other commands when sent. Replays return the stored response with ``Idempotent-Replayed: true``.
"""

from collections.abc import Callable
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Header, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from .. import idempotency
from ..access import Authorizer
from ..db import Database, TenantContext
from ..domains.actions.service import ActionService
from ..domains.cases.risk import RiskService
from ..errors import ValidationFailed
from ..jobs import JobOperations
from . import schemas as s


def register(api: APIRouter, database: Database, Ctx) -> None:
    def tx(ctx: TenantContext, fn: Callable[[Any, Authorizer], Any]) -> Any:
        with database.tenant_tx(ctx) as conn:
            return jsonable_encoder(fn(conn, Authorizer(conn, ctx)))

    def command(ctx: TenantContext, endpoint: str, key: str | None, params: dict, body: Any,
                fn: Callable[[Any, Authorizer], Any], *, status: int = 200, required: bool = False):
        if key is None:
            if required:
                raise ValidationFailed("Idempotency-Key header is required for this command",
                                       code="idempotency_key_required")
            return JSONResponse(status_code=status, content=tx(ctx, fn))
        digest = idempotency.request_digest(endpoint, {k: str(v) for k, v in params.items()},
                                            jsonable_encoder(body))
        with database.tenant_tx(ctx) as conn:
            authz = Authorizer(conn, ctx)
            code, payload, replayed = idempotency.run(conn, ctx, endpoint=endpoint, key=key, digest=digest,
                                                      status=status,
                                                      fn=lambda: jsonable_encoder(fn(conn, authz)))
        return JSONResponse(status_code=code, content=payload,
                            headers={"Idempotent-Replayed": "true" if replayed else "false"})

    Key = Annotated[str | None, Header(alias="Idempotency-Key")]

    def actions(conn, authz, ctx):
        return ActionService(conn, ctx, authz)

    # -------------------------------------------------------------------------------- proposals
    @api.post("/action-proposals", status_code=201)
    def create_proposal(ctx: Ctx, body: s.CreateProposal, key: Key = None):
        return command(ctx, "POST /action-proposals", key, {}, body, lambda c, a: actions(c, a, ctx).propose(
            case_id=body.case_id, effect=body.effect_class, connection_id=body.connection_id, payload=body.payload,
            verification_criteria=body.verification_criteria, expires_at=body.expires_at,
            rollback_guidance=body.rollback_guidance), status=201)

    @api.get("/action-proposals/{proposal_id}")
    def get_proposal(ctx: Ctx, proposal_id: UUID):
        return tx(ctx, lambda c, a: actions(c, a, ctx).get(proposal_id))

    @api.post("/action-proposals/{proposal_id}/versions", status_code=201)
    def revise_proposal(ctx: Ctx, proposal_id: UUID, body: s.ReviseProposal, key: Key = None):
        return command(ctx, "POST /action-proposals/{id}/versions", key, {"proposal_id": proposal_id}, body,
                       lambda c, a: actions(c, a, ctx).revise(
                           proposal_id, body.expected_version, payload=body.payload,
                           verification_criteria=body.verification_criteria, expires_at=body.expires_at,
                           rollback_guidance=body.rollback_guidance), status=201)

    @api.post("/action-proposals/{proposal_id}/withdraw")
    def withdraw_proposal(ctx: Ctx, proposal_id: UUID, body: s.Reason):
        return tx(ctx, lambda c, a: actions(c, a, ctx).withdraw(proposal_id, body.reason))

    @api.post("/action-proposals/{proposal_id}/versions/{version}/decisions", status_code=201)
    def decide(ctx: Ctx, proposal_id: UUID, version: int, body: s.Decide, key: Key = None):
        return command(ctx, "POST /action-proposals/{id}/versions/{v}/decisions", key,
                       {"proposal_id": proposal_id, "version": version}, body,
                       lambda c, a: actions(c, a, ctx).decide(
                           proposal_id, version, decision=body.decision, rationale=body.rationale,
                           valid_until=body.valid_until, max_uses=body.max_uses), status=201)

    @api.post("/approvals/{approval_id}/revoke")
    def revoke_approval(ctx: Ctx, approval_id: UUID, body: s.Reason):
        return tx(ctx, lambda c, a: actions(c, a, ctx).revoke_approval(approval_id, body.reason))

    @api.post("/action-proposals/{proposal_id}/versions/{version}/executions", status_code=202)
    def request_execution(ctx: Ctx, proposal_id: UUID, version: int, body: s.RequestExecution, key: Key = None):
        return command(ctx, "POST /action-proposals/{id}/versions/{v}/executions", key,
                       {"proposal_id": proposal_id, "version": version}, body,
                       lambda c, a: actions(c, a, ctx).request_execution(proposal_id, version, body.approval_id),
                       status=202, required=True)

    @api.get("/action-executions/{execution_id}")
    def get_execution(ctx: Ctx, execution_id: UUID):
        return tx(ctx, lambda c, a: actions(c, a, ctx).get_execution(execution_id))

    @api.post("/action-executions/{execution_id}/cancel")
    def cancel_execution(ctx: Ctx, execution_id: UUID, body: s.Reason):
        return tx(ctx, lambda c, a: actions(c, a, ctx).cancel_execution(execution_id, body.reason))

    @api.post("/action-executions/{execution_id}/reconcile")
    def reconcile_execution(ctx: Ctx, execution_id: UUID, body: s.Resolve):
        return tx(ctx, lambda c, a: actions(c, a, ctx).reconcile(
            execution_id, resolution=body.resolution, rationale=body.rationale, external_ref=body.external_ref))

    # ---------------------------------------------------------------------------- risk requests
    def risk(conn, authz, ctx):
        return RiskService(conn, ctx, authz)

    @api.post("/cases/{case_id}/risk-acceptance-requests", status_code=201)
    def request_risk(ctx: Ctx, case_id: UUID, body: s.RiskRequest, key: Key = None):
        return command(ctx, "POST /cases/{id}/risk-acceptance-requests", key, {"case_id": case_id}, body,
                       lambda c, a: risk(c, a, ctx).request(
                           case_id, body.expected_version, expires_at=body.expires_at, rationale=body.rationale,
                           compensating_controls=body.compensating_controls), status=201)

    @api.post("/risk-acceptance-requests/{request_id}/authorise")
    def authorise_risk(ctx: Ctx, request_id: UUID, body: s.Rationale, key: Key = None):
        return command(ctx, "POST /risk-acceptance-requests/{id}/authorise", key, {"request_id": request_id}, body,
                       lambda c, a: risk(c, a, ctx).authorise(request_id, rationale=body.rationale))

    @api.post("/risk-acceptance-requests/{request_id}/reject")
    def reject_risk(ctx: Ctx, request_id: UUID, body: s.Rationale):
        return tx(ctx, lambda c, a: risk(c, a, ctx).reject(request_id, rationale=body.rationale))

    @api.post("/risk-acceptance-requests/{request_id}/withdraw")
    def withdraw_risk(ctx: Ctx, request_id: UUID, body: s.Reason):
        return tx(ctx, lambda c, a: risk(c, a, ctx).withdraw(request_id, reason=body.reason))

    # ---------------------------------------------------------------------------- job operations
    def ops(conn, authz, ctx):
        return JobOperations(conn, ctx, authz)

    @api.get("/jobs")
    def list_jobs(ctx: Ctx, state: str | None = None, kind: str | None = None,
                  limit: Annotated[int, Query(ge=1, le=500)] = 100):
        return {"items": tx(ctx, lambda c, a: ops(c, a, ctx).list(state=state, kind=kind, limit=limit))}

    @api.get("/jobs/attention")
    def jobs_attention(ctx: Ctx):
        return {"items": tx(ctx, lambda c, a: ops(c, a, ctx).list_attention())}

    @api.get("/jobs/metrics")
    def jobs_metrics(ctx: Ctx):
        return tx(ctx, lambda c, a: ops(c, a, ctx).metrics())

    @api.get("/jobs/{job_id}")
    def get_job(ctx: Ctx, job_id: UUID):
        return tx(ctx, lambda c, a: ops(c, a, ctx).get(job_id))

    @api.post("/jobs/{job_id}/cancel")
    def cancel_job(ctx: Ctx, job_id: UUID, body: s.Reason):
        return tx(ctx, lambda c, a: ops(c, a, ctx).request_cancel(job_id, body.reason))

    @api.post("/jobs/{job_id}/retry")
    def retry_job(ctx: Ctx, job_id: UUID, body: s.JobRetry):
        return tx(ctx, lambda c, a: ops(c, a, ctx).retry(job_id, body.rationale, extra_attempts=body.extra_attempts))

    @api.post("/jobs/{job_id}/resolve-effect")
    def resolve_effect(ctx: Ctx, job_id: UUID, body: s.Resolve):
        return tx(ctx, lambda c, a: ops(c, a, ctx).resolve_effect(
            job_id, resolution=body.resolution, rationale=body.rationale, external_ref=body.external_ref))
