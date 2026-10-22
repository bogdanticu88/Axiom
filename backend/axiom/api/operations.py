"""API routes for the action protocol, two-step risk acceptance and job operations.

Idempotency (API-07): ``Idempotency-Key`` is **required** on execution requests (the external-effect command) and
honoured on the other commands when sent. Replays return the stored response with ``Idempotent-Replayed: true``.
"""

from collections.abc import Callable
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Header, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response

from .. import idempotency
from ..access import Authorizer
from ..db import Database, TenantContext
from ..domains.actions.service import ActionService
from ..domains.cases.risk import RiskService
from ..domains.reports.service import ReportService
from ..errors import NotFound
from ..errors import ValidationFailed
from ..jobs import JobOperations
from . import schemas as s


def register(api: APIRouter, database: Database, Ctx, store=None, settings=None) -> None:
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

    # ------------------------------------------------------------------- reports, SLA, ticket state
    def reports(conn, authz, ctx):
        return ReportService(conn, ctx, authz, store)

    @api.post("/reports/snapshots", status_code=201)
    def generate_report(ctx: Ctx, body: s.GenerateReport):
        return tx(ctx, lambda c, a: reports(c, a, ctx).generate(kind=body.kind, scope_id=body.scope_id,
                                                                as_of=body.as_of))

    @api.get("/reports/snapshots/{snapshot_id}")
    def get_report(ctx: Ctx, snapshot_id: UUID):
        return tx(ctx, lambda c, a: reports(c, a, ctx).get(snapshot_id))

    @api.post("/reports/snapshots/{snapshot_id}/exports", status_code=201)
    def export_report(ctx: Ctx, snapshot_id: UUID, body: s.ExportReport):
        return tx(ctx, lambda c, a: reports(c, a, ctx).export(snapshot_id, body.format))

    @api.get("/reports/exports/{export_id}/content")
    def export_content(ctx: Ctx, export_id: UUID):
        with database.tenant_tx(ctx) as conn:
            row, data = ReportService(conn, ctx, Authorizer(conn, ctx), store).read_export(export_id)
        media = "application/json" if row["format"] == "json" else "text/csv"
        return Response(content=data, media_type=media, headers={
            "X-Content-SHA256": row["sha256"],
            "Content-Disposition": f'attachment; filename="report-{row["snapshot_id"]}.{row["format"]}"'})

    @api.get("/cases/{case_id}/sla")
    def case_sla(ctx: Ctx, case_id: UUID):
        def read(conn, authz):
            case = conn.execute("SELECT scope_id FROM axiom.finding_cases WHERE id = %s", (case_id,)).fetchone()
            if case is None or not authz.has("case.read", case["scope_id"]):
                raise NotFound("case not found", code="case_not_found")
            from ..domains.cases.sla import sla_view
            now = conn.execute("SELECT clock_timestamp() AS t").fetchone()["t"]
            return {"items": [sla_view(t, now) for t in conn.execute(
                "SELECT * FROM axiom.sla_timers WHERE case_id = %s ORDER BY created_at, kind", (case_id,))]}
        return tx(ctx, read)

    @api.get("/external-references/{reference_id}/states")
    def ticket_states(ctx: Ctx, reference_id: UUID):
        def read(conn, authz):
            ref = conn.execute("""SELECT r.*, c.scope_id FROM axiom.external_references r
                                  JOIN axiom.finding_cases c ON c.id = r.case_id WHERE r.id = %s""",
                               (reference_id,)).fetchone()
            if ref is None or not authz.has("case.read", ref["scope_id"]):
                raise NotFound("reference not found", code="reference_not_found")
            return {"reference": ref, "states": list(conn.execute(
                "SELECT * FROM axiom.external_ticket_states WHERE reference_id = %s ORDER BY observed_at, id",
                (reference_id,)))}
        return tx(ctx, read)

    # -------------------------------------------- policies, prioritisation, business context, ownership, packages
    from ..domains.assets.service import AssetService, assert_business_context
    from ..domains.cases import ownership as own
    from ..domains.cases import priority as prio
    from ..domains.cases.service import CaseService
    from ..domains.policies.service import PolicyService

    @api.post("/policies", status_code=201)
    def draft_policy(ctx: Ctx, body: s.DraftPolicy):
        return tx(ctx, lambda c, a: PolicyService(c, ctx, a).draft(kind=body.kind, definition=body.definition,
                                                                   rationale=body.rationale,
                                                                   provisional=body.provisional))

    @api.post("/policies/{policy_id}/publish")
    def publish_policy(ctx: Ctx, policy_id: UUID, body: s.Rationale):
        return tx(ctx, lambda c, a: PolicyService(c, ctx, a).publish(policy_id, rationale=body.rationale))

    @api.get("/policies")
    def list_policies(ctx: Ctx, kind: str | None = None):
        return {"items": tx(ctx, lambda c, a: PolicyService(c, ctx, a).list(kind))}

    @api.post("/cases/{case_id}/commands/apply-priority-policy")
    def apply_priority(ctx: Ctx, case_id: UUID, body: s.ApplyPriority):
        return tx(ctx, lambda c, a: prio.apply(CaseService(c, ctx, a), case_id, body.expected_version,
                                               rationale=body.rationale))

    @api.post("/cases/{case_id}/commands/override-priority")
    def override_priority(ctx: Ctx, case_id: UUID, body: s.OverridePriority):
        return tx(ctx, lambda c, a: prio.override(CaseService(c, ctx, a), case_id, body.expected_version,
                                                  priority=body.priority, rationale=body.rationale))

    @api.post("/assets/{asset_id}/business-context", status_code=201)
    def business_context(ctx: Ctx, asset_id: UUID, body: s.AssertContext):
        return tx(ctx, lambda c, a: assert_business_context(
            AssetService(c, ctx, a), asset_id=asset_id, rationale=body.rationale, owner_ref=body.owner_ref,
            criticality=body.criticality, environment=body.environment, data_classification=body.data_classification))

    @api.post("/cases/{case_id}/ownership/route")
    def route_owner(ctx: Ctx, case_id: UUID):
        return tx(ctx, lambda c, a: own.route(CaseService(c, ctx, a), case_id))

    @api.post("/cases/{case_id}/ownership/override")
    def override_owner(ctx: Ctx, case_id: UUID, body: s.OwnerOverride):
        return tx(ctx, lambda c, a: own.override(CaseService(c, ctx, a), case_id,
                                                 owner_principal_id=body.owner_principal_id, reason=body.reason))

    @api.get("/cases/{case_id}/ownership")
    def ownership_history(ctx: Ctx, case_id: UUID):
        return {"items": tx(ctx, lambda c, a: own.history(CaseService(c, ctx, a), case_id))}

    @api.get("/ownership/unresolved")
    def unresolved_owners(ctx: Ctx):
        return {"items": tx(ctx, lambda c, a: own.unresolved_queue(CaseService(c, ctx, a)))}

    @api.post("/cases/{case_id}/evidence-package", status_code=201)
    def evidence_package(ctx: Ctx, case_id: UUID):
        return tx(ctx, lambda c, a: reports(c, a, ctx).evidence_package(case_id))

    # -------------------------------------------------------------------------------- investigation (ADR 0012)
    from ..investigation import snapshots as snaps
    from ..investigation.service import InvestigationService

    def inv(c, a, ctx):
        return InvestigationService(
            c, ctx, a, env=settings.env if settings else "development",
            model_destinations=settings.model_destination_set if settings else frozenset(),
            tool_destinations=settings.tool_destination_set if settings else frozenset())

    @api.post("/cases/{case_id}/evidence-snapshots", status_code=201)
    def create_snapshot(ctx: Ctx, case_id: UUID, body: s.CreateSnapshot):
        def go(c, a):
            row = snaps.build_snapshot(c, ctx, a, case_id, purpose=body.purpose)
            return snaps.get_snapshot(c, a, row["id"])
        return tx(ctx, go)

    @api.get("/evidence-snapshots/{snapshot_id}")
    def read_snapshot(ctx: Ctx, snapshot_id: UUID):
        return tx(ctx, lambda c, a: {**snaps.get_snapshot(c, a, snapshot_id),
                                     "digest_verified": snaps.verify_snapshot(c, snapshot_id)})

    @api.post("/model-routes", status_code=201)
    def propose_route(ctx: Ctx, body: s.ProposeRoute):
        return tx(ctx, lambda c, a: inv(c, a, ctx).propose_route(**body.model_dump()))

    @api.post("/model-routes/{route_id}/approve")
    def approve_route(ctx: Ctx, route_id: UUID, body: s.Rationale):
        return tx(ctx, lambda c, a: inv(c, a, ctx).approve_route(route_id, rationale=body.rationale))

    @api.post("/model-routes/{route_id}/disable")
    def disable_route(ctx: Ctx, route_id: UUID, body: s.Rationale):
        return tx(ctx, lambda c, a: inv(c, a, ctx).disable_route(route_id, rationale=body.rationale))

    @api.get("/model-routes")
    def list_routes(ctx: Ctx):
        return {"items": tx(ctx, lambda c, a: inv(c, a, ctx).list_routes())}

    @api.post("/cases/{case_id}/investigations", status_code=202)
    def start_investigation(ctx: Ctx, case_id: UUID, body: s.StartInvestigation, key: Key = None):
        return command(ctx, "POST /cases/{case_id}/investigations", key, {"case_id": case_id}, body,
                       lambda c, a: inv(c, a, ctx).start(case_id, questions=body.questions, route=body.route,
                                                         tools=body.tools, budget=body.budget,
                                                         deadline_seconds=body.deadline_seconds,
                                                         snapshot_id=body.snapshot_id), status=202)

    @api.get("/cases/{case_id}/investigations")
    def list_investigations(ctx: Ctx, case_id: UUID):
        return {"items": tx(ctx, lambda c, a: inv(c, a, ctx).list_for_case(case_id))}

    @api.get("/investigations/{run_id}")
    def get_investigation(ctx: Ctx, run_id: UUID):
        return tx(ctx, lambda c, a: inv(c, a, ctx).get(run_id))

    @api.post("/investigations/{run_id}/cancel")
    def cancel_investigation(ctx: Ctx, run_id: UUID, body: s.CancelInvestigation):
        return tx(ctx, lambda c, a: inv(c, a, ctx).cancel(run_id, reason=body.reason))

    @api.post("/investigation-claims/{claim_id}/reviews", status_code=201)
    def review_claim(ctx: Ctx, claim_id: UUID, body: s.ReviewClaim):
        return tx(ctx, lambda c, a: inv(c, a, ctx).review_claim(claim_id, verdict=body.verdict, note=body.note,
                                                                corrected_conclusion=body.corrected_conclusion))
