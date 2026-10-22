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
                                                  priority=body.priority, rationale=body.rationale,
                                                  expires_at=body.expires_at))

    @api.post("/policies/{policy_id}/preview")
    def preview_policy(ctx: Ctx, policy_id: UUID):
        return tx(ctx, lambda c, a: PolicyService(c, ctx, a).preview(policy_id))

    @api.post("/policies/preview")
    def preview_definition(ctx: Ctx, body: s.PreviewPolicy):
        return tx(ctx, lambda c, a: PolicyService(c, ctx, a).preview(definition=body.definition))

    @api.get("/cases/{case_id}/priority")
    def case_priority(ctx: Ctx, case_id: UUID):
        def read(conn, authz):
            case = conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s", (case_id,)).fetchone()
            if case is None or not authz.has("case.read", case["scope_id"]):
                raise NotFound("case not found", code="case_not_found")
            decisions = conn.execute(
                """SELECT d.id, d.kind, d.outcome, d.rationale, d.limitations, d.policy_version_id, d.actor_principal_id,
                          d.recorded_at, e.payload FROM axiom.decisions d
                     LEFT JOIN axiom.case_events e ON e.decision_id = d.id
                    WHERE d.case_id = %s AND d.kind IN ('prioritisation', 'priority_override')
                    ORDER BY d.recorded_at, d.id""", (case_id,)).fetchall()
            overrides = conn.execute("SELECT * FROM axiom.priority_overrides WHERE case_id = %s ORDER BY created_at",
                                     (case_id,)).fetchall()
            return {"priority": case["priority"], "decisions": decisions, "overrides": overrides}
        return tx(ctx, read)

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

    # -------------------------------------------------------------------------------- read models for the UI
    def _case_or_404(conn, authz, case_id):
        case = conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s", (case_id,)).fetchone()
        if case is None or not authz.has("case.read", case["scope_id"]):
            raise NotFound("case not found", code="case_not_found")
        return case

    @api.get("/cases/{case_id}/context")
    def case_context(ctx: Ctx, case_id: UUID):
        """Affected assets and deployments with their provenance (scanner observation or manual record) and the
        business-context versions with their basis (source tag or manual assertion)."""
        def read(conn, authz):
            _case_or_404(conn, authz, case_id)
            occ = conn.execute(
                """SELECT o.id, o.source_system, o.vulnerability_ref, o.component_locator, o.source_severity,
                          av.id AS asset_version_id, av.deployment_digest, av.version_label, av.observed_at,
                          av.source_evidence_id, a.id AS asset_id, a.display_name, a.asset_kind, a.lifecycle_status,
                          l.linked_at
                     FROM axiom.case_occurrence_links l JOIN axiom.finding_occurrences o ON o.id = l.occurrence_id
                     JOIN axiom.asset_versions av ON av.id = o.asset_version_id JOIN axiom.assets a ON a.id = av.asset_id
                    WHERE l.case_id = %s AND l.unlinked_at IS NULL ORDER BY o.vulnerability_ref""",
                (case_id,)).fetchall()
            asset_ids = sorted({o["asset_id"] for o in occ}, key=str)
            versions = conn.execute(
                """SELECT av.*, CASE
                          WHEN EXISTS (SELECT 1 FROM axiom.finding_occurrences o JOIN axiom.occurrence_observations ob
                                         ON ob.occurrence_id = o.id WHERE o.asset_version_id = av.id) THEN 'ingestion'
                          WHEN av.source_evidence_id IS NOT NULL THEN 'manual_with_evidence'
                          ELSE 'manual' END AS provenance
                     FROM axiom.asset_versions av WHERE av.asset_id = ANY(%s) ORDER BY av.observed_at DESC""", (asset_ids,)).fetchall()
            contexts = conn.execute(
                """SELECT id, asset_id, owner_ref, criticality, environment, data_classification, basis, asserted_by,
                          effective_from, recorded_at FROM axiom.business_context_versions WHERE asset_id = ANY(%s)
                    ORDER BY recorded_at DESC""", (asset_ids,)).fetchall()
            return {"occurrences": occ, "asset_versions": versions, "business_context": contexts}
        return tx(ctx, read)

    @api.get("/cases/{case_id}/risk")
    def case_risk(ctx: Ctx, case_id: UUID):
        """Risk-acceptance requests and acceptances for a case, with the record history the requester may see.

        Needs case.read. The audit trail of these records is included only for a requester holding audit.read at
        the tenant root (as /audit-events); otherwise ``audit`` is null and ``audit_withheld`` says why. What the
        requester may *do* is decided by the command endpoints, not by this view."""
        def read(conn, authz):
            case = _case_or_404(conn, authz, case_id)
            requests = conn.execute("SELECT * FROM axiom.risk_acceptance_requests WHERE case_id = %s ORDER BY created_at",
                                    (case_id,)).fetchall()
            acceptances = conn.execute("SELECT * FROM axiom.risk_acceptances WHERE case_id = %s ORDER BY created_at",
                                       (case_id,)).fetchall()
            decisions = conn.execute(
                """SELECT id, kind, outcome, rationale, actor_principal_id, authority, recorded_at FROM axiom.decisions
                    WHERE case_id = %s AND (kind = 'risk_acceptance' OR (kind = 'reopen' AND outcome = 'acceptance_expiry'))
                    ORDER BY recorded_at""", (case_id,)).fetchall()
            root = conn.execute("SELECT id FROM axiom.scopes WHERE kind = 'tenant_root'").fetchone()
            out = {"case": {"id": case["id"], "workflow": case["workflow"], "priority": case["priority"],
                            "record_version": case["record_version"]},
                   "requests": requests, "acceptances": acceptances, "decisions": decisions,
                   "audit": None, "audit_withheld": "requires audit.read at the tenant root"}
            if authz.has("audit.read", root["id"]):
                ids = [str(r["id"]) for r in requests] + [str(a["id"]) for a in acceptances]
                out["audit"] = conn.execute(
                    """SELECT occurred_at, action, actor_principal_id, actor_kind, resource_type, resource_id, outcome
                         FROM axiom.audit_events WHERE resource_id = ANY(%s) ORDER BY occurred_at""", (ids,)).fetchall()
                out["audit_withheld"] = None
            return out
        return tx(ctx, read)

    @api.get("/cases/{case_id}/evidence-snapshots")
    def case_snapshots(ctx: Ctx, case_id: UUID):
        def read(conn, authz):
            _case_or_404(conn, authz, case_id)
            return {"items": conn.execute(
                """SELECT id, as_of, purpose, member_count, max_classification, digest, created_by, created_at,
                          jsonb_array_length(contradictions) AS contradictions, jsonb_array_length(gaps) AS gaps
                     FROM axiom.evidence_snapshots WHERE case_id = %s ORDER BY created_at DESC""", (case_id,)).fetchall()}
        return tx(ctx, read)

    @api.get("/cases/{case_id}/action-proposals")
    def case_proposals(ctx: Ctx, case_id: UUID):
        def read(conn, authz):
            _case_or_404(conn, authz, case_id)
            rows = conn.execute("SELECT id FROM axiom.action_proposals WHERE case_id = %s ORDER BY created_at",
                                (case_id,)).fetchall()
            svc = ActionService(conn, ctx, authz)
            out = []
            for r in rows:
                try:
                    out.append(svc.get(r["id"]))
                except NotFound:
                    continue                      # not readable by this requester
            return {"items": out}
        return tx(ctx, read)

    @api.get("/connections")
    def list_connections(ctx: Ctx):
        """Connections with the adapter's support level, so the UI can label fixture-tested integrations."""
        from ..adapters.catalogue import catalogue
        levels = {a["name"]: a["support_level"] for a in catalogue()}

        def read(conn, authz):
            rows = conn.execute("""SELECT id, scope_id, adapter, adapter_kind, display_name, base_url, status, created_at
                                     FROM axiom.connections ORDER BY created_at""").fetchall()
            return {"items": [{**r, "support_level": levels.get(r["adapter"], "unknown")} for r in rows
                              if any(authz.has(p, r["scope_id"]) for p in ("proposal.read", "ingestion.read"))]}
        return tx(ctx, read)

    @api.get("/reports/live")
    def live_report(ctx: Ctx, scope_id: UUID):
        """The exposure summary computed now and not stored (not a reproducible record; generate a snapshot for
        that). Needs report.read on the scope."""
        def read(conn, authz):
            authz.require("report.read", scope_id)
            now = conn.execute("SELECT clock_timestamp() AS t").fetchone()["t"]
            return {"stored": False, "content": ReportService(conn, ctx, authz, store).compute(scope_id, now)}
        return tx(ctx, read)

    @api.get("/scopes")
    def list_scopes(ctx: Ctx):
        """Scopes in the selected tenant where the requester holds at least one role binding (and their children)."""
        def read(conn, authz):
            mine = set(authz.readable_scopes("case.read")) | set(authz.readable_scopes("report.read"))
            rows = conn.execute(
                """WITH RECURSIVE covered(id) AS (SELECT id FROM axiom.scopes WHERE id = ANY(%s)
                       UNION SELECT c.id FROM axiom.scopes c JOIN covered ON c.parent_id = covered.id)
                   SELECT s.id, s.kind, s.name, s.parent_id FROM axiom.scopes s WHERE s.id IN (SELECT id FROM covered)
                    ORDER BY s.kind = 'tenant_root' DESC, s.name""", (list(mine),)).fetchall()
            return {"items": [{**r, "report_read": authz.has("report.read", r["id"]),
                               "report_generate": authz.has("report.generate", r["id"])} for r in rows]}
        return tx(ctx, read)
