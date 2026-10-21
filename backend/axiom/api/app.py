"""FastAPI application: /api/v1.

Authority comes only from (1) a verified bearer token, (2) server-side
validation of the requested tenant against an active membership, and (3)
scoped role bindings loaded inside the request's tenant-bound transaction.
Request bodies never carry tenant or actor identity.
"""

import base64
import logging
import re
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, FastAPI, Header, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse

from .. import audit
from ..access import Authorizer
from ..auth import Actor, Authenticator, TokenVerifier
from ..config import Settings
from ..db import Database, TenantContext
from ..domains.assets.service import AssetService
from ..domains.cases.service import CaseService, EvidenceRef
from ..domains.evidence.objectstore import FilesystemObjectStore, ObjectStore, S3ObjectStore
from ..domains.evidence.service import EvidenceService
from ..domains.tenancy.service import TenancyService
from ..adapters.catalogue import catalogue as adapter_catalogue
from ..ingestion.pipeline import IngestionService
from ..ingestion.review import IdentityReview
from ..ingestion.sync import SyncService
from ..errors import DomainError, NotFound, Unauthenticated, ValidationFailed
from . import schemas as s

log = logging.getLogger("axiom.api")
_CORRELATION = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")

# SQLSTATE -> (HTTP status, code). Database guards are a backstop; the service
# layer normally raises a clearer DomainError first.
_SQLSTATE = {
    "23514": (409, "guard_violation"), "40001": (409, "stale_version"), "23505": (409, "duplicate"),
    "23503": (404, "reference_not_found"), "42501": (403, "forbidden"), "40P01": (409, "retry"),
}


def _error(status: int, code: str, message: str, correlation_id: str, *, retryable: bool = False,
           details: dict | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {
        "code": code, "message": message, "correlation_id": correlation_id, "retryable": retryable,
        "details": jsonable_encoder(details or {})}}, headers={"X-Correlation-ID": correlation_id})


def build_object_store(settings: Settings) -> ObjectStore:
    if settings.object_store == "s3":
        import boto3
        client = boto3.client("s3", endpoint_url=settings.s3_endpoint_url, region_name=settings.s3_region)
        return S3ObjectStore(client, settings.s3_bucket)
    return FilesystemObjectStore(settings.object_store_root)


def create_app(settings: Settings, *, db: Database | None = None, store: ObjectStore | None = None) -> FastAPI:
    settings.validate_for_runtime()
    database = db or Database(settings.database_dsn, min_size=settings.db_pool_min, max_size=settings.db_pool_max)
    owns_db = db is None
    authenticator = Authenticator(database, TokenVerifier(settings.trusted_issuers,
                                                          leeway_seconds=settings.token_leeway_seconds))
    object_store = store or build_object_store(settings)
    evidence = EvidenceService(database, object_store, max_bytes=settings.evidence_max_bytes)
    ingestion = IngestionService(database, object_store)
    sync = SyncService(database, ingestion, evidence)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if owns_db:
            database.open()
        database.verify_runtime_role()   # refuse to serve with an RLS-defeating identity
        yield
        if owns_db:
            database.close()

    app = FastAPI(title="Axiom API", version="0.1.0", lifespan=lifespan,
                  docs_url="/api/v1/docs", openapi_url="/api/v1/openapi.json")

    @app.middleware("http")
    async def correlation(request: Request, call_next):
        supplied = request.headers.get("x-correlation-id", "")
        request.state.correlation_id = supplied if _CORRELATION.match(supplied) else str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = request.state.correlation_id
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(DomainError)
    async def domain_error(request: Request, exc: DomainError):
        return _error(exc.status, exc.code, exc.message, request.state.correlation_id,
                      retryable=exc.retryable, details=exc.details)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        details = [{"loc": list(e.get("loc", ())), "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]
        return _error(422, "validation_failed", "request validation failed", request.state.correlation_id,
                      details={"errors": details})

    @app.exception_handler(psycopg.Error)
    async def database_error(request: Request, exc: psycopg.Error):
        sqlstate = getattr(exc, "sqlstate", None) or ""
        status, code = _SQLSTATE.get(sqlstate, (500, "internal_error"))
        if isinstance(exc, psycopg.OperationalError):
            status, code = 503, "database_unavailable"
        log.warning("database error", extra={"sqlstate": sqlstate, "correlation_id": request.state.correlation_id})
        message = {409: "the change conflicts with the current state", 404: "referenced record not found",
                   403: "not permitted", 503: "database unavailable"}.get(status, "internal error")
        return _error(status, code, message, request.state.correlation_id, retryable=status in (503,))

    # ------------------------------------------------------------ dependencies
    def get_actor(request: Request, authorization: Annotated[str | None, Header()] = None) -> Actor:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise Unauthenticated("bearer token required")
        return authenticator.authenticate(authorization[7:].strip())

    def get_ctx(request: Request, actor: Annotated[Actor, Depends(get_actor)],
                x_axiom_tenant: Annotated[str | None, Header()] = None) -> TenantContext:
        return authenticator.select_tenant(actor, x_axiom_tenant, request.state.correlation_id)

    Ctx = Annotated[TenantContext, Depends(get_ctx)]

    def in_tx(ctx: TenantContext, fn: Callable[..., Any]) -> Any:
        with database.tenant_tx(ctx) as conn:
            authz = Authorizer(conn, ctx)
            return jsonable_encoder(fn(conn, authz))

    def cases(ctx: TenantContext, fn: Callable[[CaseService], Any]) -> Any:
        return in_tx(ctx, lambda conn, authz: fn(CaseService(conn, ctx, authz)))

    api = APIRouter(prefix="/api/v1")

    @api.get("/health/live")
    def live():
        return {"status": "ok"}

    @api.get("/health/ready")
    def ready():
        with database.unbound_tx() as conn:
            conn.execute("SELECT 1")
        return {"status": "ready"}

    @api.get("/me")
    def me(actor: Annotated[Actor, Depends(get_actor)]):
        return jsonable_encoder({"principal_id": actor.principal_id, "kind": actor.kind,
                                 "tenants": authenticator.list_tenants(actor),
                                 "installation_roles": authenticator.installation_roles(actor)})

    # ------------------------------------------------------------------- cases
    @api.get("/cases")
    def list_cases(ctx: Ctx, workflow: str | None = None, limit: Annotated[int, Query(ge=1, le=200)] = 50,
                   cursor: str | None = None):
        after = None
        if cursor:
            try:
                ts, cid = base64.urlsafe_b64decode(cursor.encode()).decode().split("|")
                after = (datetime.fromisoformat(ts), UUID(cid))
            except ValueError as exc:
                raise ValidationFailed("invalid cursor") from exc
        items = cases(ctx, lambda c: c.list(workflow=workflow, limit=limit, after=after))
        next_cursor = None
        if len(items) == limit:
            last = items[-1]
            next_cursor = base64.urlsafe_b64encode(f"{last['created_at']}|{last['id']}".encode()).decode()
        return {"items": items, "next_cursor": next_cursor}

    @api.post("/cases", status_code=201)
    def create_case(ctx: Ctx, body: s.CreateCase):
        return cases(ctx, lambda c: c.create(scope_id=body.scope_id, title=body.title,
                                             occurrence_ids=body.occurrence_ids))

    @api.get("/cases/{case_id}")
    def get_case(ctx: Ctx, case_id: UUID):
        return cases(ctx, lambda c: c.get(case_id))

    @api.get("/cases/{case_id}/history")
    def case_history(ctx: Ctx, case_id: UUID):
        return cases(ctx, lambda c: c.history(case_id))

    def command(path: str, model: type[s.Body], call: Callable[[CaseService, UUID, Any], Any]):
        def endpoint(ctx: Ctx, case_id: UUID, body: model):  # type: ignore[valid-type]
            return cases(ctx, lambda c: call(c, case_id, body))
        endpoint.__name__ = f"case_command_{path.replace('-', '_')}"
        api.add_api_route(f"/cases/{{case_id}}/commands/{path}", endpoint, methods=["POST"])

    command("start-investigation", s.Versioned,
            lambda c, i, b: c.start_investigation(i, b.expected_version, b.rationale))
    command("link-occurrence", s.LinkOccurrence,
            lambda c, i, b: c.link_occurrence(i, b.expected_version, b.occurrence_id, b.rationale))
    command("record-assessment", s.RecordAssessment, lambda c, i, b: c.record_assessment(
        i, b.expected_version, assessment=b.assessment, rationale=b.rationale, limitations=b.limitations,
        evidence=[EvidenceRef(e.evidence_id, e.relation) for e in b.evidence]))
    command("escalate", s.Versioned, lambda c, i, b: c.escalate(i, b.expected_version, b.rationale))
    command("request-more-evidence", s.Versioned,
            lambda c, i, b: c.request_more_evidence(i, b.expected_version, b.rationale))
    command("plan-remediation", s.PlanRemediation, lambda c, i, b: c.plan_remediation(
        i, b.expected_version, owner_principal_id=b.owner_principal_id, rationale=b.rationale))
    command("defer", s.Defer,
            lambda c, i, b: c.defer(i, b.expected_version, review_at=b.review_at, rationale=b.rationale))
    command("record-external-work", s.ExternalWork, lambda c, i, b: c.record_external_work(
        i, b.expected_version, external_reference=b.external_reference, rationale=b.rationale))
    command("report-change", s.ReportChange, lambda c, i, b: c.report_change(
        i, b.expected_version, target_asset_version_id=b.target_asset_version_id,
        change_reference=b.change_reference, rationale=b.rationale, evidence_id=b.evidence_id))
    command("record-verification", s.RecordVerification, lambda c, i, b: c.record_verification(
        i, b.expected_version, claimed_result=b.claimed_result, coverage=b.coverage, criteria=b.criteria,
        rationale=b.rationale, observed_asset_version_id=b.observed_asset_version_id,
        observed_deployment_digest=b.observed_deployment_digest, evidence_id=b.evidence_id))
    command("close-verified", s.CloseVerified, lambda c, i, b: c.close_verified(
        i, b.expected_version, verification_run_id=b.verification_run_id, rationale=b.rationale))
    command("dismiss", s.Versioned, lambda c, i, b: c.dismiss(i, b.expected_version, rationale=b.rationale))
    command("close-duplicate", s.CloseDuplicate, lambda c, i, b: c.close_duplicate(
        i, b.expected_version, duplicate_of=b.duplicate_of, rationale=b.rationale))
    command("close-asset-retired", s.CloseRetired, lambda c, i, b: c.close_asset_retired(
        i, b.expected_version, retirement_evidence_id=b.retirement_evidence_id, rationale=b.rationale))
    command("accept-risk", s.AcceptRisk, lambda c, i, b: c.accept_risk(
        i, b.expected_version, expires_at=b.expires_at, rationale=b.rationale,
        compensating_controls=b.compensating_controls))
    command("reopen", s.Reopen,
            lambda c, i, b: c.reopen(i, b.expected_version, reason=b.reason, rationale=b.rationale))

    # ------------------------------------------------------------------ assets
    def assets(ctx: TenantContext, fn: Callable[[AssetService], Any]) -> Any:
        return in_tx(ctx, lambda conn, authz: fn(AssetService(conn, ctx, authz)))

    @api.post("/assets", status_code=201)
    def create_asset(ctx: Ctx, body: s.CreateAsset):
        return assets(ctx, lambda a: a.create_asset(scope_id=body.scope_id, kind=body.kind,
                                                    display_name=body.display_name))

    @api.post("/assets/{asset_id}/versions", status_code=201)
    def record_asset_version(ctx: Ctx, asset_id: UUID, body: s.RecordAssetVersion):
        return assets(ctx, lambda a: a.record_version(asset_id=asset_id, **body.model_dump()))

    @api.post("/assets/{asset_id}/retire")
    def retire_asset(ctx: Ctx, asset_id: UUID, body: s.RetireAsset):
        return assets(ctx, lambda a: a.retire(asset_id=asset_id, **body.model_dump()))

    @api.post("/occurrences", status_code=201)
    def record_occurrence(ctx: Ctx, body: s.RecordOccurrence):
        return assets(ctx, lambda a: a.record_occurrence(**body.model_dump()))

    # ---------------------------------------------------------------- evidence
    @api.post("/evidence", status_code=201)
    def initiate_evidence(ctx: Ctx, body: s.InitiateEvidence):
        return jsonable_encoder(evidence.initiate(ctx, **body.model_dump()))

    @api.put("/evidence/{evidence_id}/content")
    async def upload_evidence(ctx: Ctx, evidence_id: UUID, request: Request):
        spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
        total = 0
        try:
            async for chunk in request.stream():
                total += len(chunk)
                if total > settings.evidence_max_bytes:
                    raise ValidationFailed("upload exceeds the permitted size", code="size_limit_exceeded")
                spool.write(chunk)
            spool.seek(0)

            def chunks() -> Iterator[bytes]:
                while data := spool.read(1024 * 1024):
                    yield data
            return jsonable_encoder(await run_in_threadpool(evidence.upload, ctx, evidence_id, chunks()))
        finally:
            spool.close()

    @api.post("/evidence/{evidence_id}/finalise")
    def finalise_evidence(ctx: Ctx, evidence_id: UUID):
        return jsonable_encoder(evidence.finalise(ctx, evidence_id))

    @api.get("/evidence/{evidence_id}")
    def evidence_metadata(ctx: Ctx, evidence_id: UUID):
        return jsonable_encoder(evidence.metadata(ctx, evidence_id))

    @api.get("/evidence/{evidence_id}/content")
    def download_evidence(ctx: Ctx, evidence_id: UUID, purpose: Annotated[str, Query(min_length=1, max_length=200)]):
        opened = evidence.open_for_read(ctx, evidence_id, purpose=purpose)
        return StreamingResponse(opened.chunks, media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="evidence-{evidence_id}"',
            "X-Content-Type-Options": "nosniff", "X-Evidence-SHA256": opened.record["observed_digest"]})

    # ------------------------------------------------------- administration
    def tenancy(ctx: TenantContext, fn: Callable[[TenancyService], Any]) -> Any:
        return in_tx(ctx, lambda conn, authz: fn(TenancyService(conn, ctx, authz)))

    @api.post("/role-bindings", status_code=201)
    def assign_role(ctx: Ctx, body: s.AssignRole):
        return tenancy(ctx, lambda t: t.assign_role(**body.model_dump()))

    @api.post("/role-bindings/{binding_id}/revoke")
    def revoke_role(ctx: Ctx, binding_id: UUID, body: s.RevokeRole):
        return tenancy(ctx, lambda t: t.revoke_role(binding_id=binding_id, reason=body.reason))

    @api.post("/delegation-limits", status_code=201)
    def delegation_limit(ctx: Ctx, body: s.DelegationLimit):
        return tenancy(ctx, lambda t: t.set_delegation_limit(**body.model_dump()))

    # --------------------------------------------------------------- ingestion
    @api.get("/adapters")
    def adapters(ctx: Ctx):
        return {"items": adapter_catalogue()}

    @api.post("/imports", status_code=202)
    def request_import(ctx: Ctx, body: s.RequestImport):
        declared = body.declared_subject.model_dump() if body.declared_subject else None
        return jsonable_encoder(ingestion.request_import(ctx, evidence_id=body.evidence_id, adapter=body.adapter,
                                                         scope_id=body.scope_id, declared_subject=declared))

    @api.get("/ingestion-runs")
    def list_runs(ctx: Ctx, status: str | None = None, limit: Annotated[int, Query(ge=1, le=200)] = 50):
        def read(conn, authz: Authorizer):
            scopes = authz.readable_scopes("ingestion.read")
            return conn.execute(
                """WITH RECURSIVE covered(id) AS (SELECT id FROM axiom.scopes WHERE id = ANY(%(s)s)
                       UNION SELECT c.id FROM axiom.scopes c JOIN covered ON c.parent_id = covered.id)
                   SELECT id, scope_id, connection_id, source_kind, adapter, status, coverage, coverage_reason, counts,
                          created_at, finished_at FROM axiom.ingestion_runs
                    WHERE scope_id IN (SELECT id FROM covered) AND (%(st)s::text IS NULL OR status = %(st)s)
                    ORDER BY created_at DESC LIMIT %(l)s""", {"s": scopes, "st": status, "l": limit}).fetchall()
        return {"items": in_tx(ctx, read)}

    @api.get("/ingestion-runs/{run_id}")
    def get_run(ctx: Ctx, run_id: UUID):
        return jsonable_encoder(ingestion.get_run(ctx, run_id))

    @api.post("/connections", status_code=201)
    def create_connection(ctx: Ctx, body: s.CreateConnection):
        return jsonable_encoder(sync.create_connection(ctx, **body.model_dump()))

    @api.post("/connections/{connection_id}/sync", status_code=202)
    def request_sync(ctx: Ctx, connection_id: UUID):
        return jsonable_encoder(sync.request_sync(ctx, connection_id))

    @api.get("/identity-candidates")
    def identity_candidates(ctx: Ctx):
        return {"items": in_tx(ctx, lambda conn, authz: IdentityReview(conn, ctx, authz).list_open())}

    @api.post("/identity-candidates/{candidate_id}/resolve")
    def resolve_candidate(ctx: Ctx, candidate_id: UUID, body: s.ResolveCandidate):
        return in_tx(ctx, lambda conn, authz: IdentityReview(conn, ctx, authz).resolve(
            candidate_id, expected_version=body.expected_version, outcome=body.outcome, rationale=body.rationale))

    @api.get("/assets/{asset_id}")
    def get_asset(ctx: Ctx, asset_id: UUID):
        return in_tx(ctx, lambda conn, authz: IdentityReview(conn, ctx, authz).asset(asset_id))

    @api.get("/audit-events")
    def audit_events(ctx: Ctx, resource_id: str | None = None, limit: Annotated[int, Query(ge=1, le=500)] = 100):
        def read(conn, authz: Authorizer):
            root = conn.execute("SELECT id FROM axiom.scopes WHERE kind = 'tenant_root'").fetchone()
            authority = authz.require("audit.read", root["id"])
            rows = conn.execute(
                """SELECT * FROM axiom.audit_events WHERE (%(rid)s::text IS NULL OR resource_id = %(rid)s)
                   ORDER BY occurred_at DESC LIMIT %(limit)s""", {"rid": resource_id, "limit": limit}).fetchall()
            audit.record(conn, ctx, action="audit.read", resource_type="audit_events", resource_id=resource_id,
                         detail={"returned": len(rows), "authority": authority.as_json()})
            return rows
        return in_tx(ctx, read)

    app.include_router(api)

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
    def unknown(rest: str):
        raise NotFound("no such endpoint")

    return app
