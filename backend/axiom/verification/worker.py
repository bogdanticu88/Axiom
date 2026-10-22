"""Verification worker: one job per reported change, run as the tenant's verification identity (ADR 0014).

Enqueued by ``CaseService.report_change`` in the reporting transaction when an active ``verification_check``
connection covers the case's scope (dedupe key ``verification:<report id>``, payload: case and report IDs only).

A step runs in three phases, each as the tenant's **verification principal** (never the system principal and
never the person who queued it):

A. *Read* (one transaction): job lease held; nothing recorded for this job yet; case still awaiting verification
   of this report, with no verification recorded for it; ``verification.record`` and ``evidence.upload`` held at
   the case scope; an active check connection covering the case scope.
B. *Observe* (no transaction held): call the check endpoint, apply the explicit rules (``checks.assess``), and
   preserve the response body as confidential evidence.
C. *Commit* (one transaction): job lease re-checked under a row lock; the case service re-checks the state, the
   expected case version from phase A and ``verification.record`` (bindings and membership share-locked until
   commit); the verification run, its decision and the observation's provenance are inserted together.

Authorization and commit boundary. Authority is evaluated from current rows in phase A and again in phase C;
nothing captured when the job was queued is relied on. A revocation that commits before phase C's check makes
phase C refuse (the job fails with ``authority_revoked``; no verification is recorded; evidence already stored in
phase B stays, attributed to the worker). A revocation that starts after phase C's check waits until phase C
commits or rolls back. There is no guarantee for the time between phases: a check may be *performed* by a worker
whose authority is revoked moments later, but it is not *recorded* unless the authority still holds at commit.

Duplicates and crashes. The lease fences every write; a step that lost its lease writes nothing. A crash after
phase C commits is recognised on the next claim (observation already recorded for the job). A changed case
version fails phase C with stale_version and is retried from phase A, which skips the job if the case no longer
awaits verification of this report or someone has verified it meanwhile. ``UNIQUE (tenant_id, job_id)`` and the
expected case version are the database-level backstops against a second recorded outcome.
"""
from __future__ import annotations

import hashlib
import json
from secrets import token_hex
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from uuid import UUID

from ..access import Authorizer, PermissionDenied
from ..db import TenantContext
from ..domains.cases.service import CaseService
from ..domains.evidence.service import EvidenceService
from ..errors import Conflict
from ..jobs import Done, Fail, JobContext, NeedsOperator, Retry
from . import checks
from .routing import ADAPTER, KIND, covering_connection

DEFAULT_MAX_AGE = 3600
CRITERION = "original_condition"

ClientFactory = Callable[[dict, object, Callable[[], datetime], checks.DestinationPolicy],
                         checks.CheckEndpointClient]


def default_client_factory(connection: dict, secrets, clock, policy) -> checks.CheckEndpointClient:
    ref = connection["credential_ref"]
    return checks.CheckEndpointClient(connection["base_url"], (lambda: secrets.resolve(ref)) if ref else None,
                                      policy=policy, clock=clock)


def max_age(connection: dict) -> timedelta:
    value = (connection.get("config") or {}).get("max_observation_age_seconds", DEFAULT_MAX_AGE)
    seconds = value if isinstance(value, int) and not isinstance(value, bool) else DEFAULT_MAX_AGE
    return timedelta(seconds=min(max(seconds, 60), 86400))


def _digest(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class VerificationCheckHandler:
    kind = KIND
    versions = frozenset({1})
    current_version = 1

    def __init__(self, evidence: EvidenceService, *, secrets=None, client_factory: ClientFactory | None = None,
                 clock: Callable[[], datetime] | None = None, policy: checks.DestinationPolicy | None = None):
        from ..ingestion.sync import EnvSecretResolver
        self.evidence = evidence
        self.policy = policy or checks.DestinationPolicy()      # default: no destination allowed
        self.secrets = secrets or EnvSecretResolver()
        self.client_factory = client_factory or default_client_factory
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------------ helpers
    def _identity(self, jc: JobContext) -> UUID | None:
        with jc.db.tenant_tx(jc.ctx) as conn:
            row = conn.execute("SELECT verification_principal_id AS p FROM axiom.tenants WHERE id = %s",
                               (jc.ctx.tenant_id,)).fetchone()
        return row["p"] if row else None

    @staticmethod
    def _not_applicable(conn, case: dict | None, report_id: UUID) -> str | None:
        if case is None:
            return "case_not_found"
        if case["workflow"] != "awaiting_verification":
            return "case_not_awaiting_verification"
        latest = conn.execute("""SELECT id FROM axiom.remediation_reports WHERE case_id = %s
                                  ORDER BY created_at DESC, id DESC LIMIT 1""", (case["id"],)).fetchone()
        if latest is None or latest["id"] != report_id:
            return "report_superseded"
        if conn.execute("SELECT 1 FROM axiom.verification_runs WHERE remediation_report_id = %s",
                        (report_id,)).fetchone():
            return "already_verified"
        return None

    def _store(self, vctx: TenantContext, scope_id: UUID, body: bytes) -> UUID:
        rec = self.evidence.initiate(vctx, scope_id=scope_id, sha256=hashlib.sha256(body).hexdigest(),
                                     size=len(body), media_type="application/json", classification="confidential",
                                     filename="verification-check-response.json")
        self.evidence.upload(vctx, rec["id"], iter([body]))
        done = self.evidence.finalise(vctx, rec["id"])
        if done["status"] != "verified":
            raise RuntimeError(f"stored check response failed verification ({done['rejection_reason']})")
        return done["id"]

    # --------------------------------------------------------------------- step
    def step(self, jc: JobContext):
        case_id, report_id = UUID(jc.job["payload"]["case_id"]), UUID(jc.job["payload"]["remediation_report_id"])
        principal = self._identity(jc)
        if principal is None:
            return NeedsOperator("no verification identity is provisioned for this tenant "
                                 "(python -m axiom.provisioning create-verification-identity)")
        vctx = TenantContext(jc.ctx.tenant_id, principal, "workload", f"{jc.ctx.correlation_id}:verification")

        # ---- phase A: read and authorise
        try:
            with jc.db.tenant_tx(vctx) as conn:
                jc.fenced(conn)
                prior = conn.execute("SELECT verification_run_id FROM axiom.verification_observations WHERE job_id = %s",
                                     (jc.job["id"],)).fetchone()
                if prior:
                    return Done({"status": "already_recorded", "verification_run_id": str(prior["verification_run_id"])})
                case = conn.execute("SELECT * FROM axiom.finding_cases WHERE id = %s", (case_id,)).fetchone()
                skip = self._not_applicable(conn, case, report_id)
                if skip:
                    return Done({"status": "skipped", "reason": skip})
                authz = Authorizer(conn, vctx)
                authz.require("verification.record", case["scope_id"])
                authz.require("evidence.upload", case["scope_id"])
                connection = covering_connection(conn, authz, case["scope_id"])
                if connection is None:
                    return Done({"status": "skipped", "reason": "no_check_endpoint"})
                report = conn.execute("SELECT * FROM axiom.remediation_reports WHERE id = %s", (report_id,)).fetchone()
                target = conn.execute("SELECT * FROM axiom.asset_versions WHERE id = %s",
                                      (report["target_asset_version_id"],)).fetchone()
                asset = conn.execute("SELECT * FROM axiom.assets WHERE id = %s", (target["asset_id"],)).fetchone()
                conditions = [dict(r) for r in conn.execute(
                    """SELECT DISTINCT o.vulnerability_ref, o.component_locator AS component
                         FROM axiom.case_occurrence_links l
                         JOIN axiom.finding_occurrences o ON o.tenant_id = l.tenant_id AND o.id = l.occurrence_id
                         JOIN axiom.asset_versions v ON v.tenant_id = o.tenant_id AND v.id = o.asset_version_id
                        WHERE l.case_id = %s AND l.unlinked_at IS NULL AND v.asset_id = %s
                          AND o.vulnerability_ref IS NOT NULL ORDER BY 1, 2""", (case_id, asset["id"]))]
                version = case["record_version"]
        except PermissionDenied as exc:
            return Fail(f"authority_missing: {exc}")

        criteria_doc = {"check": "verification_check", "connection_id": str(connection["id"]),
                        "criteria": [{"id": CRITERION, "kind": "finding_absent", "conditions": conditions}]}
        request = {"schema": checks.SCHEMA, "request_id": str(jc.job["id"]), "nonce": token_hex(16),
                   "asset": {"id": str(asset["id"]), "kind": asset["asset_kind"], "name": asset["display_name"]},
                   "deployment_digest": target["deployment_digest"], "criteria": criteria_doc["criteria"]}
        attempt = jc.job["attempts"] + 1

        # ---- phase B: observe (no transaction held)
        exchange, evidence_id = None, None
        requested_at = self.clock()
        if not conditions:
            result = checks.inconclusive("no_checkable_condition",
                                         "the case has no vulnerability reference on the reported asset")
        else:
            client = self.client_factory(connection, self.secrets, self.clock, self.policy)
            try:
                exchange = client.run(request)
                requested_at = exchange.sent_at
            except checks.DestinationRefused as exc:
                return NeedsOperator(f"verification destination refused: {exc}")
            except checks.CheckUnavailable as exc:
                if attempt < jc.job["max_attempts"]:
                    return Retry(str(exc))
                result = checks.inconclusive("target_unavailable", f"{exc} on all {attempt} attempts")
            else:
                result = checks.assess(exchange, request_id=request["request_id"], nonce=request["nonce"],
                                       asset_id=request["asset"]["id"], criteria=[CRITERION],
                                       target_digest=target["deployment_digest"],
                                       change_reported_at=report["created_at"], max_age=max_age(connection))
                if exchange.body:
                    try:
                        evidence_id = self._store(vctx, case["scope_id"], exchange.body)
                    except PermissionDenied as exc:
                        return Fail(f"authority_revoked: {exc}")

        # ---- phase C: commit
        rationale = (f"Automated check via connection {connection['display_name']}: {result.explanation} "
                     f"(rule {result.rule}).")
        try:
            with jc.db.tenant_tx(vctx) as conn:
                jc.fenced(conn)
                svc = CaseService(conn, vctx, Authorizer(conn, vctx))
                svc.record_verification(case_id, version, claimed_result=result.claimed, coverage=result.coverage,
                                        criteria=criteria_doc, rationale=rationale,
                                        observed_deployment_digest=result.observed_digest, evidence_id=evidence_id)
                run = conn.execute("""SELECT id, outcome, outcome_reason, evidence_object_id FROM axiom.verification_runs
                                       WHERE remediation_report_id = %s AND recorded_by = %s""",
                                   (report_id, principal)).fetchone()
                conn.execute(
                    """INSERT INTO axiom.verification_observations(tenant_id, id, case_id, remediation_report_id,
                           verification_run_id, job_id, lease_token, worker, connection_id, source_adapter,
                           source_origin, request_digest, requested_at, received_at, http_status, response_digest,
                           evidence_object_id, target_observed_at, observed_deployment_digest, rule, attempts,
                           recorded_by, connected_address, response_redacted)
                       VALUES (%s, gen_random_uuid(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                               %s, %s, %s, %s, %s, %s, %s)""",
                    (vctx.tenant_id, case_id, report_id, run["id"], jc.job["id"], jc.lease_token, jc.worker_id,
                     connection["id"], ADAPTER, checks.origin(connection["base_url"]), _digest(request),
                     requested_at, exchange.received_at if exchange else None, exchange.status if exchange else None,
                     hashlib.sha256(exchange.body).hexdigest() if exchange else None, run["evidence_object_id"],
                     result.observed_at, result.observed_digest, result.rule, attempt, principal,
                     exchange.connected_address if exchange else None, bool(exchange and exchange.redacted)))
        except PermissionDenied as exc:
            return Fail(f"authority_revoked: {exc}")
        except Conflict as exc:
            if getattr(exc, "code", None) == "stale_version":
                return Retry("case changed while the check ran; re-reading")
            return Done({"status": "skipped", "reason": getattr(exc, "code", "conflict")})
        return Done({"status": "recorded", "verification_run_id": str(run["id"]), "outcome": run["outcome"],
                     "rule": result.rule, "outcome_reason": run["outcome_reason"]})

