"""Request bodies. ``extra='forbid'`` everywhere: unknown fields (for example a
client-supplied tenant_id, actor or 'verified': true) are rejected, never ignored."""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Versioned(Body):
    expected_version: int = Field(ge=0)
    rationale: str = Field(min_length=1, max_length=10000)


class EvidenceRefIn(Body):
    evidence_id: UUID
    relation: Literal["supports", "contradicts", "context"] = "supports"


class CreateCase(Body):
    scope_id: UUID
    title: str = Field(min_length=1, max_length=500)
    occurrence_ids: list[UUID] = Field(default_factory=list, max_length=500)


class LinkOccurrence(Versioned):
    occurrence_id: UUID


class RecordAssessment(Versioned):
    assessment: Literal["supported", "not_supported", "inconclusive"]
    limitations: str = Field(min_length=1, max_length=10000)
    evidence: list[EvidenceRefIn] = Field(default_factory=list, max_length=200)
    evidence_snapshot_id: UUID | None = None
    investigation_run_id: UUID | None = None


class PlanRemediation(Versioned):
    owner_principal_id: UUID


class Defer(Versioned):
    review_at: datetime
    pause_reason: str | None = Field(default=None, max_length=50)


class ExternalWork(Versioned):
    external_reference: str = Field(min_length=1, max_length=500)


class ReportChange(Versioned):
    target_asset_version_id: UUID
    change_reference: str = Field(min_length=1, max_length=500)
    evidence_id: UUID | None = None


class RecordVerification(Versioned):
    claimed_result: Literal["passed", "failed", "inconclusive"]
    coverage: Literal["complete", "partial", "none"]
    criteria: dict = Field(min_length=1)
    observed_asset_version_id: UUID | None = None
    observed_deployment_digest: str | None = Field(default=None, max_length=200)
    evidence_id: UUID | None = None


class CloseVerified(Versioned):
    verification_run_id: UUID


class CloseDuplicate(Versioned):
    duplicate_of: UUID


class CloseRetired(Versioned):
    retirement_evidence_id: UUID


class AcceptRisk(Versioned):
    expires_at: datetime
    compensating_controls: str | None = Field(default=None, max_length=5000)


class WithdrawRemediation(Versioned):
    """R7: from remediation_planned no deployment_state; from remediating one of none/deployed/partial/unknown."""
    deployment_state: Literal["none", "deployed", "partial", "unknown"] | None = None
    evidence: list[EvidenceRefIn] = Field(default_factory=list, max_length=200)
    target_asset_version_id: UUID | None = None
    change_reference: str | None = Field(default=None, max_length=500)


class Reopen(Versioned):
    reason: Literal["relevant_change", "recurrence", "authorised_reassessment"]


class InitiateEvidence(Body):
    scope_id: UUID
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    size: int = Field(ge=0)
    media_type: str = Field(min_length=3, max_length=255)
    classification: Literal["internal", "confidential", "restricted"]
    filename: str | None = Field(default=None, max_length=255)


class CreateAsset(Body):
    scope_id: UUID
    kind: Literal["host", "container_image", "workload", "cloud_resource", "repository", "application", "unknown"]
    display_name: str = Field(min_length=1, max_length=500)


class RecordAssetVersion(Body):
    observed_at: datetime
    deployment_digest: str | None = Field(default=None, max_length=200)
    version_label: str | None = Field(default=None, max_length=200)
    source_evidence_id: UUID | None = None


class RecordOccurrence(Body):
    source_system: str = Field(min_length=1, max_length=100)
    source_finding_id: str = Field(min_length=1, max_length=500)
    asset_version_id: UUID
    component_locator: str = Field(default="", max_length=1000)
    vulnerability_ref: str | None = Field(default=None, max_length=200)


class RetireAsset(Body):
    expected_version: int = Field(ge=0)
    evidence_id: UUID
    rationale: str = Field(min_length=1, max_length=10000)


class AssignRole(Body):
    principal_id: UUID
    role_id: str = Field(pattern=r"^[a-z_]+$")
    scope_id: UUID
    reason: str = Field(min_length=1, max_length=2000)
    valid_until: datetime | None = None
    emergency: bool = False


class RevokeRole(Body):
    reason: str = Field(min_length=1, max_length=2000)


class DelegationLimit(Body):
    principal_id: UUID
    action_class: Literal["risk.accept", "action.approve"]
    scope_id: UUID
    max_priority: Literal["low", "medium", "high", "urgent"]
    max_duration_days: int = Field(ge=1, le=730)


class DeclaredIdentifier(Body):
    namespace: str = Field(pattern=r"^[a-z0-9_]+$")
    value: str = Field(min_length=1, max_length=2048)


class DeclaredSubject(Body):
    identifiers: list[DeclaredIdentifier] = Field(min_length=1, max_length=20)
    kind: Literal["host", "container_image", "workload", "cloud_resource", "repository", "application", "unknown"]
    display_name: str | None = Field(default=None, max_length=500)
    deployment_digest: str | None = Field(default=None, pattern=r"^[a-z0-9]+:[0-9a-f]{32,128}$")
    version_label: str | None = Field(default=None, max_length=200)


class RequestImport(Body):
    evidence_id: UUID
    adapter: str = Field(pattern=r"^[a-z0-9_]+$")
    scope_id: UUID
    declared_subject: DeclaredSubject | None = None


class CreateConnection(Body):
    adapter: Literal["tenable_vm", "azure_resource_graph", "jira_style", "servicenow", "github_issues"]
    scope_id: UUID
    display_name: str = Field(min_length=1, max_length=200)
    base_url: str | None = Field(default=None, max_length=500)
    credential_ref: str | None = Field(default=None, pattern=r"^secretref:[A-Za-z0-9._/-]+$")
    config: dict = Field(default_factory=dict)


class ResolveCandidate(Body):
    expected_version: int = Field(ge=0)
    outcome: Literal["confirmed_same", "confirmed_distinct", "dismissed"]
    rationale: str = Field(min_length=1, max_length=5000)


# ---------------------------------------------------------------- actions, risk requests, job operations
class CreateProposal(Body):
    case_id: UUID
    effect_class: str = Field(min_length=1, max_length=100)
    connection_id: UUID
    payload: dict
    verification_criteria: str = Field(min_length=1, max_length=5000)
    rollback_guidance: str | None = Field(default=None, max_length=5000)
    expires_at: datetime


class ReviseProposal(Body):
    expected_version: int = Field(ge=1)
    payload: dict
    verification_criteria: str = Field(min_length=1, max_length=5000)
    rollback_guidance: str | None = Field(default=None, max_length=5000)
    expires_at: datetime


class Decide(Body):
    decision: Literal["approved", "rejected"]
    rationale: str = Field(min_length=1, max_length=10000)
    valid_until: datetime | None = None
    max_uses: int = Field(default=1, ge=1, le=100)


class Reason(Body):
    reason: str = Field(min_length=1, max_length=5000)


class RequestExecution(Body):
    approval_id: UUID


class Resolve(Body):
    resolution: Literal["adopt", "not_applied", "abandon"]
    rationale: str = Field(min_length=1, max_length=5000)
    external_ref: str | None = Field(default=None, max_length=200)


class RiskRequest(Body):
    expected_version: int = Field(ge=0)
    expires_at: datetime
    rationale: str = Field(min_length=1, max_length=10000)
    compensating_controls: str | None = Field(default=None, max_length=10000)


class Rationale(Body):
    rationale: str = Field(min_length=1, max_length=10000)


class JobRetry(Body):
    rationale: str = Field(min_length=1, max_length=5000)
    extra_attempts: int = Field(default=3, ge=1, le=10)


class GenerateReport(Body):
    kind: Literal["exposure_summary"]
    scope_id: UUID
    as_of: datetime | None = None


class DraftPolicy(Body):
    kind: Literal["priority", "ownership", "sla", "freshness"]
    definition: dict
    rationale: str = Field(min_length=1, max_length=5000)
    provisional: bool = True


class ApplyPriority(Body):
    expected_version: int = Field(ge=0)
    rationale: str = Field(min_length=1, max_length=5000)


class OverridePriority(ApplyPriority):
    priority: Literal["urgent", "high", "medium", "low"]
    expires_at: datetime | None = None


class PreviewPolicy(Body):
    definition: dict


class AssertContext(Body):
    rationale: str = Field(min_length=1, max_length=5000)
    owner_ref: str | None = Field(default=None, max_length=200)
    criticality: Literal["low", "medium", "high", "critical"] | None = None
    environment: str | None = Field(default=None, max_length=100)
    data_classification: str | None = Field(default=None, max_length=100)


class OwnerOverride(Body):
    owner_principal_id: UUID
    reason: str = Field(min_length=1, max_length=5000)


class ExportReport(Body):
    format: Literal["json", "csv"]


class CreateSnapshot(Body):
    purpose: Literal["investigation", "assessment"] = "assessment"


class ProposeRoute(Body):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,62}$")
    provider: Literal["deterministic_fake", "anthropic_messages"]
    model: str = Field(min_length=1, max_length=200)
    endpoint: str = Field(min_length=1, max_length=300)
    region: str = Field(min_length=1, max_length=100)
    max_classification: Literal["internal", "confidential", "restricted"]
    rationale: str = Field(min_length=1, max_length=5000)
    credential_ref: str | None = Field(default=None, max_length=300)
    input_price_micros_per_mtok: int = Field(default=0, ge=0)
    output_price_micros_per_mtok: int = Field(default=0, ge=0)
    timeout_seconds: int = Field(default=60, ge=1, le=600)
    max_retries: int = Field(default=1, ge=0, le=3)
    max_output_tokens: int = Field(default=4096, ge=1, le=64000)


class StartInvestigation(Body):
    questions: list[str] = Field(min_length=1, max_length=10)
    route: str = Field(min_length=1, max_length=100)
    tools: list[str] | None = Field(default=None, max_length=10)
    budget: dict[str, int] | None = None
    deadline_seconds: int = Field(default=900, ge=30, le=3600)
    snapshot_id: UUID | None = None


class CancelInvestigation(Body):
    reason: str = Field(min_length=1, max_length=2000)


class ReviewClaim(Body):
    verdict: Literal["confirmed", "rejected", "corrected"]
    note: str = Field(min_length=1, max_length=5000)
    corrected_conclusion: Literal["supported", "contradicted", "unknown"] | None = None
