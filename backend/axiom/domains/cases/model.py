"""Pure case lifecycle rules (Specification section 4, Data design section 6/7).

These functions take facts that the service layer has loaded from authoritative
records; they never accept client-asserted booleans. The same rules are
re-checked by database triggers at commit (migration 0002).
"""
from __future__ import annotations

from enum import StrEnum

from ...errors import Conflict


class Workflow(StrEnum):
    RECEIVED = "received"
    INVESTIGATING = "investigating"
    REVIEW = "review_required"
    PLANNED = "remediation_planned"
    REMEDIATING = "remediating"
    VERIFYING = "awaiting_verification"
    CLOSED = "closed"


class Assessment(StrEnum):
    UNASSESSED = "unassessed"
    SUPPORTED = "supported"
    NOT_SUPPORTED = "not_supported"
    INCONCLUSIVE = "inconclusive"


class ClosureReason(StrEnum):
    VERIFIED_REMEDIATED = "verified_remediated"
    ACCEPTED_RISK = "accepted_risk"
    DISMISSED = "dismissed"
    DUPLICATE = "duplicate"
    ASSET_RETIRED = "asset_retired"


class ReopenReason(StrEnum):
    RELEVANT_CHANGE = "relevant_change"
    RECURRENCE = "recurrence"
    ACCEPTANCE_EXPIRY = "acceptance_expiry"
    AUTHORISED_REASSESSMENT = "authorised_reassessment"


ALLOWED: dict[Workflow, frozenset[Workflow]] = {
    Workflow.RECEIVED: frozenset({Workflow.INVESTIGATING}),
    Workflow.INVESTIGATING: frozenset({Workflow.REVIEW}),
    Workflow.REVIEW: frozenset({Workflow.INVESTIGATING, Workflow.PLANNED, Workflow.CLOSED}),
    Workflow.PLANNED: frozenset({Workflow.REMEDIATING}),
    Workflow.REMEDIATING: frozenset({Workflow.VERIFYING}),
    Workflow.VERIFYING: frozenset({Workflow.CLOSED, Workflow.REMEDIATING, Workflow.REVIEW}),
    Workflow.CLOSED: frozenset({Workflow.INVESTIGATING}),
}


def check_transition(current: str, target: str) -> None:
    if Workflow(target) not in ALLOWED[Workflow(current)]:
        raise Conflict(f"transition {current} -> {target} is not allowed", code="transition_not_allowed",
                       details={"from": current, "to": target})


def check_expected_version(current_version: int, expected_version: int) -> None:
    if current_version != expected_version:
        raise Conflict("case was changed by another request", code="stale_version",
                       details={"current_version": current_version, "expected_version": expected_version})


def require_state(current: str, *allowed: Workflow) -> None:
    if Workflow(current) not in allowed:
        raise Conflict(f"command not valid while case is {current}", code="invalid_state",
                       details={"workflow": current, "allowed": [a.value for a in allowed]})


def closure_origin(reason: ClosureReason) -> Workflow:
    """Verified remediation closes from verification; every other reason closes from review."""
    return Workflow.VERIFYING if reason is ClosureReason.VERIFIED_REMEDIATED else Workflow.REVIEW


def assessment_needs_evidence(assessment: Assessment) -> bool:
    """A definite assessment must cite verified supporting evidence (B03).

    'inconclusive' is the honest outcome when evidence is missing, stale or contradictory.
    """
    return assessment in (Assessment.SUPPORTED, Assessment.NOT_SUPPORTED)


def verification_outcome(*, claimed: str, coverage: str, observed_matches_target: bool | None,
                         evidence_verified: bool) -> tuple[str, str]:
    """Decide the recorded verification outcome from loaded facts.

    ``observed_matches_target`` is None when the observed deployment is unknown.
    Returns (outcome, reason). A claimed pass is downgraded, never upgraded.
    """
    if claimed not in ("passed", "failed", "inconclusive"):
        raise ValueError("invalid claimed outcome")
    if observed_matches_target is None:
        return "inconclusive", "observed deployment unknown"
    if not observed_matches_target:
        # Evidence about a different deployment says nothing about the reported change.
        return "inconclusive", "observed deployment differs from the reported change"
    if claimed == "failed":
        return "failed", "check failed on the reported deployment"
    if claimed == "inconclusive":
        return "inconclusive", "verifier reported inconclusive"
    if coverage != "complete":
        return "inconclusive", f"coverage {coverage}"
    if not evidence_verified:
        return "inconclusive", "no verified evidence for the check"
    return "passed", "acceptance criteria met on the reported deployment"


def workflow_after_verification(outcome: str) -> Workflow:
    return {"passed": Workflow.VERIFYING, "failed": Workflow.REMEDIATING,
            "inconclusive": Workflow.REVIEW}[outcome]
