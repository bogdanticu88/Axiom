"""Plain dataclasses shared by workflow, activities and tests (sandbox-safe)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RemediationInput:
    proposal: dict  # the remediation action payload to be approved
    platform_db: str  # path of the SQLite file standing in for the platform DB
    ticket_url: str  # base URL of the fake external ticket system
    approval_window_seconds: float = 3600.0  # durable timer for the approval deadline


@dataclass
class Approval:
    approver: str
    payload_digest: str  # sha256 of the canonical proposal the approver saw
    expires_at: str  # ISO-8601 UTC timestamp; an expired approval must not be used


@dataclass
class OperatorResolution:
    decision: str  # "adopt" (operator found the ticket) or "abandon"
    ticket_id: str | None = None
    operator: str = "operator"
    note: str = ""


@dataclass
class EffectRequest:
    workflow_id: str
    operation_key: str
    payload_digest: str
    proposal: dict
    platform_db: str
    ticket_url: str


@dataclass
class EffectResult:
    ticket_id: str
    outcome: str  # "created" | "adopted"


@dataclass
class WorkflowOutcome:
    status: str
    payload_digest: str = ""
    operation_key: str = ""
    ticket_id: str | None = None
    detail: str = ""
    history: list[str] = field(default_factory=list)
