"""Inputs/outputs of the ids-only workflow variant. Nothing here carries evidence or proposal text."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SecureInput:
    tenant_id: str
    run_id: str  # the platform's remediation-run id (NOT Temporal's run id)
    proposal_digest: str  # sha256 of the canonical proposal stored in the platform DB
    approval_window_seconds: float = 3600.0  # non-sensitive configuration


@dataclass
class SecureOutcome:
    status: str
    ticket_id: str | None = None
    reason_code: str = ""
