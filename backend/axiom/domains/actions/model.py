"""Effect classes and canonical payloads for external actions (Specification S 9, ACT-01, ACT-08)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from ...errors import ValidationFailed


@dataclass(frozen=True)
class EffectClass:
    name: str
    enabled: bool
    adapter: str | None                 # connection adapter that can execute it
    approval_required: bool = True
    max_uses_limit: int = 1             # upper bound an approver may grant
    max_proposal_days: int = 30
    description: str = ""


# ACT-08: ticket creation, pull requests and production mutation are distinct classes with distinct enablement.
# Production mutation is disabled by default and has no executor; enabling it needs a separate policy and
# integration (Specification S 9), which do not exist.
REGISTRY: dict[str, EffectClass] = {
    "ticket.create": EffectClass("ticket.create", True, "jira_style", True, 3, 30,
                                 "Create a remediation ticket in a Jira-style tracker (fixture-tested only)"),
    "pull_request.create": EffectClass("pull_request.create", False, None,
                                       description="Planned; no integration built"),
    "production.change": EffectClass("production.change", False, None,
                                      description="Disabled by default; requires a separately enabled policy"),
}

_PROJECT = re.compile(r"^[A-Z][A-Z0-9_]{1,9}$")
_LABEL = re.compile(r"^[A-Za-z0-9_.-]{1,50}$")


def effect_class(name: str) -> EffectClass:
    cls = REGISTRY.get(name)
    if cls is None:
        raise ValidationFailed(f"unknown effect class {name}")
    if not cls.enabled:
        raise ValidationFailed(f"effect class {name} is not enabled", code="effect_class_disabled")
    return cls


def canonical_ticket_payload(payload: dict) -> dict:
    """Validate and normalise a ticket.create payload. Only these keys are approved and sent."""
    unknown = set(payload) - {"project_key", "summary", "description", "labels", "issue_type"}
    if unknown:
        raise ValidationFailed(f"unknown payload fields: {sorted(unknown)}")
    project = str(payload.get("project_key", ""))
    summary = str(payload.get("summary", "")).strip()
    description = str(payload.get("description", ""))
    labels = payload.get("labels", []) or []
    issue_type = str(payload.get("issue_type", "Task"))
    if not _PROJECT.match(project):
        raise ValidationFailed("project_key must look like ABC")
    if not 1 <= len(summary) <= 255:
        raise ValidationFailed("summary must be 1 to 255 characters")
    if len(description) > 20000:
        raise ValidationFailed("description is limited to 20000 characters")
    if not isinstance(labels, list) or len(labels) > 10 or not all(isinstance(x, str) and _LABEL.match(x)
                                                                  for x in labels):
        raise ValidationFailed("labels: up to 10 of [A-Za-z0-9_.-]{1,50}")
    if any(x.startswith("axiom-op-") for x in labels):
        raise ValidationFailed("the axiom-op- label prefix is reserved")
    if issue_type not in ("Task", "Bug"):
        raise ValidationFailed("issue_type must be Task or Bug")
    return {"project_key": project, "summary": summary, "description": description, "labels": sorted(set(labels)),
            "issue_type": issue_type}
