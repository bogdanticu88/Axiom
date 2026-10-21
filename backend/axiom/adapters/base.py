"""Adapter contracts (Implementation plan section 5).

Scanner and context adapters turn source data into typed parse events. They are
pure: no database access, no network calls (API clients live in separate
modules and hand pages to these parsers). Unknown or missing source values stay
unknown (None); they are never coerced to False or to a default severity.

Imported text (titles, descriptions, messages) is untrusted data. Adapters copy it
into ``source_fields`` verbatim and never interpret it as instructions.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol


class SupportLevel(StrEnum):
    PLANNED = "planned"
    FIXTURE_TESTED = "fixture-tested"
    SANDBOX_VALIDATED = "sandbox-validated"
    PRODUCTION_SUPPORTED = "production-supported"


# Identifier namespaces. Strong identifiers identify one asset per tenant; weak ones never merge assets.
STRONG_NAMESPACES = frozenset({
    "image_repository", "tenable_asset_uuid", "azure_resource_id", "azure_vm_id", "aws_arn",
    "repository_uri", "source_asset",
})
WEAK_NAMESPACES = frozenset({"hostname", "fqdn", "ipv4", "ipv6", "mac_address", "netbios_name", "display_name"})


def identifier_strength(namespace: str) -> str:
    if namespace in STRONG_NAMESPACES:
        return "strong"
    if namespace in WEAK_NAMESPACES:
        return "weak"
    raise ValueError(f"unknown identifier namespace: {namespace}")


@dataclass(frozen=True)
class Identifier:
    namespace: str
    value: str

    @property
    def strength(self) -> str:
        return identifier_strength(self.namespace)


@dataclass(frozen=True)
class SubjectHints:
    """What a record says about the asset and deployment it concerns."""
    identifiers: tuple[Identifier, ...]
    kind: str                                   # assets.asset_kind
    display_name: str
    deployment_digest: str | None = None        # e.g. sha256:<hex>, git:<sha>
    version_label: str | None = None
    declared: bool = False                      # True when supplied by the importer, not the source


@dataclass(frozen=True)
class FindingRecord:
    locator: str                                # JSON pointer into the raw document/page
    external_id: str                            # stable source identity of the finding (never just a CVE)
    version_key: str                            # changes when the source's view of the finding changes
    subject: SubjectHints
    component_locator: str
    vulnerability_ref: str | None
    title: str | None
    source_severity: str | None
    source_status: str                          # 'open' | 'fixed' | 'suppressed'
    source_time: datetime | None
    normalised: dict[str, Any]
    source_fields: dict[str, Any]


@dataclass(frozen=True)
class AssetRecord:
    locator: str
    external_id: str
    version_key: str
    subject: SubjectHints
    context: dict[str, Any]                     # owner_ref, criticality, environment, location, tags
    source_time: datetime | None
    source_fields: dict[str, Any]


@dataclass(frozen=True)
class Quarantine:
    locator: str
    reason_code: str
    detail: str
    record_digest: str | None = None


@dataclass(frozen=True)
class ScanSummary:
    """What the source itself says about completeness of the document or page."""
    tool: str
    tool_version: str | None
    complete: bool | None                       # None = the source does not say
    completeness_reason: str
    supports_absence_inference: bool            # only for full scans of an identified subject
    non_findings: int = 0                       # e.g. SARIF results of kind 'pass'


ParseEvent = FindingRecord | AssetRecord | Quarantine | ScanSummary


class ParseError(ValueError):
    """The whole document is unusable (not JSON, wrong schema). Recorded as a failed run."""


@dataclass(frozen=True)
class AdapterInfo:
    name: str
    version: str
    adapter_kind: str                           # scanner | context | intelligence | workflow | evidence
    formats: tuple[str, ...]
    operations: tuple[str, ...]
    support_level: SupportLevel
    validation_notes: str
    requires_declared_subject: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


class Parser(Protocol):
    info: AdapterInfo

    def parse(self, data: bytes, *, declared_subject: SubjectHints | None = None) -> Iterator[ParseEvent]: ...


def stable_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def load_json(data: bytes) -> Any:
    try:
        return json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ParseError(f"not valid JSON: {exc}") from exc


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def pointer(*parts: Any) -> str:
    return "/" + "/".join(str(p).replace("~", "~0").replace("/", "~1") for p in parts)
