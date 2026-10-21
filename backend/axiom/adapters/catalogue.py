"""Adapter catalogue: what exists, at which support level, and what is only planned.

Support levels are claims that must be backed by evidence in docs/VERIFICATION.md:
fixture-tested = parser/client tests against fixtures or a local fake; sandbox-validated = live test against
a vendor sandbox/test tenant; production-supported = sandbox validation plus operational criteria.
"""
from __future__ import annotations

from .azure_resource_graph import ResourceGraphPageParser
from .base import AdapterInfo, Parser, SupportLevel
from .sarif import SarifParser
from .tenable import TenableChunkParser
from .trivy import TrivyParser

PARSERS: dict[str, Parser] = {p.info.name: p for p in (TrivyParser(), SarifParser(), TenableChunkParser(),
                                                        ResourceGraphPageParser())}

PLANNED = [
    AdapterInfo(name, "0", kind, (), (), SupportLevel.PLANNED, note) for name, kind, note in [
        ("qualys_vmdr", "scanner", "needs Qualys subscription"),
        ("rapid7_insightvm", "scanner", "needs InsightVM access"),
        ("codeql", "scanner", "generic SARIF works today; CodeQL-specific mapping planned"),
        ("semgrep", "scanner", "generic SARIF works today; Semgrep-specific mapping planned"),
        ("snyk", "scanner", "needs Snyk organisation"),
        ("owasp_zap", "scanner", "open source; planned"),
        ("burp_dast", "scanner", "needs PortSwigger licence"),
        ("defender_for_cloud", "scanner", "needs Azure subscription"),
        ("aws_security_hub", "scanner", "needs AWS account"),
        ("aws_resource_inventory", "context", "needs AWS account"),
        ("jira", "workflow", "needs Jira site"),
        ("servicenow", "workflow", "needs ServiceNow instance"),
        ("github", "workflow", "needs GitHub organisation or app"),
        ("business_inventory_import", "context", "schema to be defined"),
        ("threat_intel_feeds", "intelligence", "feed selection and licence review pending"),
        ("witness", "evidence", "optional provider; platform runs without it"),
    ]
]


def parser(name: str) -> Parser:
    try:
        return PARSERS[name]
    except KeyError:
        raise KeyError(f"no parser named {name!r}") from None


def catalogue() -> list[dict]:
    rows = [p.info for p in PARSERS.values()] + PLANNED
    return [{"name": i.name, "kind": i.adapter_kind, "version": i.version, "formats": list(i.formats),
             "operations": list(i.operations), "support_level": i.support_level.value,
             "validation_notes": i.validation_notes} for i in rows]
