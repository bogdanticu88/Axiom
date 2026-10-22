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
        ("business_inventory_import", "context", "schema to be defined"),
        ("threat_intel_feeds", "intelligence", "feed selection and licence review pending"),
        ("witness", "evidence", "optional provider; platform runs without it"),
    ]
]


WORKFLOW = [
    AdapterInfo("jira_style", "1", "workflow", ("rest-v3",), ("create_ticket", "lookup", "fetch_state"),
                SupportLevel.FIXTURE_TESTED, "local fake only; never run against a Jira site; no deduplication, "
                "search not read-after-write consistent (Atlassian docs)"),
    AdapterInfo("servicenow", "1", "workflow", ("table-api",), ("create_ticket", "lookup", "fetch_state"),
                SupportLevel.FIXTURE_TESTED, "local fake only; needs a ServiceNow instance; table, correlation field "
                "and state mapping are per-instance assumptions"),
    AdapterInfo("github_issues", "1", "workflow", ("rest-2022-11-28",), ("create_ticket", "lookup", "fetch_state"),
                SupportLevel.FIXTURE_TESTED, "local fake only; needs a GitHub organisation or app; lookup scans recent "
                "issues for a body marker"),
]


# The platform's own check-endpoint contract for the verification worker (ADR 0014); no external product
# implements it.
VERIFICATION = [
    AdapterInfo("verification_check", "1", "evidence", ("axiom-check/2",), ("check_original_condition",),
                SupportLevel.FIXTURE_TESTED, "tested against a local TLS fixture and the local demonstration check "
                "service (scripts/demo, a Trivy rescan); axiom-check/2 is the platform's own contract and no "
                "external product implements it"),
]


def parser(name: str) -> Parser:
    try:
        return PARSERS[name]
    except KeyError:
        raise KeyError(f"no parser named {name!r}") from None


def catalogue() -> list[dict]:
    rows = [p.info for p in PARSERS.values()] + WORKFLOW + VERIFICATION + PLANNED
    return [{"name": i.name, "kind": i.adapter_kind, "version": i.version, "formats": list(i.formats),
             "operations": list(i.operations), "support_level": i.support_level.value,
             "validation_notes": i.validation_notes} for i in rows]
