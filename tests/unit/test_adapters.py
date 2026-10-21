"""Parser and API-client tests against fixtures (see tests/fixtures/PROVENANCE.md) and local fake transports."""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from axiom.adapters.azure_resource_graph import ResourceGraphClient, ResourceGraphPageParser
from axiom.adapters.base import (AssetRecord, FindingRecord, Identifier, ParseError, Quarantine, ScanSummary,
                                    SubjectHints, identifier_strength)
from axiom.adapters.catalogue import catalogue
from axiom.adapters.sarif import SarifParser
from axiom.adapters.tenable import TenableApiError, TenableChunkParser, TenableExportClient
from axiom.adapters.trivy import TrivyParser

FIX = Path(__file__).resolve().parent.parent / "fixtures"


def split(events):
    out = {"findings": [], "assets": [], "quarantine": [], "summary": []}
    for e in events:
        key = {FindingRecord: "findings", AssetRecord: "assets", Quarantine: "quarantine", ScanSummary: "summary"}[type(e)]
        out[key].append(e)
    return out


# --------------------------------------------------------------------- Trivy (real output)
def test_trivy_real_report():
    ev = split(TrivyParser().parse((FIX / "trivy/debian-bullseye-20230612-slim.subset.json").read_bytes()))
    assert len(ev["findings"]) == 30 and not ev["quarantine"]
    f = ev["findings"][0]
    assert f.subject.deployment_digest == "sha256:924df86f8aad741a0134b2de7d8e70c5c6863f839caadef62609c1be1340daf5"
    assert f.subject.identifiers == (Identifier("image_repository", "public.ecr.aws/docker/library/debian"),)
    assert f.subject.version_label == "bullseye-20230612-slim"
    assert f.component_locator.startswith("pkg:deb/debian/")
    summary = ev["summary"][0]
    assert summary.tool_version == "0.76.1" and summary.supports_absence_inference
    # Findings sharing a CVE across packages keep separate identities (CVE is never the identity alone).
    by_cve: dict[str, set] = {}
    for x in ev["findings"]:
        by_cve.setdefault(x.vulnerability_ref, set()).add(x.external_id)
    assert any(len(ids) > 1 for ids in by_cve.values())
    assert len({x.external_id for x in ev["findings"]}) == 30


def test_trivy_tarball_without_digest_cannot_support_absence():
    doc = json.loads((FIX / "trivy/debian-bullseye-20230612-slim.subset.json").read_text())
    doc["Metadata"]["RepoDigests"] = []
    ev = split(TrivyParser().parse(json.dumps(doc).encode()))
    assert ev["findings"][0].subject.deployment_digest is None
    assert ev["summary"][0].supports_absence_inference is False


def test_trivy_invalid_records_are_quarantined_and_bad_documents_rejected():
    doc = json.loads((FIX / "trivy/debian-bullseye-20230612-slim.subset.json").read_text())
    vulns = doc["Results"][0]["Vulnerabilities"]
    del vulns[0]["PkgName"]
    vulns[1]["Severity"] = "SEVERE"
    vulns.append("garbage")
    ev = split(TrivyParser().parse(json.dumps(doc).encode()))
    assert sorted(q.reason_code for q in ev["quarantine"]) == ["invalid_severity", "missing_required_field",
                                                               "not_an_object"]
    assert len(ev["findings"]) == 28
    with pytest.raises(ParseError):
        list(TrivyParser().parse(b"{not json"))
    with pytest.raises(ParseError):
        list(TrivyParser().parse(b'{"SchemaVersion": 1, "Results": []}'))


# --------------------------------------------------------------------------------- SARIF
def test_sarif_real_trivy_output_requires_declared_subject_and_keeps_identities_distinct():
    data = (FIX / "sarif/trivy-debian-bullseye.subset.sarif").read_bytes()
    with pytest.raises(ParseError, match="declare the subject"):
        list(SarifParser().parse(data))
    declared = SubjectHints((Identifier("image_repository", "public.ecr.aws/docker/library/debian"),),
                            "container_image", "debian", deployment_digest="sha256:" + "9" * 64, declared=True)
    ev = split(SarifParser().parse(data, declared_subject=declared))
    assert len(ev["findings"]) == 30 and not ev["quarantine"]
    assert len({f.external_id for f in ev["findings"]}) == 30
    assert all(f.normalised["identity_basis"] == "weak_location" for f in ev["findings"])
    assert ev["summary"][0].supports_absence_inference is False   # declared subject: no absence inference


def test_sarif_synthetic_features():
    ev = split(SarifParser().parse((FIX / "sarif/synthetic-code-scanning.sarif").read_bytes()))
    assert sorted(q.reason_code for q in ev["quarantine"]) == ["invalid_level", "unresolved_rule"]
    assert ev["summary"][0].non_findings == 1               # the 'pass' result
    findings = {f.normalised["start_line"]: f for f in ev["findings"]}
    assert findings[42].normalised["identity_basis"] == "partial_fingerprint"
    assert findings[7].normalised["identity_basis"] == "fingerprint" and findings[7].source_status == "suppressed"
    assert findings[88].normalised["identity_basis"] == "weak_location"
    subject = findings[42].subject
    assert subject.identifiers == (Identifier("repository_uri", "https://git.example.invalid/acme/payments-api"),)
    assert subject.deployment_digest == "git:3f2c1b0a9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a"
    # Injected instructions are carried as untrusted data only.
    assert "IGNORE PREVIOUS INSTRUCTIONS" in findings[42].source_fields["message"]["text"]


def test_sarif_duplicate_identity_is_quarantined_not_merged():
    doc = json.loads((FIX / "sarif/synthetic-code-scanning.sarif").read_text())
    doc["runs"][0]["results"].append(json.loads(json.dumps(doc["runs"][0]["results"][0])))
    ev = split(SarifParser().parse(json.dumps(doc).encode()))
    assert "ambiguous_identity" in [q.reason_code for q in ev["quarantine"]]


def test_sarif_failed_invocation_is_not_complete():
    doc = json.loads((FIX / "sarif/synthetic-code-scanning.sarif").read_text())
    doc["runs"][0]["invocations"] = [{"executionSuccessful": False}]
    summary = split(SarifParser().parse(json.dumps(doc).encode()))["summary"][0]
    assert summary.complete is False and summary.supports_absence_inference is False


# ------------------------------------------------------------------------------- Tenable
def test_tenable_chunk():
    ev = split(TenableChunkParser().parse((FIX / "tenable/synthetic-vulns-chunk-1.json").read_bytes()))
    assert [q.reason_code for q in ev["quarantine"]] == ["missing_asset_uuid"]
    assert [f.source_status for f in ev["findings"]] == ["open", "fixed", "open"]
    a, _, c = ev["findings"]
    assert a.external_id == "11111111-2222-4333-8444-555555555555|plugin:900001|TCP/443"
    assert Identifier("hostname", "pay-db-01") in a.subject.identifiers
    assert Identifier("hostname", "pay-db-01") in c.subject.identifiers     # same weak id, different asset uuid
    assert ev["summary"][0].supports_absence_inference is False


def _tenable_transport(script: list):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        assert request.headers["X-ApiKeys"] == "accessKey=ak;secretKey=sk"
        status, body, headers = script.pop(0)
        return httpx.Response(status, json=body if not isinstance(body, bytes) else None,
                              content=body if isinstance(body, bytes) else None, headers=headers)
    return httpx.MockTransport(handler), calls


def test_tenable_export_client_flow_with_rate_limit_and_duplicate_export():
    chunk = (FIX / "tenable/synthetic-vulns-chunk-1.json").read_bytes()
    transport, calls = _tenable_transport([
        (409, {"active_job_id": "exp-1", "failure_reason": "duplicate"}, {}),
        (429, {}, {"retry-after": "7"}),
        (200, {"status": "PROCESSING", "chunks_available": [1]}, {}),
        (200, {"status": "FINISHED", "chunks_available": [2, 1], "chunks_failed": [3], "chunks_cancelled": []}, {}),
        (200, chunk, {}),
    ])
    sleeps = []
    client = TenableExportClient("https://tenable.test.invalid", lambda: ("ak", "sk"), transport=transport,
                                 sleep=sleeps.append, poll_interval=1)
    export = client.request_export(filters={"state": ["OPEN", "REOPENED", "FIXED"], "since": 1760000000})
    assert export == "exp-1"                        # adopted the active duplicate export
    result = client.wait_for_export(export)
    assert result.status == "FINISHED" and result.chunks == [1, 2] and result.failed_chunks == [3]
    assert client.download_chunk(export, 1) == chunk
    assert sleeps[0] == 7.0                         # honoured retry-after
    assert calls[0] == ("POST", "/vulns/export")


def test_tenable_client_bounded_retries_and_expired_chunk():
    transport, _ = _tenable_transport([(503, {}, {})] * 3)
    client = TenableExportClient("https://t.invalid", lambda: ("ak", "sk"), transport=transport,
                                 sleep=lambda s: None, max_attempts=3)
    with pytest.raises(TenableApiError) as err:
        client.wait_for_export("x")
    assert err.value.retryable
    transport, _ = _tenable_transport([(404, {}, {})])
    client = TenableExportClient("https://t.invalid", lambda: ("ak", "sk"), transport=transport, sleep=lambda s: None)
    with pytest.raises(TenableApiError, match="expired") as err:
        client.download_chunk("x", 1)
    assert not err.value.retryable


# --------------------------------------------------------------------- Azure Resource Graph
def test_resource_graph_pages_and_parser():
    pages = [(FIX / "azure/synthetic-arg-page-1.json").read_bytes(), (FIX / "azure/synthetic-arg-page-2.json").read_bytes()]
    seen_tokens = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen_tokens.append(body["options"].get("$skipToken"))
        assert request.url.params["api-version"] == "2024-04-01"
        if len(seen_tokens) == 1:
            return httpx.Response(429, headers={"x-ms-user-quota-resets-after": "00:00:02"})
        page = pages[0] if body["options"].get("$skipToken") is None else pages[1]
        return httpx.Response(200, content=page, headers={"x-ms-user-quota-remaining": "10"})
    sleeps = []
    client = ResourceGraphClient(lambda: "tok", transport=httpx.MockTransport(handler), sleep=sleeps.append)
    got = list(client.pages(subscriptions=["00000000-1111-4222-8333-444444444444"]))
    assert [t for _, t in got] == ["c3ludGhldGljLXBhZ2UtMg==", None]
    assert seen_tokens == [None, None, "c3ludGhldGljLXBhZ2UtMg=="]
    assert 2.0 <= sleeps[0] <= 3.0
    ev = split(ResourceGraphPageParser().parse(got[0][0]))
    vm = ev["assets"][0]
    assert Identifier("azure_vm_id", "9a8b7c6d-5e4f-4321-8765-0fedcba98765") in vm.subject.identifiers
    assert vm.subject.kind == "host" and vm.context["owner_ref"] == "payments-team" and vm.context["criticality"] == "high"
    assert vm.external_id == vm.external_id.lower()


def test_identifier_strength_and_catalogue_honesty():
    assert identifier_strength("tenable_asset_uuid") == "strong" and identifier_strength("ipv4") == "weak"
    with pytest.raises(ValueError):
        identifier_strength("cve")
    levels = {row["name"]: row["support_level"] for row in catalogue()}
    assert levels["trivy_json"] == "fixture-tested" and levels["tenable_vm"] == "fixture-tested"
    assert "production-supported" not in levels.values() and "sandbox-validated" not in levels.values()
    assert levels["qualys_vmdr"] == "planned"
