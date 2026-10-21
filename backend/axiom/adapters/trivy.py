"""Trivy JSON report parser (SchemaVersion 2).

Format reference: https://trivy.dev/latest/docs/configuration/reporting/ (checked 2026-10-22).
Fixture: real Trivy 0.76.1 output (tests/fixtures/PROVENANCE.md). Support level:
fixture-tested for container image reports. Filesystem/repository reports parse, but
their subject must be declared by the importer.

Occurrence identity: artifact (asset + deployment) + package identity (PURL, else PkgID,
else name@version) + vulnerability ID. A CVE alone is never the identity.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .base import (AdapterInfo, FindingRecord, Identifier, ParseError, ParseEvent, Quarantine, ScanSummary,
                   SubjectHints, SupportLevel, load_json, parse_time, pointer, stable_digest)

INFO = AdapterInfo(
    name="trivy_json", version="1.0.0", adapter_kind="scanner", formats=("trivy-json-schema-2",),
    operations=("file_import",), support_level=SupportLevel.FIXTURE_TESTED,
    validation_notes="Parsed real Trivy 0.76.1 container-image output. Not validated against other Trivy "
                     "versions, filesystem, SBOM or Kubernetes report types.")

_SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _repository(ref: str) -> str:
    """'registry/repo@sha256:..' or 'registry/repo:tag' -> 'registry/repo'."""
    base = ref.split("@", 1)[0]
    last = base.rsplit("/", 1)[-1]
    if ":" in last:
        base = base[: len(base) - len(last)] + last.split(":", 1)[0]
    return base


class TrivyParser:
    info = INFO

    def parse(self, data: bytes, *, declared_subject: SubjectHints | None = None) -> Iterator[ParseEvent]:
        doc = load_json(data)
        if not isinstance(doc, dict) or doc.get("SchemaVersion") != 2 or not isinstance(doc.get("Results", []), list):
            raise ParseError("not a Trivy JSON report with SchemaVersion 2")
        subject = declared_subject or self._subject(doc)
        if subject is None:
            raise ParseError("report does not identify its subject; declare the subject at import")
        created = parse_time(doc.get("CreatedAt"))
        count = 0
        for ri, result in enumerate(doc.get("Results") or []):
            target = result.get("Target")
            for vi, vuln in enumerate(result.get("Vulnerabilities") or []):
                loc = pointer("Results", ri, "Vulnerabilities", vi)
                record = self._finding(vuln, loc, subject, target, result, created)
                count += 1
                yield record
        yield ScanSummary(
            tool="trivy", tool_version=(doc.get("Trivy") or {}).get("Version"), complete=True if subject.deployment_digest else None,
            completeness_reason=("full report for one identified image digest" if subject.deployment_digest
                                 else "subject has no deployment digest; completeness unknown"),
            supports_absence_inference=bool(subject.deployment_digest))

    @staticmethod
    def _subject(doc: dict) -> SubjectHints | None:
        meta = doc.get("Metadata") or {}
        if doc.get("ArtifactType") != "container_image":
            return None
        digests = [d for d in (meta.get("RepoDigests") or []) if isinstance(d, str) and "@sha256:" in d]
        name = doc.get("ArtifactName")
        if digests:
            repo, digest = digests[0].split("@", 1)
        elif isinstance(name, str) and name:
            # No registry digest (e.g. a tarball scan): the image config ID is NOT a registry digest,
            # so it is kept as a label only and verification cannot match it to a deployment.
            repo, digest = _repository(name), None
        else:
            return None
        tag = None
        if isinstance(name, str) and "@" not in name and ":" in name.rsplit("/", 1)[-1]:
            tag = name.rsplit(":", 1)[-1]
        label = tag or (meta.get("ImageID") and f"image-config {meta['ImageID']}")
        return SubjectHints(identifiers=(Identifier("image_repository", _repository(repo)),),
                            kind="container_image", display_name=_repository(repo),
                            deployment_digest=digest, version_label=label)

    @staticmethod
    def _finding(vuln: Any, loc: str, subject: SubjectHints, target: Any, result: dict, created) -> ParseEvent:
        if not isinstance(vuln, dict):
            return Quarantine(loc, "not_an_object", "vulnerability entry is not an object", stable_digest(vuln))
        vid, pkg, installed = vuln.get("VulnerabilityID"), vuln.get("PkgName"), vuln.get("InstalledVersion")
        if not (isinstance(vid, str) and vid and isinstance(pkg, str) and pkg and isinstance(installed, str)):
            return Quarantine(loc, "missing_required_field",
                              "VulnerabilityID, PkgName and InstalledVersion are always populated by Trivy",
                              stable_digest(vuln))
        severity = vuln.get("Severity")
        if severity is not None and severity not in _SEVERITIES:
            return Quarantine(loc, "invalid_severity", f"unexpected Severity {severity!r}", stable_digest(vuln))
        ident = vuln.get("PkgIdentifier") or {}
        component = ident.get("PURL") or vuln.get("PkgID") or f"{pkg}@{installed}"
        normalised = {"vulnerability_id": vid, "package": pkg, "installed_version": installed,
                      "fixed_version": vuln.get("FixedVersion") or None, "fix_status": vuln.get("Status"),
                      "severity": severity, "class": result.get("Class"), "type": result.get("Type"),
                      "target": target}
        return FindingRecord(
            locator=loc, external_id=f"{component}|{vid}",
            version_key=stable_digest({k: normalised[k] for k in ("fixed_version", "fix_status", "severity")}),
            subject=subject, component_locator=component, vulnerability_ref=vid,
            title=vuln.get("Title") if isinstance(vuln.get("Title"), str) else None, source_severity=severity,
            source_status="open", source_time=created, normalised=normalised, source_fields=vuln)
