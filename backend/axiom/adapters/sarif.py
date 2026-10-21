"""Generic SARIF 2.1.0 parser.

Schema reference: SARIF 2.1.0 (OASIS) via https://www.schemastore.org/sarif-2.1.0.json, checked 2026-10-22:
result.kind in {notApplicable, pass, fail, review, open, informational} (default 'fail');
result.level in {none, note, warning, error} (default 'warning'); suppression.status in
{accepted, underReview, rejected}; fingerprints/partialFingerprints are string maps.

Subject: run.versionControlProvenance[0] (repositoryUri + revisionId) when present,
otherwise the importer must declare it (recorded as an importer assertion).

Finding identity, in order of preference:
  1. a `fingerprints` entry (stable by definition),
  2. a `partialFingerprints` entry,
  3. fallback digest of (rule, artifact URI, region, location message): marked weak
     (line moves create new identities; nothing is merged on a weak guess).
Two results with the same identity in one run are quarantined as ambiguous rather than merged.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .base import (AdapterInfo, FindingRecord, Identifier, ParseError, ParseEvent, Quarantine, ScanSummary,
                   SubjectHints, SupportLevel, load_json, pointer, stable_digest)

INFO = AdapterInfo(
    name="sarif", version="1.0.0", adapter_kind="scanner", formats=("sarif-2.1.0",),
    operations=("file_import",), support_level=SupportLevel.FIXTURE_TESTED,
    validation_notes="Tested with real Trivy 0.76.1 SARIF and a synthetic code-scanning document. Not yet tested "
                     "with real CodeQL or Semgrep output; tool-specific mappings (CodeQL, Semgrep) are planned.",
    requires_declared_subject=False)

KINDS = {"notApplicable", "pass", "fail", "review", "open", "informational"}
LEVELS = {"none", "note", "warning", "error"}
FINDING_KINDS = {"fail", "review", "open"}


class SarifParser:
    info = INFO

    def parse(self, data: bytes, *, declared_subject: SubjectHints | None = None) -> Iterator[ParseEvent]:
        doc = load_json(data)
        if not isinstance(doc, dict) or doc.get("version") != "2.1.0" or not isinstance(doc.get("runs"), list):
            raise ParseError("not a SARIF 2.1.0 log (version and runs are required)")
        for run_index, run in enumerate(doc["runs"]):
            yield from self._run(run, run_index, declared_subject)

    def _run(self, run: Any, ri: int, declared: SubjectHints | None) -> Iterator[ParseEvent]:
        if not isinstance(run, dict) or not isinstance((run.get("tool") or {}).get("driver"), dict):
            yield Quarantine(pointer("runs", ri), "invalid_run", "run.tool.driver is required")
            return
        driver = run["tool"]["driver"]
        tool = driver.get("name")
        if not isinstance(tool, str) or not tool:
            yield Quarantine(pointer("runs", ri), "invalid_run", "tool.driver.name is required")
            return
        rules = driver.get("rules") if isinstance(driver.get("rules"), list) else []
        subject = self._subject(run) or declared
        if subject is None:
            raise ParseError("SARIF run has no versionControlProvenance; declare the subject at import")
        seen: dict[str, str] = {}
        non_findings = 0
        incomplete = any(isinstance(inv, dict) and inv.get("executionSuccessful") is False
                         for inv in run.get("invocations") or [])
        for i, result in enumerate(run.get("results") or []):
            loc = pointer("runs", ri, "results", i)
            event = self._result(result, loc, tool, rules, subject)
            if isinstance(event, FindingRecord):
                if event.external_id in seen:
                    yield Quarantine(loc, "ambiguous_identity",
                                     f"same identity as {seen[event.external_id]}; not merged", stable_digest(result))
                    continue
                seen[event.external_id] = loc
            if event is None:
                non_findings += 1
                continue
            yield event
        has_provenance = self._subject(run) is not None
        yield ScanSummary(
            tool=tool, tool_version=driver.get("semanticVersion") or driver.get("version"),
            complete=False if incomplete else None,
            completeness_reason=("an invocation reported executionSuccessful=false" if incomplete
                                 else "SARIF does not state analysis completeness"),
            supports_absence_inference=False if incomplete else has_provenance and bool(subject.deployment_digest),
            non_findings=non_findings)

    @staticmethod
    def _subject(run: dict) -> SubjectHints | None:
        vcp = run.get("versionControlProvenance")
        if not isinstance(vcp, list) or not vcp or not isinstance(vcp[0], dict):
            return None
        repo, rev = vcp[0].get("repositoryUri"), vcp[0].get("revisionId")
        if not isinstance(repo, str) or not repo:
            return None
        digest = f"git:{rev.lower()}" if isinstance(rev, str) and len(rev) in (40, 64) and all(
            c in "0123456789abcdefABCDEF" for c in rev) else None
        return SubjectHints(identifiers=(Identifier("repository_uri", repo.rstrip("/").removesuffix(".git")),),
                            kind="repository", display_name=repo, deployment_digest=digest,
                            version_label=vcp[0].get("branch"))

    @staticmethod
    def _rule_id(result: dict, rules: list) -> str | None:
        rid = result.get("ruleId")
        if isinstance(rid, str) and rid:
            return rid
        rule = result.get("rule")
        if isinstance(rule, dict) and isinstance(rule.get("id"), str):
            return rule["id"]
        idx = result.get("ruleIndex")
        if isinstance(idx, int) and 0 <= idx < len(rules) and isinstance(rules[idx], dict):
            return rules[idx].get("id")
        return None

    def _result(self, result: Any, loc: str, tool: str, rules: list, subject: SubjectHints) -> ParseEvent | None:
        if not isinstance(result, dict) or not isinstance((result.get("message") or {}), dict):
            return Quarantine(loc, "invalid_result", "result must be an object with a message", stable_digest(result))
        kind = result.get("kind", "fail")
        level = result.get("level", "warning")
        if kind not in KINDS:
            return Quarantine(loc, "invalid_kind", f"kind {kind!r} is not a SARIF 2.1.0 value", stable_digest(result))
        if level not in LEVELS:
            return Quarantine(loc, "invalid_level", f"level {level!r} is not a SARIF 2.1.0 value", stable_digest(result))
        if kind not in FINDING_KINDS:
            return None   # pass / notApplicable / informational are not findings
        rule_id = self._rule_id(result, rules)
        if not rule_id:
            return Quarantine(loc, "unresolved_rule", "no ruleId, rule.id or valid ruleIndex", stable_digest(result))
        locations = result.get("locations") or []
        phys = (locations[0] or {}).get("physicalLocation") or {} if locations and isinstance(locations[0], dict) else {}
        art = phys.get("artifactLocation") or {}
        region = phys.get("region") or {}
        uri = art.get("uri") if isinstance(art.get("uri"), str) else None
        loc_message = ((locations[0] or {}).get("message") or {}).get("text") if locations and isinstance(
            locations[0], dict) else None
        component = f"{uri or '?'}:{region.get('startLine', '')}" + (f" {loc_message}" if loc_message else "")
        fps = result.get("fingerprints") if isinstance(result.get("fingerprints"), dict) else {}
        pfps = result.get("partialFingerprints") if isinstance(result.get("partialFingerprints"), dict) else {}
        if fps:
            key = sorted(fps)[-1]
            identity, strength = f"fp:{key}={fps[key]}", "fingerprint"
        elif pfps:
            key = sorted(pfps)[-1]
            identity, strength = f"pfp:{key}={pfps[key]}", "partial_fingerprint"
        else:
            identity = "weak:" + stable_digest([rule_id, uri, region.get("startLine"), region.get("startColumn"),
                                                loc_message])[:32]
            strength = "weak_location"
        suppressions = result.get("suppressions") if isinstance(result.get("suppressions"), list) else []
        suppressed = any(isinstance(s, dict) and s.get("status", "accepted") == "accepted" for s in suppressions)
        normalised = {"tool": tool, "rule_id": rule_id, "kind": kind, "level": level, "uri": uri,
                      "uri_base_id": art.get("uriBaseId"), "start_line": region.get("startLine"),
                      "identity_basis": strength, "baseline_state": result.get("baselineState"),
                      "suppressed": suppressed}
        return FindingRecord(
            locator=loc, external_id=f"{tool}|{rule_id}|{identity}",
            version_key=stable_digest({"level": level, "kind": kind, "suppressed": suppressed}),
            subject=subject, component_locator=component[:1000], vulnerability_ref=rule_id,
            title=(result["message"].get("text") or "")[:500] or None, source_severity=level,
            source_status="suppressed" if suppressed else "open", source_time=None,
            normalised=normalised, source_fields=result)
