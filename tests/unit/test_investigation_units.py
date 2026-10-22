"""Unit tests: claim validation rules, output schema, redaction, and the Anthropic adapter against documented shapes.

The Anthropic tests use a local transport returning the shapes in the public documentation; they do not show that
the live service behaves this way (never called: no credentials or external access authorised).
"""
from __future__ import annotations

import json

import httpx
import pytest

from axiom.investigation.claims import validate_claim
from axiom.investigation.providers import AnthropicMessagesProvider, ModelRequest, ProviderError
from axiom.investigation.redaction import redact
from axiom.investigation.schema import Claim, MalformedOutput, parse_round

V, W, A = "CVE-2024-0001", "CVE-2024-0002", "11111111-1111-1111-1111-111111111111"
D1, D2 = "d1000000-0000-0000-0000-000000000001", "d2000000-0000-0000-0000-000000000002"   # two deployments
OCC_V, OCC_W, OCC_V2 = "occ-v-d1", "occ-w-d1", "occ-v-d2"


def m(key, kind, *, vuln=V, asset=A, dep=D1, status=None, freshness="fresh", cls=None, available=True, ref=None,
      **attrs):
    a = {"vulnerability_ref": vuln, "asset_id": asset, "asset_version_id": dep, **attrs}
    if kind == "occurrence_observation":
        a["observed_status"] = status
    if kind == "observation":
        a["observation_type"] = {"present": "finding_reported", "fixed_by_source": "finding_fixed_by_source"}[status]
    ref = ref or (asset if kind == "asset" else f"ref-{key}")
    return {"member_key": key, "kind": kind, "ref_id": ref, "classification": cls, "freshness": freshness,
            "available": available, "attributes": a}


MEMBERS = {x["member_key"]: x for x in [
    m("M001", "occurrence", freshness="not_applicable", source_severity="HIGH", ref=OCC_V),
    m("M002", "asset", freshness="not_applicable"),
    m("M003", "occurrence_observation", status="present", occurrence_id=OCC_V, scan_time="2026-10-01T00:00:00+00:00"),
    m("M004", "occurrence_observation", status="absent_in_complete_scan", occurrence_id=OCC_V,
      scan_time="2026-09-15T00:00:00+00:00"),
    m("M005", "occurrence_observation", vuln=W, status="present", occurrence_id=OCC_W),
    m("M006", "occurrence", vuln=W, freshness="not_applicable", ref=OCC_W),
    m("M007", "occurrence_observation", status="present", freshness="stale", occurrence_id=OCC_V),
    m("M008", "observation", status="present", cls="confidential"),
    m("M009", "observation", status="present", available=False, cls="internal"),
    m("M010", "observation", status="present", cls="internal", normalised={"fixed_version": None}),
]}


def claim(attr="present_in_deployment", conclusion="supported", sup=(), con=(), vuln=V, limitations=None, dep=None,
          statement="s"):
    subject = {"vulnerability_ref": vuln, "asset_id": A, "attribute": attr}
    if dep:
        subject["asset_version_id"] = dep
    return Claim.model_validate({"question_id": "q1", "statement": statement, "subject": subject,
                                 "conclusion": conclusion, "supporting": list(sup), "contradicting": list(con),
                                 "limitations": limitations})


def check(c, contradictions=(), route="confidential", readable=True, members=None):
    return validate_claim(c, members or MEMBERS, list(contradictions), route_max=route, can_read=lambda p: readable)


def contra(ordering="by_scan_time", latest="present", keys=("M001", "M003", "M004"), occ=OCC_V, reason="x"):
    c = {"kind": "presence_disagreement", "occurrence_id": occ, "vulnerability_ref": V, "member_keys": list(keys),
         "ordering": ordering, "ordering_reason": reason}
    if ordering == "by_scan_time":
        c.update(latest_status=latest, latest_scan_time="2026-10-01T00:00:00+00:00")
    return c


@pytest.mark.parametrize("c,code", [
    (claim(sup=["M999"]), "fabricated_reference"),
    (claim(sup=["M005"]), "subject_mismatch"),                        # valid member, other vulnerability identifier
    (claim(sup=["M004"]), "status_conflicts_with_citation"),          # 'absent' cited as support for presence
    (claim(conclusion="contradicted", con=["M003"]), "status_conflicts_with_citation"),
    (claim(sup=["M002"]), "conclusion_without_reference"),            # an asset record does not show presence
    (claim(sup=["M009"]), "reference_unavailable"),                   # unverified evidence
    (claim(vuln="CVE-2099-9", sup=["M003"]), "subject_not_in_snapshot"),
    (claim(dep=D2, sup=["M003"]), "subject_not_in_snapshot"),         # deployment not affected in this snapshot
])
def test_rejections(c, code):
    r = check(c)
    assert (r.validation, r.accepted) == ("rejected", None) and r.reasons[0]["code"] == code


def test_classification_and_permission_make_references_unavailable():
    assert check(claim(sup=["M008"]), route="internal").reasons[0]["code"] == "reference_unavailable"
    assert check(claim(sup=["M008"]), readable=False).reasons[0]["code"] == "reference_unavailable"
    assert check(claim(sup=["M008"])).validation == "references_checked"


def test_downgrades():
    c = [contra()]
    r = check(claim(sup=["M003"]), c)
    assert (r.validation, r.accepted, r.reasons[0]["code"]) == ("downgraded", "unknown", "ignores_recorded_contradiction")
    assert check(claim(sup=["M003"], con=["M004"]), c).validation == "references_checked"
    r = check(claim(sup=["M007"]))
    assert (r.accepted, r.reasons[0]["code"]) == ("unknown", "stale_evidence_only")
    r = check(claim(attr="exposure", sup=["M003"]))
    assert (r.accepted, r.reasons[0]["code"]) == ("unknown", "attribute_not_established")


def test_defensible_ordering_downgrades_a_conclusion_against_the_latest_scan():
    c = [contra(latest="absent_in_complete_scan")]
    r = check(claim(sup=["M003"], con=["M004"]), c)
    assert (r.validation, r.accepted, r.reasons[-1]["code"]) == ("downgraded", "unknown", "latest_observation_disagrees")
    ok = check(claim(conclusion="contradicted", sup=["M003"], con=["M004"]), c)
    assert (ok.validation, ok.accepted) == ("references_checked", "contradicted")


# ---- the five required cases (record-level rules; statement text is never read)
def test_a_valid_reference_that_does_not_support_the_claim():
    # structured field shows no fix, cited for "fix available": rejected
    r = check(claim(attr="fix_available", sup=["M010"]))
    assert (r.validation, r.reasons[0]["code"]) == ("rejected", "conclusion_without_reference")
    # the statement text is not checked: this passes the record checks although the statement does not follow;
    # it is stored with entailment = not_verified and needs a person
    r = check(claim(attr="severity_as_reported", sup=["M001"],
                    statement="openssl 3.0 on every host is remotely exploitable"))
    assert (r.validation, r.accepted) == ("references_checked", "supported")


def test_newer_evidence_about_a_different_deployment_does_not_decide_this_one():
    two = dict(MEMBERS)
    two["M011"] = m("M011", "occurrence", dep=D2, freshness="not_applicable", ref=OCC_V2)
    two["M012"] = m("M012", "occurrence_observation", dep=D2, status="absent_in_complete_scan", occurrence_id=OCC_V2,
                    scan_time="2026-10-20T00:00:00+00:00")
    # D2's newer absence cannot be cited against D1
    r = check(claim(dep=D1, conclusion="contradicted", sup=["M003"], con=["M012"]), members=two)
    assert (r.validation, r.reasons[0]["code"]) == ("rejected", "subject_mismatch")
    ok = check(claim(dep=D1, sup=["M003"]), members=two)
    assert (ok.validation, ok.accepted) == ("references_checked", "supported")
    # without naming the deployment, a presence conclusion over two deployments is not accepted
    r = check(claim(sup=["M003"]), members=two)
    assert (r.accepted, r.reasons[0]["code"]) == ("unknown", "deployment_unspecified")


def test_newer_but_incomplete_evidence_does_not_establish_absence():
    part = dict(MEMBERS)
    part["M013"] = m("M013", "ingestion_run", freshness="fresh", coverage="partial")
    # a newer partial run records nothing about the finding; citing it cannot establish absence
    r = check(claim(attr="absent_in_deployment", sup=["M013"]), members=part)
    assert (r.validation, r.reasons[0]["code"]) == ("rejected", "conclusion_without_reference")


def test_conflicting_observations_without_a_defensible_ordering_stay_open():
    for reason in ("conflicting observations carry the same latest scan time",
                   "observations come from different sources", "the source reported no scan time"):
        c = [contra(ordering="undetermined", reason=reason)]
        for cl in (claim(sup=["M003"], con=["M004"]), claim(conclusion="contradicted", sup=["M003"], con=["M004"])):
            r = check(cl, c)
            assert (r.accepted, r.validation) == ("unknown", "downgraded")
            assert any(x["code"] == "unresolved_contradiction" and reason in x["message"] for x in r.reasons)
        ok = check(claim(conclusion="unknown", sup=["M003"], con=["M004"], limitations="unresolved"), c)
        assert (ok.validation, ok.accepted) == ("references_checked", "unknown")


def test_multiple_claims_some_supported_some_unresolved():
    c = [contra(ordering="undetermined", reason="same latest scan time")]
    results = [check(claim(attr="severity_as_reported", sup=["M001"]), c),
               check(claim(sup=["M003"], con=["M004"]), c),
               check(claim(vuln=W, sup=["M005"]), c)]
    assert [(r.validation, r.accepted) for r in results] == [
        ("references_checked", "supported"), ("downgraded", "unknown"), ("references_checked", "supported")]


def test_valid_references_still_carry_no_entailment_claim():
    r = check(claim(sup=["M003"]))
    assert (r.validation, r.accepted) == ("references_checked", "supported")
    assert r.refs == [("supports", "M003")]
    u = check(claim(conclusion="unknown", sup=["M003"]))
    assert u.accepted == "unknown" and u.reasons[0]["code"] == "no_limitation_stated"


@pytest.mark.parametrize("text", [
    "not json", "[]", '{"done": true, "dismiss": true}', '{"done": true, "priority": "low"}',
    '{"done": true, "claims": [{"question_id": "q1", "statement": "x", "subject": {"attribute": "anything"},'
    ' "conclusion": "supported"}]}',
    '{"done": true, "claims": [{"question_id": "q1", "statement": "x", "subject": {"attribute": "exposure"},'
    ' "conclusion": "supported", "model_stated_confidence": 0.93}]}',
])
def test_schema_refuses_actions_unknown_fields_and_numeric_confidence(text):
    with pytest.raises(MalformedOutput):
        parse_round(text)


def test_schema_accepts_a_fenced_object():
    out = parse_round('```json\n{"done": true, "claims": [], "tool_requests": [], "next_checks": []}\n```')
    assert out.done


@pytest.mark.parametrize("secret,kind", [
    ("AKIA" + "ABCDEFGHIJKLMNOP", "aws_access_key"),
    ("-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow\n-----END RSA " + "PRIVATE KEY-----", "private_key"),  # split: secret scan
    ("Authorization: Bearer abcdefghijklmnopqrstuvwx", "bearer"),
    ("postgres://app:hunter2secret@db.internal:5432/x", "url_credentials"),
    ("password=CorrectHorseBattery", "key_value_secret"),
    ("ghp_" + "a" * 36, "github_token"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "jwt"),
])
def test_redaction(secret, kind):
    out, n = redact(f"context {secret} more")
    assert n >= 1 and f"[REDACTED:{kind}]" in out
    assert "hunter2secret" not in out and "CorrectHorseBattery" not in out and "ABCDEFGHIJKLMNOP" not in out


# ------------------------------------------------------------------------------- Anthropic (documented shapes)
def provider(handler):
    return AnthropicMessagesProvider("https://api.anthropic.test", "model-x", lambda: "key-1",
                                     transport=httpx.MockTransport(handler))


def test_anthropic_request_and_response_shapes():
    seen = {}

    def ok(req):
        seen.update(url=str(req.url), headers=dict(req.headers), body=json.loads(req.content))
        return httpx.Response(200, headers={"request-id": "req_1"}, json={
            "id": "msg_1", "type": "message", "role": "assistant", "model": "model-x", "stop_reason": "end_turn",
            "content": [{"type": "text", "text": '{"done": true}'}], "usage": {"input_tokens": 12, "output_tokens": 3}})
    r = provider(ok).complete(ModelRequest(system="sys", user="u", max_output_tokens=100, timeout_seconds=5))
    assert seen["url"] == "https://api.anthropic.test/v1/messages"
    assert seen["headers"]["x-api-key"] == "key-1" and seen["headers"]["anthropic-version"] == "2023-06-01"
    assert seen["body"] == {"model": "model-x", "max_tokens": 100, "system": "sys",
                            "messages": [{"role": "user", "content": "u"}]}
    assert (r.text, r.input_tokens, r.output_tokens, r.provider_request_id) == ('{"done": true}', 12, 3, "req_1")


@pytest.mark.parametrize("status,etype,retryable", [
    (429, "rate_limit_error", True), (529, "overloaded_error", True), (500, "api_error", True),
    (504, "timeout_error", True), (400, "invalid_request_error", False), (401, "authentication_error", False),
])
def test_anthropic_errors(status, etype, retryable):
    p = provider(lambda req: httpx.Response(status, json={"type": "error", "error": {"type": etype, "message": "m"},
                                                          "request_id": "req_2"}))
    with pytest.raises(ProviderError) as err:
        p.complete(ModelRequest(system="s", user="u", max_output_tokens=10, timeout_seconds=5))
    assert (err.value.kind, err.value.retryable, err.value.status) == (etype, retryable, status)


def test_anthropic_refusal_and_timeout():
    p = provider(lambda req: httpx.Response(200, json={"content": [], "stop_reason": "refusal", "usage": {}}))
    with pytest.raises(ProviderError) as err:
        p.complete(ModelRequest(system="s", user="u", max_output_tokens=10, timeout_seconds=5))
    assert (err.value.kind, err.value.retryable) == ("refusal", False)

    def slow(req):
        raise httpx.ReadTimeout("timed out", request=req)
    with pytest.raises(ProviderError) as err:
        provider(slow).complete(ModelRequest(system="s", user="u", max_output_tokens=10, timeout_seconds=1))
    assert (err.value.kind, err.value.retryable) == ("timeout", True)
    with pytest.raises(ValueError):
        AnthropicMessagesProvider("http://api.anthropic.test", "m", lambda: "k")
