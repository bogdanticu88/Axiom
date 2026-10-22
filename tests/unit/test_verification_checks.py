"""Explicit outcome rules of the verification worker (axiom.verification.checks, ADR 0014)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from axiom.domains.cases import model
from axiom.verification import checks

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
REPORTED = NOW - timedelta(minutes=30)
TARGET = "sha256:" + "b" * 64
OTHER = "sha256:" + "c" * 64


def body(**over):
    doc = {"schema": "axiom-check/2", "request_id": "job-1", "nonce": "n-1", "asset_id": "asset-1", "observed_at": (NOW - timedelta(minutes=1)).isoformat(),
           "deployment_digest": TARGET, "coverage": "complete",
           "results": [{"criterion": "original_condition", "result": "absent"}]}
    doc.update(over)
    return json.dumps({k: v for k, v in doc.items() if v is not ...}).encode()


def assess(raw: bytes, status: int = 200, truncated: bool = False):
    ex = checks.Exchange(status, raw, truncated, NOW - timedelta(seconds=1), NOW)
    return checks.assess(ex, request_id="job-1", nonce="n-1", asset_id="asset-1", criteria=["original_condition"],
                         target_digest=TARGET,
                         change_reported_at=REPORTED, max_age=timedelta(hours=1))


def r(result):
    return [{"criterion": "original_condition", "result": result}]


CASES = [
    ("clean", body(), "passed", "complete", "condition_absent"),
    ("present", body(results=r("present")), "failed", "complete", "condition_present"),
    ("present partial", body(results=r("present"), coverage="partial"), "failed", "partial", "condition_present"),
    ("404", body(), "inconclusive", "none", "target_refused"),
    ("truncated", body(), "inconclusive", "none", "malformed_response"),
    ("not json", b"<html>", "inconclusive", "none", "malformed_response"),
    ("wrong schema", body(schema="axiom-check/1"), "inconclusive", "none", "malformed_response"),
    ("other request", body(request_id="job-2"), "inconclusive", "none", "unbound_response"),
    ("other nonce", body(nonce="n-2"), "inconclusive", "none", "unbound_response"),
    ("no nonce", body(nonce=...), "inconclusive", "none", "unbound_response"),
    ("other asset", body(asset_id="asset-2"), "inconclusive", "none", "unbound_response"),
    ("generic success", json.dumps({"schema": "axiom-check/2", "status": "ok", "coverage": "complete",
                                    "results": []}).encode(), "inconclusive", "none", "unbound_response"),
    ("no coverage", body(coverage=...), "inconclusive", "none", "malformed_response"),
    ("bad entry", body(results=[{"criterion": "original_condition", "result": "maybe"}]), "inconclusive", "none",
     "malformed_response"),
    ("no digest", body(deployment_digest=...), "inconclusive", "none", "deployment_unknown"),
    ("bad digest", body(deployment_digest="latest"), "inconclusive", "none", "deployment_unknown"),
    ("no time", body(observed_at=...), "inconclusive", "none", "observation_time_unknown"),
    ("naive time", body(observed_at="2026-10-22T11:59:00"), "inconclusive", "none", "observation_time_unknown"),
    ("future", body(observed_at=(NOW + timedelta(minutes=6)).isoformat()), "inconclusive", "none",
     "observation_time_in_future"),
    ("small skew ok", body(observed_at=(NOW + timedelta(minutes=4)).isoformat()), "passed", "complete",
     "condition_absent"),
    ("stale", body(observed_at=(NOW - timedelta(hours=2)).isoformat()), "inconclusive", "none", "observation_stale"),
    ("predates", body(observed_at=(REPORTED - timedelta(seconds=1)).isoformat()), "inconclusive", "none",
     "observation_predates_change"),
    ("other deployment", body(deployment_digest=OTHER), "inconclusive", "none", "different_deployment"),
    ("other deployment present", body(deployment_digest=OTHER, results=r("present")), "inconclusive", "none",
     "different_deployment"),
    ("contradiction", body(results=r("absent") + r("present")), "inconclusive", "none", "contradictory_results"),
    ("duplicate agreeing", body(results=r("absent") + r("absent")), "passed", "complete", "condition_absent"),
    ("missing criterion", body(results=[]), "inconclusive", "partial", "incomplete_coverage"),
    ("only other criterion", body(results=[{"criterion": "x", "result": "absent"}]), "inconclusive", "partial",
     "incomplete_coverage"),
    ("error", body(results=r("error")), "inconclusive", "partial", "incomplete_coverage"),
    ("partial", body(coverage="partial"), "inconclusive", "partial", "incomplete_coverage"),
]


@pytest.mark.parametrize("name,raw,claimed,coverage,rule", CASES, ids=[c[0] for c in CASES])
def test_rules(name, raw, claimed, coverage, rule):
    a = assess(raw, status=404 if name == "404" else 200, truncated=name == "truncated")
    assert (a.claimed, a.coverage, a.rule) == (claimed, coverage, rule)


def test_only_a_matching_complete_clean_check_with_verified_evidence_passes_after_the_service_recomputes():
    for name, raw, *_ in CASES:
        a = assess(raw, status=404 if name == "404" else 200, truncated=name == "truncated")
        matches = None if a.observed_digest is None else a.observed_digest == TARGET
        for evidence in (True, False):
            outcome, _ = model.verification_outcome(claimed=a.claimed, coverage=a.coverage,
                                                    observed_matches_target=matches, evidence_verified=evidence)
            assert (outcome == "passed") == (a.rule == "condition_absent" and evidence), name


def test_origin_strips_credentials_paths_and_queries():
    assert checks.origin("https://user:pw@check.example:8443/base/path?q=1") == "https://check.example:8443"


# ----------------------------------------------------------------------------------------- destination policy
POLICY = checks.DestinationPolicy.from_settings("https://checks.example:8443, https://scan.example")


@pytest.mark.parametrize("url", ["https://checks.example:8443", "https://CHECKS.example:8443/base", "https://scan.example",
                                 "https://scan.example:443"])
def test_allowed_origins(url):
    POLICY.check_origin(url)


@pytest.mark.parametrize("url", ["https://checks.example", "https://checks.example:9443", "http://scan.example",
                                 "https://evil.example", "https://user:pw@scan.example", "https://scan.example.evil.test"])
def test_refused_origins(url):
    with pytest.raises(checks.DestinationRefused):
        POLICY.check_origin(url)


def test_nothing_is_allowed_by_default():
    with pytest.raises(checks.DestinationRefused):
        checks.DestinationPolicy().check_origin("https://scan.example")


@pytest.mark.parametrize("addresses", [["127.0.0.1"], ["169.254.169.254"], ["::1"], ["fe80::1"], ["0.0.0.0"],
                                       ["10.0.0.5", "127.0.0.1"], []])
def test_default_address_rules_refuse_local_and_metadata_ranges(addresses):
    with pytest.raises(checks.DestinationRefused):
        POLICY.check_addresses(addresses)


def test_private_addresses_are_allowed_by_default_and_networks_narrow_them():
    POLICY.check_addresses(["10.0.0.5", "192.168.1.10", "203.0.113.7"])
    narrow = checks.DestinationPolicy.from_settings("https://scan.example", "10.20.0.0/16")
    narrow.check_addresses(["10.20.1.1"])
    for bad in (["10.21.0.1"], ["203.0.113.7"], ["10.20.1.1", "10.30.0.1"]):
        with pytest.raises(checks.DestinationRefused):
            narrow.check_addresses(bad)
    checks.DestinationPolicy.from_settings("https://x.example", "127.0.0.0/8").check_addresses(["127.0.0.1"])
