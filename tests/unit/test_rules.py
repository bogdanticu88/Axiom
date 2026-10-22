"""Pure rule tests: case model, verification outcomes, permission evaluation, tokens, configuration.

Includes the intent of the eight supplied foundation tests
(docs/design-inputs/original-foundation/test_domain.py), ported to the new model.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from axiom.access import PermissionDenied, RoleBinding, evaluate, priority_rank
from axiom.auth.tokens import TokenVerifier
from axiom.config import Settings, TrustedIssuer
from axiom.domains.cases import model
from axiom.domains.cases.model import ALLOWED, ClosureReason, Workflow
from axiom.errors import ConfigurationError, Conflict, Unauthenticated

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------------ case model
def test_transition_table_matches_specification():
    spec = {("received", "investigating"), ("investigating", "review_required"),
            ("review_required", "investigating"), ("review_required", "remediation_planned"),
            ("remediation_planned", "remediating"), ("remediating", "awaiting_verification"),
            # R7, approved 2026-10-22 (Specification S 4 amendment)
            ("remediation_planned", "review_required"), ("remediating", "review_required"),
            ("awaiting_verification", "closed"), ("awaiting_verification", "remediating"),
            ("awaiting_verification", "review_required"), ("review_required", "closed"),
            ("closed", "investigating")}
    actual = {(a.value, b.value) for a, targets in ALLOWED.items() for b in targets}
    assert actual == spec


@pytest.mark.parametrize("src,dst", [("received", "closed"), ("remediating", "closed"),
                                     ("investigating", "closed"), ("closed", "review_required")])
def test_cannot_skip_states(src, dst):
    with pytest.raises(Conflict):
        model.check_transition(src, dst)


def test_stale_writer_rejected():
    with pytest.raises(Conflict) as err:
        model.check_expected_version(3, 2)
    assert err.value.code == "stale_version"


def test_closure_origin():
    assert model.closure_origin(ClosureReason.VERIFIED_REMEDIATED) is Workflow.VERIFYING
    for reason in (ClosureReason.ACCEPTED_RISK, ClosureReason.DISMISSED, ClosureReason.DUPLICATE,
                   ClosureReason.ASSET_RETIRED):
        assert model.closure_origin(reason) is Workflow.REVIEW


def test_ticket_closed_is_not_a_closure_reason():
    with pytest.raises(ValueError):
        ClosureReason("ticket_closed")


@pytest.mark.parametrize("claimed,coverage,matches,evidence,expected", [
    ("passed", "complete", True, True, "passed"),
    ("passed", "complete", False, True, "inconclusive"),    # wrong deployment (A18)
    ("passed", "complete", None, True, "inconclusive"),     # unknown deployment
    ("passed", "partial", True, True, "inconclusive"),      # partial scan
    ("passed", "none", True, True, "inconclusive"),
    ("passed", "complete", True, False, "inconclusive"),    # no verified evidence
    ("failed", "complete", True, True, "failed"),
    ("failed", "complete", False, True, "inconclusive"),    # failure on another deployment says nothing
    ("inconclusive", "complete", True, True, "inconclusive"),
])
def test_verification_outcome(claimed, coverage, matches, evidence, expected):
    outcome, _ = model.verification_outcome(claimed=claimed, coverage=coverage,
                                            observed_matches_target=matches, evidence_verified=evidence)
    assert outcome == expected


def test_unknown_priority_is_conservative():
    assert priority_rank("pending") == priority_rank("urgent")


# ------------------------------------------------------------------ permissions
T, P, ROOT, PROJECT, SIBLING = (uuid.uuid4() for _ in range(5))
PERMS = {"analyst": frozenset({"case.read", "investigation.request"}), "viewer": frozenset({"case.read"})}


def binding(**kw):
    base = dict(id=uuid.uuid4(), tenant_id=T, principal_id=P, role_id="analyst", scope_id=PROJECT,
                valid_from=NOW - timedelta(days=1), valid_until=None, revoked_at=None)
    base.update(kw)
    return RoleBinding(**base)


def check(bindings, permission="investigation.request", lineage=(PROJECT, ROOT), **kw):
    args = dict(tenant_id=T, principal_id=P, permission=permission, scope_lineage=lineage, now=NOW)
    args.update(kw)
    return evaluate(bindings, PERMS, **args)


def test_binding_covers_descendants_not_ancestors_or_siblings():
    child = uuid.uuid4()
    assert check([binding()], lineage=(child, PROJECT, ROOT)).binding_ids
    with pytest.raises(PermissionDenied):
        check([binding()], lineage=(ROOT,))
    with pytest.raises(PermissionDenied):
        check([binding()], lineage=(SIBLING, ROOT))
    assert check([binding(scope_id=ROOT)], lineage=(PROJECT, ROOT)).scope_id == PROJECT


@pytest.mark.parametrize("override", [dict(tenant_id=uuid.uuid4()), dict(principal_id=uuid.uuid4()),
                                      dict(permission="risk.accept")])
def test_permissions_cannot_cross_boundaries(override):
    with pytest.raises(PermissionDenied):
        check([binding()], **override)


@pytest.mark.parametrize("kw", [dict(valid_until=NOW), dict(revoked_at=NOW - timedelta(seconds=1)),
                                dict(valid_from=NOW + timedelta(seconds=1)), dict(role_id="viewer")])
def test_expired_revoked_future_and_wrong_role_denied(kw):
    with pytest.raises(PermissionDenied):
        check([binding(**kw)])


def test_naive_time_rejected():
    with pytest.raises(ValueError):
        binding().active_at(datetime(2026, 1, 1))


def test_authority_records_matching_bindings():
    b1, b2 = binding(), binding(scope_id=ROOT)
    authority = check([b1, b2, binding(role_id="viewer")])
    assert set(authority.binding_ids) == {b1.id, b2.id} and authority.roles == ("analyst",)


# ----------------------------------------------------------------------- tokens
@pytest.fixture(scope="module")
def keys():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048), \
        rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks(key, kid="k1"):
    import json
    from jwt.algorithms import RSAAlgorithm
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid=kid, alg="RS256", use="sig")
    return {"keys": [jwk]}


def _token(key, kid="k1", alg="RS256", **claims):
    now = int(time.time())
    body = {"iss": "https://idp", "aud": "axiom", "sub": "u1", "iat": now, "exp": now + 60}
    body.update(claims)
    return jwt.encode({k: v for k, v in body.items() if v is not None}, key, algorithm=alg, headers={"kid": kid})


def test_token_verification(keys):
    good, other = keys
    v = TokenVerifier([TrustedIssuer(issuer="https://idp", audience="axiom", jwks=_jwks(good))])
    assert v.verify(_token(good)).subject == "u1"
    bad_tokens = [
        _token(other),                                   # wrong key
        _token(good, kid="unknown"),                     # unknown kid
        _token(good, iss="https://evil"),                # untrusted issuer
        _token(good, aud="other"),                       # wrong audience
        _token(good, exp=int(time.time()) - 3600),       # expired
        _token(good, sub=None),                          # missing subject
        jwt.encode({"iss": "https://idp", "aud": "axiom", "sub": "u1", "iat": int(time.time()),
                    "exp": int(time.time()) + 60}, "x" * 32, algorithm="HS256", headers={"kid": "k1"}),
        "not-a-jwt",
    ]
    for token in bad_tokens:
        with pytest.raises(Unauthenticated):
            v.verify(token)


# ------------------------------------------------------------------ configuration
def _settings(**kw):
    base = dict(database_dsn="x", trusted_issuers_json='[{"issuer":"https://idp","audience":"axiom","jwks":{"keys":[{"kty":"RSA"}]}}]')
    base.update(kw)
    return Settings(**base)


def test_production_refuses_development_shortcuts():
    _settings(env="development").validate_for_runtime()
    with pytest.raises(ConfigurationError, match="inline JWKS"):
        _settings(env="production", object_store="s3").validate_for_runtime()
    with pytest.raises(ConfigurationError, match="filesystem"):
        _settings(env="production", trusted_issuers_json='[{"issuer":"i","audience":"a","jwks_uri":"https://k"}]'
                  ).validate_for_runtime()
    with pytest.raises(ConfigurationError, match="symmetric"):
        _settings(trusted_issuers_json='[{"issuer":"i","audience":"a","jwks_uri":"https://k","algorithms":["HS256"]}]'
                  ).validate_for_runtime()
    with pytest.raises(ConfigurationError, match="no trusted"):
        _settings(trusted_issuers_json="[]").validate_for_runtime()


def test_empty_inline_jwks_rejected():
    with pytest.raises(ConfigurationError, match="empty inline JWKS"):
        _settings(trusted_issuers_json='[{"issuer":"i","audience":"a","jwks":{"keys":[]}}]').validate_for_runtime()
