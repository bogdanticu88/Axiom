"""ID-token and discovery checks of the OIDC client, with locally signed tokens (no network)."""
from __future__ import annotations

import time

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, OctKey, RSAKey

from axiom.auth.oidc import OidcClient
from axiom.errors import ConfigurationError, Unauthenticated

ISS = "https://idp.example/realms/r"
KEY = RSAKey.generate_key(2048, parameters={"kid": "k1", "alg": "RS256", "use": "sig"})
OTHER = RSAKey.generate_key(2048, parameters={"kid": "k1", "alg": "RS256", "use": "sig"})


def transport(issuer=ISS, keys=None):
    def handler(req):
        if req.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": issuer, "authorization_endpoint": f"{ISS}/auth",
                                             "token_endpoint": f"{ISS}/token", "jwks_uri": f"{ISS}/certs",
                                             "end_session_endpoint": f"{ISS}/logout"})
        if req.url.path.endswith("/certs"):
            return httpx.Response(200, json=KeySet([keys or KEY]).as_dict(private=False))
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def client(**kw):
    return OidcClient(issuer=ISS, client_id="ui", client_secret=lambda: "s", redirect_uri="https://axiom/cb",
                      transport=transport(**kw))


def token(key=KEY, alg="RS256", **claims):
    now = int(time.time())
    body = {"iss": ISS, "aud": "ui", "sub": "user-1", "iat": now, "exp": now + 300, "nonce": "n1", **claims}
    body = {k: v for k, v in body.items() if v is not None}
    return jwt.encode({"alg": alg, "kid": "k1"}, body, key, algorithms=[alg])


def test_valid_token():
    assert client().validate_id_token(token(), nonce="n1").subject == "user-1"


@pytest.mark.parametrize("claims", [
    {"nonce": "other"}, {"nonce": None}, {"aud": "another-client"}, {"iss": "https://evil.example"},
    {"exp": int(time.time()) - 600}, {"sub": None}, {"iat": int(time.time()) - 3600},
    {"aud": ["ui", "other"]},                                  # several audiences without azp
    {"aud": ["ui", "other"], "azp": "other"},
])
def test_rejected_claims(claims):
    with pytest.raises(Unauthenticated):
        client().validate_id_token(token(**claims), nonce="n1")


def test_rejected_signatures_and_algorithms():
    with pytest.raises(Unauthenticated):
        client().validate_id_token(token(key=OTHER), nonce="n1")              # signed by a key the IdP does not publish
    with pytest.raises(Unauthenticated):                                     # HS256 is not on the allow-list
        client().validate_id_token(token(key=OctKey.generate_key(256), alg="HS256"), nonce="n1")
    ok = client().validate_id_token(token(aud=["ui", "other"], azp="ui"), nonce="n1")
    assert ok.subject == "user-1"


def test_discovery_issuer_must_match():
    with pytest.raises(ConfigurationError):
        client(issuer="https://idp.example/realms/other").metadata()


def test_authorization_url_uses_pkce_s256_and_nonce():
    url = httpx.URL(client().authorization_url(state="st", nonce="nn", code_verifier="v" * 50))
    q = dict(url.params)
    assert q["code_challenge_method"] == "S256" and q["code_challenge"] and "v" * 50 not in str(url)
    assert (q["state"], q["nonce"], q["response_type"], q["client_id"]) == ("st", "nn", "code", "ui")
