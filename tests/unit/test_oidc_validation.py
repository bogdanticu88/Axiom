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


# ------------------------------------------------------------- code exchange (checkpoint 6: no deprecated client)
def test_authorization_url_challenge_is_s256_of_the_verifier_and_redirect_is_fixed():
    import base64
    import hashlib
    verifier = "v" * 50
    q = dict(httpx.URL(client().authorization_url(state="st", nonce="nn", code_verifier=verifier)).params)
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert q["code_challenge"] == expected                                   # RFC 7636 S256
    assert q["redirect_uri"] == "https://axiom/cb" and q["scope"] == "openid profile email"


def exchange_client(response, seen):
    def handler(req):
        if req.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": ISS, "authorization_endpoint": f"{ISS}/auth",
                                             "token_endpoint": f"{ISS}/token", "jwks_uri": f"{ISS}/certs"})
        seen.append(req)
        return response(req) if callable(response) else response
    return OidcClient(issuer=ISS, client_id="ui:x", client_secret=lambda: "s&cret", redirect_uri="https://axiom/cb",
                      transport=httpx.MockTransport(handler))


def test_code_exchange_sends_pkce_verifier_and_basic_client_authentication():
    import base64
    from urllib.parse import parse_qs
    seen = []
    ok = httpx.Response(200, json={"access_token": "a", "token_type": "Bearer", "id_token": "x.y.z"})
    token = exchange_client(ok, seen).exchange("the-code", "the-verifier")
    assert token["id_token"] == "x.y.z"
    [req] = seen
    assert req.method == "POST" and req.url == f"{ISS}/token"
    form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
    assert form == {"grant_type": "authorization_code", "code": "the-code", "redirect_uri": "https://axiom/cb",
                    "code_verifier": "the-verifier"}
    # client id and secret are form-urlencoded before Base64 (RFC 6749 section 2.3.1); the secret is not in the body
    assert req.headers["authorization"] == "Basic " + base64.b64encode(b"ui%3Ax:s%26cret").decode()


@pytest.mark.parametrize("response", [
    httpx.Response(400, json={"error": "invalid_grant"}),          # replayed or expired code
    httpx.Response(400, json={"error": "invalid_grant", "id_token": "x.y.z", "token_type": "Bearer"}),  # status decides
    httpx.Response(401, json={"error": "invalid_client"}),
    httpx.Response(302, headers={"location": "https://evil.example/"}),   # redirects are not followed
    httpx.Response(200, text="not json"),
    httpx.Response(200, json={"access_token": "a", "token_type": "Bearer"}),        # no ID token
    httpx.Response(200, json={"id_token": "x.y.z", "token_type": "mac"}),            # wrong token type
    lambda req: (_ for _ in ()).throw(httpx.ConnectError("down")),                   # transport failure
])
def test_failed_code_exchanges_refuse_the_login(response):
    with pytest.raises(Unauthenticated):
        exchange_client(response, []).exchange("code", "verifier")


def test_discovery_can_come_from_an_internal_address_but_the_issuer_must_still_match():
    calls = []

    def handler(req):
        calls.append(str(req.url))
        return httpx.Response(200, json={"issuer": ISS, "authorization_endpoint": f"{ISS}/auth",
                                         "token_endpoint": "http://idp.internal/token", "jwks_uri": "http://idp.internal/certs"})
    c = OidcClient(issuer=ISS, client_id="ui", client_secret=lambda: "s", redirect_uri="https://axiom/cb",
                   transport=httpx.MockTransport(handler),
                   metadata_url="http://idp.internal/realms/r/.well-known/openid-configuration")
    assert c.metadata()["token_endpoint"] == "http://idp.internal/token" and calls[0].startswith("http://idp.internal/")
    bad = OidcClient(issuer="https://other.example/realms/r", client_id="ui", client_secret=lambda: "s",
                     redirect_uri="https://axiom/cb", transport=httpx.MockTransport(handler),
                     metadata_url="http://idp.internal/realms/r/.well-known/openid-configuration")
    with pytest.raises(ConfigurationError):
        bad.metadata()


def test_the_deprecated_authlib_http_client_is_not_used():
    import sys
    import axiom.auth.oidc  # noqa: F401
    import axiom.auth.sessions  # noqa: F401
    assert "authlib.integrations.httpx_client" not in sys.modules
