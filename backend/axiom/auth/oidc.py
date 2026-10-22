"""Enterprise sign-in for the analyst UI: OpenID Connect authorization code flow with PKCE (ADR 0013).

Libraries: Authlib's framework-independent OAuth 2 helpers (``authlib.oauth2.rfc7636.create_s256_code_challenge``,
``authlib.common.urls.add_params_to_uri``) build the authorization request; the code exchange is one form POST made
here with httpx, authenticated with ``client_secret_basic`` (RFC 6749 section 2.3.1); joserfc 1.7 verifies the ID
token signature and claims. ``authlib.integrations.httpx_client.OAuth2Client`` is deliberately not used: since
Authlib 1.8.0 it is built on ``httpx2`` and its fallback to ``httpx`` is deprecated.

Checks, in order, on the callback:

1. The ``state`` must match an unexpired, unconsumed login attempt **bound to this browser** (a random binding value
   in an HttpOnly cookie, stored as a hash). Consumption is single-use, so a replayed callback fails.
2. If the authorization response carries ``iss`` (RFC 9207), it must equal the configured issuer.
3. The code is exchanged with the stored PKCE verifier and the client secret, at the token endpoint from discovery.
4. The ID token:
   * signature, with an algorithm from the allow-list, against the issuer's JWKS from discovery;
   * ``iss`` equals the configured issuer exactly;
   * ``aud`` contains the client id; ``azp`` must equal it when present, and must be present when there are
     several audiences;
   * ``exp`` and ``iat`` within leeway, and ``iat`` not older than the maximum login age;
   * ``nonce`` equals the nonce stored with the state;
   * ``sub`` present.
5. The platform principal is resolved by **(issuer, client id, subject)** through ``axiom_auth.resolve_principal``.
   Email is never used to find or merge accounts, and there is no automatic provisioning: an unknown subject is
   refused.

Tenant membership and permissions are not stored in the session; every request re-checks them.
The discovery document's ``issuer`` must equal the configured issuer (mix-up defence). ``metadata_url`` lets the
server fetch discovery from an internal address (for example a container network name) while the issuer, which the
browser and the ID token use, stays the public URL; the issuer check is unchanged.
"""
from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from urllib.parse import quote

import httpx
from authlib.common.urls import add_params_to_uri
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from ..errors import ConfigurationError, Unauthenticated

ALGORITHMS = ["RS256", "PS256", "ES256"]
MAX_LOGIN_AGE = 600


@dataclass
class IdTokenClaims:
    issuer: str
    subject: str
    claims: dict


class OidcClient:
    def __init__(self, *, issuer: str, client_id: str, client_secret: callable, redirect_uri: str,
                 scopes: str = "openid profile email", transport: httpx.BaseTransport | None = None,
                 leeway: int = 30, cache_seconds: int = 300, metadata_url: str | None = None):
        self.issuer, self.client_id, self._secret = issuer.rstrip("/"), client_id, client_secret
        self.metadata_url = metadata_url or f"{self.issuer}/.well-known/openid-configuration"
        self.redirect_uri, self.scopes, self.transport, self.leeway = redirect_uri, scopes, transport, leeway
        self._meta: tuple[float, dict] | None = None
        self._jwks: tuple[float, KeySet] | None = None
        self._cache = cache_seconds

    def _http(self) -> httpx.Client:
        return httpx.Client(transport=self.transport, timeout=10, follow_redirects=False)

    def metadata(self) -> dict:
        if self._meta and time.monotonic() - self._meta[0] < self._cache:
            return self._meta[1]
        with self._http() as c:
            r = c.get(self.metadata_url)
        if r.status_code != 200:
            raise ConfigurationError(f"OIDC discovery failed: HTTP {r.status_code}")
        meta = r.json()
        if meta.get("issuer", "").rstrip("/") != self.issuer:
            raise ConfigurationError("OIDC discovery issuer does not match the configured issuer")
        for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not meta.get(k):
                raise ConfigurationError(f"OIDC discovery lacks {k}")
        self._meta = (time.monotonic(), meta)
        return meta

    def _keys(self, refresh: bool = False) -> KeySet:
        if self._jwks and not refresh and time.monotonic() - self._jwks[0] < self._cache:
            return self._jwks[1]
        with self._http() as c:
            r = c.get(self.metadata()["jwks_uri"])
        if r.status_code != 200:
            raise Unauthenticated("identity provider keys unavailable")
        keys = KeySet.import_key_set(r.json())
        self._jwks = (time.monotonic(), keys)
        return keys

    def authorization_url(self, *, state: str, nonce: str, code_verifier: str) -> str:
        params = [("response_type", "code"), ("client_id", self.client_id), ("redirect_uri", self.redirect_uri),
                  ("scope", self.scopes), ("state", state), ("nonce", nonce),
                  ("code_challenge", create_s256_code_challenge(code_verifier)), ("code_challenge_method", "S256")]
        return add_params_to_uri(self.metadata()["authorization_endpoint"], params)

    def exchange(self, code: str, code_verifier: str) -> dict:
        # client_secret_basic: form-urlencoded client id and secret, then Base64 (RFC 6749 section 2.3.1)
        basic = base64.b64encode(f"{quote(self.client_id, safe='')}:{quote(self._secret(), safe='')}".encode()).decode()
        try:
            with self._http() as c:
                r = c.post(self.metadata()["token_endpoint"],
                           data={"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri,
                                 "code_verifier": code_verifier},
                           headers={"Authorization": f"Basic {basic}", "Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise Unauthenticated(f"code exchange failed: {type(exc).__name__}") from exc
        if r.status_code != 200:
            try:
                reason = str(r.json().get("error", ""))[:60]
            except (ValueError, AttributeError):
                reason = ""
            raise Unauthenticated(f"code exchange refused: HTTP {r.status_code} {reason}".rstrip())
        try:
            token = r.json()
        except ValueError as exc:
            raise Unauthenticated("code exchange returned no JSON") from exc
        if not isinstance(token, dict) or not token.get("id_token"):
            raise Unauthenticated("no ID token returned")
        if str(token.get("token_type", "")).lower() != "bearer":
            raise Unauthenticated("unexpected token type")
        return token

    def validate_id_token(self, id_token: str, *, nonce: str) -> IdTokenClaims:
        try:
            try:
                tok = jwt.decode(id_token, self._keys(), algorithms=ALGORITHMS)
            except JoseError:
                tok = jwt.decode(id_token, self._keys(refresh=True), algorithms=ALGORITHMS)   # key rotation
            registry = jwt.JWTClaimsRegistry(
                leeway=self.leeway, iss={"essential": True, "value": self.issuer}, sub={"essential": True},
                aud={"essential": True, "value": self.client_id}, exp={"essential": True},
                iat={"essential": True}, nonce={"essential": True, "value": nonce})
            registry.validate(tok.claims)
        except JoseError as exc:
            raise Unauthenticated(f"ID token rejected: {exc.error}") from exc
        claims = tok.claims
        aud = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        # OIDC Core 3.1.3.7: azp is required to name this client when there are several audiences, and must name
        # it whenever it is present
        if (len(aud) > 1 or "azp" in claims) and claims.get("azp") != self.client_id:
            raise Unauthenticated("ID token rejected: azp does not name this client")
        if claims["iat"] < time.time() - MAX_LOGIN_AGE - self.leeway:
            raise Unauthenticated("ID token rejected: issued too long ago")
        return IdTokenClaims(self.issuer, claims["sub"], claims)

    def end_session_url(self, post_logout_redirect_uri: str | None) -> str | None:
        try:
            endpoint = self.metadata().get("end_session_endpoint")
        except ConfigurationError:
            return None
        if not endpoint:
            return None
        params = {"client_id": self.client_id}
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        return str(httpx.URL(endpoint, params=params))
