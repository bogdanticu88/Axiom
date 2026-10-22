"""OIDC access-token verification.

Only issuers configured by the installation are trusted. Only asymmetric
algorithms configured for that issuer are accepted (never HS*/none). Required
claims: iss, aud, sub, exp, iat. Authentication proves identity; it does not
grant tenant membership or permissions.
"""
from __future__ import annotations

from dataclasses import dataclass

import jwt
from jwt import PyJWKClient, PyJWKSet

from ..config import TrustedIssuer
from ..errors import Unauthenticated


@dataclass(frozen=True)
class VerifiedIdentity:
    issuer: str
    audience: str
    subject: str
    claims: dict


class TokenVerifier:
    def __init__(self, issuers: list[TrustedIssuer], *, leeway_seconds: int = 30, env: str = "development"):
        self._env = env
        self._issuers = {i.issuer: i for i in issuers}
        self._leeway = leeway_seconds
        self._clients: dict[str, PyJWKClient] = {}
        self._static: dict[str, PyJWKSet] = {
            i.issuer: PyJWKSet.from_dict(i.jwks) for i in issuers if i.jwks is not None}

    def _key_for(self, cfg: TrustedIssuer, token: str, kid: str | None):
        if cfg.issuer in self._static:
            keyset = self._static[cfg.issuer]
            for key in keyset.keys:
                if key.key_id == kid:
                    return key.key
            raise Unauthenticated("unknown signing key")
        client = self._clients.get(cfg.issuer)
        if client is None:
            client = PyJWKClient(cfg.jwks_uri, cache_keys=True, lifespan=300, timeout=5)
            self._clients[cfg.issuer] = client
        try:
            return client.get_signing_key_from_jwt(token).key
        except jwt.PyJWKClientError as exc:
            raise Unauthenticated("signing key unavailable") from exc

    def verify(self, token: str) -> VerifiedIdentity:
        try:
            header = jwt.get_unverified_header(token)
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            raise Unauthenticated("malformed token") from exc
        cfg = self._issuers.get(unverified.get("iss"))
        if cfg is None:
            raise Unauthenticated("untrusted issuer")
        if self._env == "production" and cfg.jwks is not None:
            # start-up already refuses this configuration; this is the runtime second line
            raise Unauthenticated("development token authentication is disabled in production")
        if header.get("alg") not in cfg.algorithms:
            raise Unauthenticated("token algorithm not accepted")
        key = self._key_for(cfg, token, header.get("kid"))
        try:
            claims = jwt.decode(
                token, key, algorithms=cfg.algorithms, audience=cfg.audience, issuer=cfg.issuer,
                leeway=self._leeway, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
        except jwt.PyJWTError as exc:
            raise Unauthenticated("token rejected") from exc
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise Unauthenticated("token subject missing")
        return VerifiedIdentity(cfg.issuer, cfg.audience, subject, claims)
