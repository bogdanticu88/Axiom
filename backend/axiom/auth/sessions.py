"""Server-side UI sessions and the login state machine (ADR 0013).

Browser-held secrets (state, login binding, session token, CSRF token) are random 32-byte values; only their SHA-256
hashes are stored, through the narrow ``axiom_auth`` functions of migration 0015. The session cookie is HttpOnly,
SameSite=Lax and Secure (configurable for local HTTP tests only; refused in production). State-changing requests that
authenticate by session must carry ``X-CSRF-Token`` equal to the session's CSRF token (double submit, verified
against the stored hash), so a cross-site form cannot act with the cookie.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from urllib.parse import urlparse
from uuid import UUID

from ..db import Database
from ..errors import Forbidden, Unauthenticated
from .oidc import OidcClient

SESSION_COOKIE = "axiom_session"
CSRF_COOKIE = "axiom_csrf"
BINDING_COOKIE = "axiom_login"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def safe_return_to(value: str | None) -> str:
    """Only same-origin paths under /ui are accepted, so the callback cannot be used as an open redirect."""
    if not value:
        return "/ui/"
    p = urlparse(value)
    if p.scheme or p.netloc or not p.path.startswith("/ui") or value.startswith("//") or "\\" in value:
        return "/ui/"
    return value


@dataclass
class SessionActor:
    session_id: UUID
    principal_id: UUID
    kind: str
    issuer: str
    subject: str
    csrf_hash: str


class SessionService:
    def __init__(self, db: Database, oidc: OidcClient, *, ttl_seconds: int, idle_seconds: int):
        self.db, self.oidc, self.ttl, self.idle = db, oidc, ttl_seconds, idle_seconds

    def start_login(self, return_to: str | None) -> tuple[str, str]:
        state, nonce, verifier, binding = (secrets.token_urlsafe(32) for _ in range(4))
        verifier = verifier + secrets.token_urlsafe(16)            # 43..128 characters (RFC 7636)
        with self.db.unbound_tx() as conn:
            conn.execute("SELECT axiom_auth.login_state_create(%s, %s, %s, %s, %s, %s, %s)",
                         (h(state), h(binding), self.oidc.issuer, nonce, verifier, safe_return_to(return_to), 600))
        return self.oidc.authorization_url(state=state, nonce=nonce, code_verifier=verifier), binding

    def finish_login(self, *, code: str | None, state: str | None, binding: str | None, iss: str | None,
                     error: str | None = None) -> tuple[str, str, str]:
        if error:
            raise Unauthenticated(f"identity provider returned an error: {error[:100]}")
        if not (code and state and binding):
            raise Unauthenticated("incomplete login response")
        with self.db.unbound_tx() as conn:
            row = conn.execute("SELECT * FROM axiom_auth.login_state_consume(%s, %s)", (h(state), h(binding))).fetchone()
        if row is None:
            raise Unauthenticated("login state invalid, expired, already used or from another browser")
        if iss is not None and iss.rstrip("/") != self.oidc.issuer:
            raise Unauthenticated("authorization response issuer does not match")
        token = self.oidc.exchange(code, row["code_verifier"])
        claims = self.oidc.validate_id_token(token["id_token"], nonce=row["nonce"])
        with self.db.unbound_tx() as conn:
            principal = conn.execute(
                "SELECT principal_id, principal_kind FROM axiom_auth.resolve_principal(%s, %s, %s)",
                (claims.issuer, self.oidc.client_id, claims.subject)).fetchone()
            if principal is None:
                raise Forbidden("this identity is not provisioned for the platform", code="identity_not_provisioned")
            session_token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            conn.execute("SELECT axiom_auth.session_create(%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                         (uuid.uuid4(), h(session_token), h(csrf), principal["principal_id"], claims.issuer,
                          claims.subject, claims.claims.get("sid"), self.ttl, self.idle))
        return session_token, csrf, row["return_to"]

    def authenticate(self, token: str, *, method: str, csrf_header: str | None) -> SessionActor:
        with self.db.unbound_tx() as conn:
            row = conn.execute("SELECT * FROM axiom_auth.session_use(%s)", (h(token),)).fetchone()
        if row is None:
            raise Unauthenticated("session expired or signed out")
        if method.upper() in UNSAFE and (not csrf_header or not secrets.compare_digest(h(csrf_header), row["csrf_hash"])):
            raise Forbidden("missing or wrong CSRF token", code="csrf_failed")
        return SessionActor(row["session_id"], row["principal_id"], row["principal_kind"], row["issuer"],
                            row["subject"], row["csrf_hash"])

    def revoke(self, token: str, *, reason: str) -> None:
        with self.db.unbound_tx() as conn:
            conn.execute("SELECT axiom_auth.session_revoke(%s, %s)", (h(token), reason))

    def logout(self, token: str | None, post_logout_redirect_uri: str | None) -> str | None:
        if token:
            with self.db.unbound_tx() as conn:
                conn.execute("SELECT axiom_auth.session_revoke(%s, 'logout')", (h(token),))
        return self.oidc.end_session_url(post_logout_redirect_uri)
