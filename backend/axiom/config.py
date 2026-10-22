"""Deployment configuration.

Insecure development conveniences (static JWKS, filesystem object store) are
refused when AXIOM_ENV=production so that they cannot silently carry into a
production deployment.
"""
from __future__ import annotations

import json
from functools import cached_property
from typing import Literal

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .errors import ConfigurationError


class TrustedIssuer(BaseModel):
    issuer: str
    audience: str
    jwks_uri: str | None = None
    # Inline JWKS is for development and tests only ("development-token authentication"); refused in production
    # at start-up and, as a second line, by the token verifier at runtime.
    jwks: dict | None = None
    algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256", "PS256"])


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AXIOM_", extra="ignore")

    env: Literal["development", "test", "production"] = "development"
    database_dsn: str = Field(description="Runtime login (member of axiom_runtime only)")
    relay_database_dsn: str | None = None
    db_pool_min: int = 1
    db_pool_max: int = 10

    trusted_issuers_json: str = "[]"
    token_leeway_seconds: int = 30

    object_store: Literal["filesystem", "s3"] = "filesystem"
    object_store_root: str = ".var/objects"
    s3_endpoint_url: str | None = None
    s3_bucket: str | None = None
    s3_region: str = "us-east-1"
    evidence_max_bytes: int = 512 * 1024 * 1024

    # Job worker (ADR 0006, ADR 0010). The restore witness must be outside the database's backup domain:
    # "dir:/path" (separate volume) or "s3:bucket/prefix" (separate bucket/account; uses the S3 endpoint above).
    restore_witness: str | None = None
    worker_metrics_port: int | None = None

    # Phase C (ADR 0012). Registered destinations: comma-separated https origins. A model route or tool may only use
    # an origin listed here; nothing is enabled by default. The deterministic fake model is refused in production.
    model_destinations: str = ""
    tool_destinations: str = ""

    # Enterprise sign-in for the analyst UI (ADR 0013): OpenID Connect authorization code flow with PKCE, run by the
    # backend (confidential client). Sessions are server-side; the browser holds an HttpOnly cookie.
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret_ref: str | None = None      # secretref:env/NAME (never the secret itself)
    oidc_redirect_uri: str | None = None
    oidc_scopes: str = "openid profile email"
    oidc_post_logout_redirect_uri: str | None = None
    ui_session_ttl_seconds: int = 8 * 3600
    ui_session_idle_seconds: int = 1800
    ui_cookie_secure: bool = True
    ui_dist_dir: str | None = None                 # built analyst UI to serve at /ui

    @property
    def model_destination_set(self) -> frozenset[str]:
        return frozenset(o.strip().rstrip("/") for o in self.model_destinations.split(",") if o.strip())

    @property
    def tool_destination_set(self) -> frozenset[str]:
        return frozenset(o.strip().rstrip("/") for o in self.tool_destinations.split(",") if o.strip())

    @cached_property
    def trusted_issuers(self) -> list[TrustedIssuer]:
        raw = json.loads(self.trusted_issuers_json)
        return [TrustedIssuer.model_validate(item) for item in raw]

    def validate_for_runtime(self) -> None:
        issuers = self.trusted_issuers
        if not issuers:
            raise ConfigurationError("no trusted OIDC issuers configured")
        for issuer in issuers:
            bad = {a for a in issuer.algorithms if a.upper().startswith("HS") or a.lower() == "none"}
            if bad:
                raise ConfigurationError(f"symmetric/none algorithms are not accepted: {sorted(bad)}")
            if issuer.jwks is None and issuer.jwks_uri is None:
                raise ConfigurationError(f"issuer {issuer.issuer} has no key source")
            if issuer.jwks is not None and not issuer.jwks.get("keys"):
                raise ConfigurationError(f"issuer {issuer.issuer} has an empty inline JWKS")
        if self.env == "production":
            if any(i.jwks is not None for i in issuers):
                raise ConfigurationError("inline JWKS is not permitted in production")
            if any(i.jwks_uri and not i.jwks_uri.startswith("https://") for i in issuers):
                raise ConfigurationError("JWKS must be fetched over HTTPS in production")
            if self.object_store == "filesystem":
                raise ConfigurationError("filesystem object store is not permitted in production")
            if self.oidc_issuer:
                for name in ("oidc_issuer", "oidc_redirect_uri"):
                    if not (getattr(self, name) or "").startswith("https://"):
                        raise ConfigurationError(f"{name} must use HTTPS in production")
                if not self.ui_cookie_secure:
                    raise ConfigurationError("UI session cookies must be Secure in production")
        if self.oidc_issuer and not (self.oidc_client_id and self.oidc_client_secret_ref and self.oidc_redirect_uri):
            raise ConfigurationError("OIDC sign-in needs client id, client secret reference and redirect URI")
        if self.oidc_client_secret_ref and not self.oidc_client_secret_ref.startswith("secretref:"):
            raise ConfigurationError("the OIDC client secret must be given as a secret reference, not a value")
