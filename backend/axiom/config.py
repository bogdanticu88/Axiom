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
    # Inline JWKS is for development and tests only.
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
