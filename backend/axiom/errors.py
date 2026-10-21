"""Structured domain errors mapped to safe API responses.

Messages are safe for clients: they never include other tenants' identifiers,
SQL, or secrets. Detailed diagnostics belong in server logs keyed by the
correlation ID.
"""
from __future__ import annotations


class DomainError(Exception):
    status = 400
    code = "invalid_request"
    retryable = False

    def __init__(self, message: str, *, code: str | None = None, details: dict | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.details = details or {}


class ValidationFailed(DomainError):
    status = 422
    code = "validation_failed"


class Unauthenticated(DomainError):
    status = 401
    code = "unauthenticated"


class Forbidden(DomainError):
    status = 403
    code = "forbidden"


class NotFound(DomainError):
    """Also used when a resource exists but is outside the caller's visibility."""
    status = 404
    code = "not_found"


class Conflict(DomainError):
    """Stale version, disallowed transition or unmet guard. No partial state is committed."""
    status = 409
    code = "conflict"


class DependencyFailure(DomainError):
    status = 503
    code = "dependency_unavailable"
    retryable = True


class ConfigurationError(RuntimeError):
    """Unsafe or incomplete deployment configuration; refuse to start."""
