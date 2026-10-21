# ADR 0008: Authentication and tenant selection

Status: accepted for development; **production SSO not yet implemented** (2026-10-22)

## What exists
* The API accepts OIDC-style JWT bearer access tokens. Trusted issuers are installation configuration
  (`AXIOM_TRUSTED_ISSUERS_JSON`: issuer, audience, JWKS URI or inline JWKS, allowed algorithms). Only asymmetric
  algorithms are accepted; HS* and `none` are refused at startup. Required claims: iss, aud, sub, exp, iat.
* Principals are resolved from (issuer, audience, subject) through `axiom_auth.resolve_principal`. No email-based
  account merging. A valid token for an unprovisioned subject is refused: authentication is not membership.
* The tenant is selected per request with `X-Axiom-Tenant` (slug or id) and validated against an active membership in an
  active tenant. The response is identical whether the tenant is missing, suspended or not a membership.
* Installation operators hold installation roles only and cannot select tenants.

## What is development-only
* **Development token authentication**: `axiom.devtools` generates an RSA key and mints tokens for a fixed dev
  issuer; Compose wires it as an inline JWKS. Production configuration refuses inline JWKS and non-HTTPS JWKS URIs.

## Gaps (tracked)
* **No production-ready enterprise OIDC/SSO integration yet (AUTHZ-14).** Not done: interactive login (authorisation
  code + PKCE) for the web UI, integration testing with a real IdP (Entra ID, Keycloak or Okta), JWKS rotation tests
  against a live endpoint, token revocation strategy, session management, group/role claim mapping policy (deliberately
  not trusted for authority today), workload identity for workers, and SCIM or JIT provisioning.
* Membership and identity provisioning happens through the provisioning CLI, not a self-service flow.
