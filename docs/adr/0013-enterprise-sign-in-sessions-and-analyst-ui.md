# ADR 0013: Enterprise sign-in, browser sessions and the analyst UI

Status: accepted (2026-10-22). Verified against a **local Keycloak 26.4.2 container only**. Microsoft Entra ID and
other hosted identity providers have **not** been tested.

## Context
ADR 0008 left production sign-in as a tracked gap (AUTHZ-14): the API accepted bearer tokens from configured issuers
and development token authentication minted them locally. The analyst UI (ARC-05) needs interactive sign-in, and a
browser must not hold bearer tokens that scripts on the page can read.

## Decision

### 1. Protocol: OpenID Connect authorization code flow with PKCE
* Library: **Authlib 1.8.0** (`authlib.integrations.httpx_client.OAuth2Client`) for the authorization request and
  code exchange, with **joserfc 1.7.5** (Authlib's maintained JOSE library) for ID-token validation. Behaviour follows
  OpenID Connect Core 1.0 and RFC 7636 (PKCE) and RFC 9207 (issuer in the authorization response).
* Discovery is read from `{issuer}/.well-known/openid-configuration`; the document's `issuer` must equal the configured
  issuer exactly, or sign-in is refused.
* The authorization request uses `response_type=code`, `code_challenge_method=S256`, a fresh `state`, `nonce` and
  code verifier per attempt.
* ID-token validation (`auth/oidc.py`): signature against the issuer's JWKS (RS256, PS256 or ES256 only; HS* and
  `none` refused; one JWKS refresh on an unknown `kid`), `iss` equal to the configured issuer, `aud` containing the
  client ID and `azp` equal to it when there are several audiences, `exp` in the future, `iat` present and not more
  than 600 seconds old, `nonce` equal to the stored value, `sub` present.
* Users are identified by **(issuer, client ID, subject)** through `axiom_auth.resolve_principal`. Email addresses are
  never used to find or merge accounts (tested with two IdP users sharing an email address). A valid login for an
  unprovisioned identity is refused with `identity_not_provisioned`: authentication is not membership.
* Tenant membership and every permission stay server-side and are evaluated on each request (unchanged from ADR
  0002/0008). Group or role claims in tokens are not trusted for authority.

### 2. Callback protections
* Login state rows (`axiom.ui_login_states`, migration 0015) are created and consumed only through `axiom_authn`
  security-definer functions. A row holds hashes of `state` and of a **browser-binding** value; the binding value is
  set as the `axiom_login` cookie (HttpOnly, SameSite=Lax, 10 minutes). The callback must present both, so a callback
  URL replayed in another browser fails.
* States are single use (consumed under a row lock) and expire after at most 15 minutes (10 by default).
* An `iss` parameter in the callback, when present, must equal the configured issuer (mix-up defence).
* `return_to` accepts only paths under `/ui` (no scheme, host or `//`), so the callback cannot redirect elsewhere.
* An `error` response from the IdP ends the attempt with no session.

### 3. Server-side sessions
* `axiom.ui_sessions` (migration 0015, forced RLS, readable only by `axiom_authn`) stores **hashes** of the session token
  and CSRF token, the principal, issuer, subject and IdP session ID. The browser holds the random session token in
  `axiom_session` (HttpOnly, SameSite=Lax, Secure in production, path `/`). No access, refresh or ID token is kept.
* `axiom_auth.session_use` refuses revoked, expired (absolute lifetime, default 8 h, capped at 24 h) and idle
  (default 30 min) sessions, and sessions of disabled principals; it refreshes `last_seen_at`.
* CSRF: unsafe methods (POST, PUT, PATCH, DELETE) on session-authenticated requests must send `X-CSRF-Token` equal to
  the `axiom_csrf` cookie value (readable by the page, compared by hash). Bearer-token API clients are unaffected.
* Logout (`POST /auth/logout`, CSRF-protected) revokes the session server-side first, then returns the IdP's
  `end_session_endpoint` with `client_id` and the registered post-logout redirect. No `id_token_hint` is sent because
  ID tokens are not retained, so Keycloak shows its own logout confirmation.
* Membership or role revocation takes effect on the next request because authority is never cached in the session.

### 4. Development tokens are refused in production
* In `env=production`, configuration refuses inline-JWKS issuers, non-HTTPS issuer and redirect URIs, insecure cookies
  and an inline client secret (only a `secretref:` reference is accepted). `TokenVerifier` also refuses inline-JWKS
  issuers at runtime with "development token authentication is disabled in production". Both are tested.

### 5. Analyst UI
* React 18 + TypeScript + Vite in `frontend/`, built to static files and served by the API at `/ui` (same origin as
  the API, so the session cookie and CSRF header work without CORS). Lockfile committed; CI runs `npm ci`, the type
  check and the build.
* Content-Security-Policy on `/ui`: scripts and styles from self only, no inline script or style, `frame-ancestors
  'none'`; plus `nosniff`, `no-referrer` and `X-Frame-Options: DENY`.
* The UI only calls the real API. The selected tenant is sent in `X-Axiom-Tenant` and rechecked by the server on every
  request; a remembered tenant the user is not a member of is ignored.
* Honesty labels are part of the contract: the deterministic fake route is labelled "Fake model (not a language
  model)"; other routes "Unverified route"; fixture-tested integrations "Fixture-tested integration"; manually recorded
  deployments and asserted business context "Manually recorded" / "Manual assertion"; AI claims "AI analysis —
  references checked, reasoning not verified"; provisional policies "provisional".
* Every data view has loading, empty, denied, not-found, stale-version (409 `stale_version` with a reload action),
  conflict, invalid and dependency-failure states.

## Consequences
* Sessions add a database round trip per request (one `session_use` call), and an expired session means signing in
  again; there is no silent refresh.
* Because ID tokens are not kept, RP-initiated logout always asks the user to confirm at the IdP.
* The UI and API must share an origin; a separate UI origin would need CORS and a different cookie policy.

## Not done or not verified
* **Microsoft Entra ID, Okta or any hosted IdP**: not tested. Entra-specific behaviour (multi-tenant issuers, `tid`,
  v1/v2 endpoints, conditional access) is unhandled and unverified.
* Back-channel and front-channel logout from the IdP; IdP-initiated logout does not end platform sessions.
* JIT or SCIM provisioning; principals are provisioned with the CLI.
* Workload identity federation for workers.
* Accessibility audit, browsers other than Chromium, analyst usability testing.
* Debt: Authlib 1.8.0 emits a deprecation warning for its `httpx` integration in favour of `httpx2`; the client must
  move before Authlib removes it.

## Amendment (2026-10-22, checkpoint 6)
**Deprecated client removed.** `auth/oidc.py` used `authlib.integrations.httpx_client.OAuth2Client`
(`create_authorization_url`, `fetch_token`). Since Authlib 1.8.0 that integration is built on `httpx2`, and without
`httpx2` it falls back to `httpx` with an `AuthlibDeprecationWarning`; the fallback is due for removal. The client now
uses Authlib's framework-independent helpers (`authlib.oauth2.rfc7636.create_s256_code_challenge`,
`authlib.common.urls.add_params_to_uri`) for the authorization request and makes the token request itself: one form
POST with `client_secret_basic` (form-urlencoded id and secret, RFC 6749 section 2.3.1), the PKCE verifier and the
registered redirect URI; redirects are not followed; any status other than 200, a non-JSON body, a missing ID token or
a token type other than Bearer refuses the login. ID-token validation (joserfc) is unchanged. The module no longer
imports `authlib.integrations` at all (a unit test checks).

**Internal discovery address.** `AXIOM_OIDC_METADATA_URL` lets the API fetch discovery from a container-network address
while the issuer stays the public URL the browser uses; the document's `issuer` must still equal the configured issuer.

**Fail closed at start-up.** The client secret reference is resolved when the API starts, not at the first login. In
production, the API refuses: plain-HTTP issuer, redirect, discovery or post-logout URLs; non-Secure cookies; serving the
UI without sign-in; a secret given as a value; and the environment secret resolver (so production sign-in is not
configurable until a secret-manager resolver exists).

**Compose.** The image builds the UI (pinned Node image, `npm ci` from the lockfile) and serves it at /ui. The
Compose profile runs a local Keycloak 26.4.2 (development mode, synthetic users) and maps each Keycloak subject to the
seeded principal by issuer and subject (docs/INSTALL-COMPOSE.md).

**What local Keycloak testing establishes, precisely.** Against this one IdP, configured as in the tests: the
authorization code flow with PKCE S256 completes; the state is single use and bound to the browser that started the
login (replays with the copied binding cookie, missing or forged bindings, tampered state, a mismatched `iss`
parameter, IdP errors and missing codes are refused); the code exchange authenticates the client and sends the
verifier; ID tokens are checked for signature, issuer, audience, expiry, issue time and nonce; identity is by issuer
and subject (a second user with the same email is refused, not merged); sessions are server-side with CSRF on unsafe
methods; logout revokes the session server-side; role and membership revocation apply to the next request.
**Not established:** behaviour with Microsoft Entra ID (multi-tenant issuers, `tid`, v1 and v2 endpoints, conditional
access, token formats), Okta or any other provider; key rotation at a live JWKS endpoint; back-channel or front-channel
logout; IdP-initiated logout; clock skew beyond the configured leeway; anything over TLS.
