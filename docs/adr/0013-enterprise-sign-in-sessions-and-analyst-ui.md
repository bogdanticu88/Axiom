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

## Amendment 2 (2026-10-22, checkpoint 7): review of the replacement client; secrets; session rotation

### What the libraries do and what the application now does
| Protection | Done by | Test |
|---|---|---|
| PKCE S256 challenge from the verifier (RFC 7636) | Authlib `create_s256_code_challenge` | `test_authorization_url_uses_pkce_s256_and_nonce` (and a known-answer check) |
| Authorization URL query encoding | Authlib `add_params_to_uri` | same |
| JWS signature verification, algorithm allow-list, JWK parsing | joserfc `jwt.decode`, `KeySet` | `test_rejected_signatures_and_algorithms`, `test_malformed_id_tokens_are_refused_not_errors` |
| `iss`, `aud`, `exp`, `iat`, `nonce`, `sub` claim checks with leeway | joserfc `JWTClaimsRegistry` (configured here) | `test_rejected_claims` |
| `azp` (several audiences, or present at all), maximum login age | **application** | `test_rejected_claims` |
| State, browser binding, single use, expiry | **application** (`axiom_auth` functions, migration 0015) | `test_callback_protections` (local Keycloak) |
| `iss` authorization-response parameter (RFC 9207) | **application** | same |
| Discovery issuer equality, required endpoints | **application** | `test_discovery_issuer_must_match` |
| Token request: client authentication (`client_secret_basic`), verifier, redirect URI | **application** (httpx) | `test_code_exchange_sends_pkce_verifier_and_basic_client_authentication` |
| Token response: status 200 only, JSON object, `id_token` present, `token_type` Bearer | **application** | `test_failed_code_exchanges_refuse_the_login` (including an HTTP 400 that carries an `id_token`) |
| No redirects followed (discovery, JWKS, token endpoint); 10 s timeout | **application** (httpx settings) | `test_timeouts_and_redirects_on_discovery_keys_and_token_endpoint_refuse` |
| One JWKS refresh on an unknown `kid`; a never-published key refused after it | **application** | `test_unknown_key_id_refreshes_the_key_set_once`, `test_a_key_the_idp_never_publishes_is_refused_after_one_refresh`; live rotation at the local Keycloak (`test_signing_key_rotation_at_the_local_idp_is_followed`) |
| Callback input never selects endpoints or keys | **application** (endpoints come only from configured discovery) | `test_callback_protections` (tampered state, foreign `iss`) |
| Sessions, CSRF, logout invalidation, rotation | **application** | `test_logout_revokes_the_session`, CSRF assertions, `test_login_rotates_the_session_and_keeps_codes_out_of_the_url_trail` |

No further client replacement was made: no concrete defect was found in the helpers the code uses. The application
owns the token request and response handling (about 30 lines) because the maintained Authlib client for httpx moved to
`httpx2`; moving to Authlib's `httpx2` client would hand those checks back to the library, but adds a dependency
that is not otherwise used and was not needed to fix anything found here.

### Defects and gaps found by this review
* **azp with a single audience was ignored** (OIDC Core 3.1.3.7 says the client should check it when present). A token
  for this audience but authorised to another client was accepted. Now refused; reproduced by the new
  `{"azp": "other"}` case in `test_rejected_claims` before the fix.
* **Login did not rotate an existing session.** A browser that already held a `axiom_session` kept it valid after a new
  login (two live sessions; session fixation risk if an attacker planted the first). The callback now revokes the
  previous session (`replaced_by_login`).
* **Authorization codes and state reached the access log**: uvicorn logs the request line, including the callback
  query. A logging filter now replaces the query of `/auth/callback` and `/auth/login` with `?[redacted]`. Errors and
  redirects were checked for the code, state, client secret and token: none contained them.
* **Production secrets could not be supplied** (see `docs/DEPLOYMENT-TRUST-BOUNDARY.md`): a mounted-file resolver
  (`secretref:file/`) now exists and is the only form accepted in production. Production also requires the redirect
  and post-logout URIs to share one origin, and the redirect URI to end in `/auth/callback`.

### Not applicable, and why
* Refresh tokens and access tokens: not requested for use and not stored; the platform keeps its own session.
* `at_hash` / `c_hash`: the ID token comes from the token endpoint over a server-to-server TLS channel in production
  (code flow), where OIDC Core makes `at_hash` optional; the access token is discarded.
* Front- and back-channel logout: not implemented (unchanged).

### Still not established
Everything is against one local Keycloak over plain HTTP. Sign-in over TLS, any hosted IdP (Microsoft Entra ID,
Okta), and the reverse-proxy arrangement are untested. Passing these tests does not verify production authentication.
