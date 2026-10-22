# Deployment trust boundary, TLS termination and secret delivery

Status: describes what the code requires and refuses (checkpoint 7). **No production deployment has been made or
tested.** Everything below about TLS, proxies and secret mounting is an untested deployment assumption unless a test
is named.

## Supported arrangement

```
browser ──HTTPS──▶ TLS-terminating reverse proxy ──HTTP, private network──▶ API (uvicorn, AXIOM_BIND_HOST:AXIOM_PORT)
                    (operator-provided)                                      │
                                                                             ├──▶ PostgreSQL (runtime role)
API ──HTTPS──▶ identity provider (discovery, JWKS, token endpoint)           └──▶ object store
worker ──HTTPS──▶ check endpoints / trackers configured as connections
```

* **TLS terminates at a reverse proxy the operator runs** (for example nginx, HAProxy, an ingress controller or a
  cloud load balancer). The API does not serve TLS itself and is not meant to be reachable except from the proxy.
* **The API ignores forwarding headers** (`proxy_headers=False`). It never derives URLs, schemes or client addresses
  from `X-Forwarded-*`: every externally visible URL it uses (OIDC redirect URI, post-logout redirect URI) is
  configured, absolute and HTTPS. Client IP addresses in the access log are therefore the proxy's.
* The proxy must forward the `Host` it receives unchanged or not at all (the API does not use it for URLs), must not
  cache `/auth/*` or `/api/*` responses, and should strip any client-supplied `X-Forwarded-*` headers (they are unused
  today; stripping keeps a future change from trusting them).
* Cookies are `Secure` in production (start-up refuses otherwise), `HttpOnly` for the session and login binding,
  `SameSite=Lax`, path `/`. The UI and API must share one origin.

## What start-up refuses in production (`AXIOM_ENV=production`)

Tested in `tests/integration/test_oidc_sso.py::test_production_sso_settings_are_checked`, `test_unresolvable_client_secret_stops_start_up` and
`test_production_start_up_with_a_mounted_secret_file`, `tests/unit/test_secretrefs.py`:

* plain-HTTP issuer, discovery, redirect or post-logout URLs; non-Secure cookies; serving the UI without OIDC;
* a client secret given as a value, as `secretref:env/...`, or as anything other than `secretref:file/<path>`;
* a secret file outside the allowed directories (`AXIOM_SECRET_FILE_DIRS`, default `/run/secrets`), a missing, empty,
  non-regular or oversized (> 4096 bytes) file, or one that cannot be read; the error never contains the value;
* redirect and post-logout URIs on different origins; a redirect URI not ending in `/auth/callback`;
* inline JWKS (development tokens), non-HTTPS JWKS, the filesystem object store, a missing restore witness
  (worker).

## Secret delivery

Configuration holds references, never values (`axiom/secretrefs.py`):

| Reference | Where | Use |
|---|---|---|
| `secretref:file/<absolute path>` | every environment | Docker/Compose secrets, Kubernetes Secret volumes, systemd credentials, or a cloud secret store mounted as files (for example by a CSI driver). The path must resolve, after symlinks, inside `AXIOM_SECRET_FILE_DIRS`. One trailing newline is removed. |
| `secretref:env/<NAME>` | development and test only | local runs and tests |

The same resolver serves the OIDC client secret and connection credentials (trackers, scanners, check endpoints).
Values are read at use (OIDC: once at start-up, so a missing secret stops start-up). Rotation: replace the file and
restart the API (OIDC) — connection credentials are re-read on each use.

**Why checkpoint 6 said production sign-in could not be configured:** the only resolver then was the environment
resolver, and production refused it (environment variables leak into process listings, crash reports and child
processes). No file or secret-store resolver existed, so there was no accepted way to supply the client secret in
production. Checkpoint 7 adds the mounted-file resolver; no cloud provider or external secret service is required.

## Trust boundary

Trusted: the operator's proxy and network (the API trusts that only the proxy reaches it), the PostgreSQL server
and its role configuration (ADR 0003), the object store, the configured identity provider's discovery and JWKS (over
HTTPS in production), the secret files the deployment mounts, and the runtime database credential. That credential
(`axiom_app`) is shared by the API and the job worker for every tenant of the installation. Whoever holds it can bind
any tenant and any principal, read that tenant's rows and record decisions, approvals and audit entries in that
principal's name. The database keeps history append-only and enforces structural rules, but it does not authenticate
people (ADR 0012 amendment 4, ADR 0002).

Not trusted: browsers, request bodies and headers, token claims other than those validated (issuer, audience,
authorised party, expiry, issue time, nonce, subject), group or role claims (never used), callback query parameters
(only `state`, `code`, `iss` and `error` are read, and checked against stored state and configuration), check
endpoint and tracker responses (validated, preserved as evidence, never followed on redirect).

## Verified versus assumed

* **Verified locally, over TLS** (`tests/integration/test_tls_deployment.py`, checkpoint 8): an nginx reverse proxy
  (pinned image) terminates TLS with a certificate from a throwaway local CA for `localhost`, in front of the API in
  production mode and of a local Keycloak 26.4.2 that knows its public HTTPS address. The OIDC client secret comes
  from a mounted file. Chromium signs in through Keycloak's page and the callback over HTTPS; the session cookie is
  `Secure`, `HttpOnly` and `SameSite=Lax`, the CSRF cookie `Secure` and readable by the page; an unsafe request
  without the CSRF header is refused; logout revokes the session and the old cookie is then refused. Spoofed
  `Host`, `X-Forwarded-*` and `Forwarded` headers, through the proxy or sent straight to the API, do not change the
  sign-in redirect, the callback target or the post-logout address. Missing, empty, oversized, out-of-directory and
  symlink-escaping secret files stop start-up without the contents appearing in the error.
* **Verified locally, plain HTTP:** the full sign-in test suite against local Keycloak; the production configuration
  checks above.
* **Not verified:** a public certificate authority; a hosted identity provider (Microsoft Entra ID, Okta, others);
  provider interoperability beyond Keycloak; any proxy other than this nginx configuration; Docker, Kubernetes or
  systemd secret mounts (the test uses a directory on the test host); a public or hostile network; load. Production
  authentication is **not** verified by these local tests.

### The proxy configuration that was tested
```
server {
  listen 443 ssl;                                    # the test used a random port on 127.0.0.1
  ssl_certificate /certs/leaf.pem; ssl_certificate_key /certs/leaf.key;
  location / {
    proxy_pass http://<api address>;
    proxy_set_header Host $host:$server_port;
    proxy_set_header X-Forwarded-For ""; proxy_set_header X-Forwarded-Host "";
    proxy_set_header X-Forwarded-Proto ""; proxy_set_header Forwarded "";
  }
}
```
