# Compose installation (development and evaluation, synthetic data only)

This profile runs the whole platform on one host with **synthetic** tenants and users: PostgreSQL, single-node
object storage (SeaweedFS), the API serving the analyst UI, the job worker, and a local Keycloak for sign-in. It is
not a production profile. What it lacks for production is listed at the end.

## Requirements
* Docker Engine with Compose v2.
* Free loopback ports for the API/UI (default 8000) and the local identity provider (default 8081).
* For a rebuild behind a TLS-intercepting proxy: the proxy's CA bundle (`BUILD_CA`, passed as a build secret).

## Start
```
cp deployments/compose/.env.example deployments/compose/.env
# replace every value; generate each with: python3 -c 'import secrets;print(secrets.token_urlsafe(24))'
docker compose -f deployments/compose/compose.yaml --env-file deployments/compose/.env up -d --build
```
Then open `http://127.0.0.1:${AXIOM_API_PORT}/ui/` and choose **Sign in**. The browser goes to the local Keycloak login
page; sign in as one of the synthetic users with the password from `AXIOM_DEMO_PASSWORD`.

| User | Role in tenant `demo` (project `payments` unless noted) |
|---|---|
| alice, carol | analyst |
| bob | remediation owner |
| dave | approver |
| erin | risk owner (delegation limit up to `high`, 90 days) |
| admin | tenant administrator (root) |
| audrey | auditor (root) |
| consult | analyst in `demo` and in `demo-two` |

The order of start-up is enforced by Compose: `db-init` (cluster roles and database) → `app-init` (migrations,
development bearer-token keys, synthetic seed, evidence bucket) → `idp-init` (Keycloak realm and the mapping of each
Keycloak subject to the seeded principal) → `keycloak`, `api`, `job-worker`. The init services are idempotent;
re-running them applies no migration and seeds nothing twice.

## Configuration (`deployments/compose/.env`)
| Variable | Purpose |
|---|---|
| `AXIOM_PG_SUPERUSER_PASSWORD`, `AXIOM_MIGRATOR_PASSWORD`, `AXIOM_APP_PASSWORD`, `AXIOM_RELAY_PASSWORD`, `AXIOM_ADMIN_CLI_PASSWORD` | Database identities (superuser for initialisation only; separate migrator, runtime, relay and provisioning logins) |
| `AXIOM_S3_ACCESS_KEY`, `AXIOM_S3_SECRET_KEY` | Object storage credentials |
| `AXIOM_OIDC_CLIENT_SECRET` | Client secret of `axiom-ui` in the local Keycloak; the API receives it as `secretref:env/AXIOM_OIDC_CLIENT_SECRET` |
| `AXIOM_DEMO_PASSWORD` | Password of every synthetic Keycloak user |
| `AXIOM_API_PORT`, `AXIOM_IDP_PORT` | Loopback ports for the API/UI and Keycloak |

The API container is configured with: `AXIOM_UI_DIST_DIR=/app/ui` (the UI built into the image), `AXIOM_OIDC_ISSUER`
(the public issuer URL the browser uses), `AXIOM_OIDC_METADATA_URL` (the same discovery document on the container
network; its `issuer` must still equal `AXIOM_OIDC_ISSUER`), `AXIOM_OIDC_CLIENT_ID`, `AXIOM_OIDC_CLIENT_SECRET_REF`,
`AXIOM_OIDC_REDIRECT_URI`, `AXIOM_OIDC_POST_LOGOUT_REDIRECT_URI` and `AXIOM_UI_COOKIE_SECURE=false` (plain HTTP on loopback).
Development bearer tokens (`python -m axiom.devtools mint`) still work for API scripts in this profile.

## What fails closed
The API refuses to start, rather than starting insecurely, when:
* `AXIOM_ENV=production` and any trusted issuer uses an inline JWKS (development tokens), a JWKS URL is not HTTPS, or the
  object store is the filesystem;
* `AXIOM_ENV=production` with sign-in configured and the issuer, redirect, discovery or post-logout URL is not HTTPS, or
  session cookies are not `Secure`;
* `AXIOM_ENV=production` and the UI is served without OIDC sign-in;
* no trusted issuer is configured at all;
* sign-in is configured without a client id, a secret reference or a redirect URI, or the secret is given as a value
  instead of a `secretref:`;
* the client secret reference does not resolve (checked at start-up, not at the first login).

In production the environment secret resolver is refused; the client secret must be a mounted file
(`secretref:file/run/secrets/<name>`, inside `AXIOM_SECRET_FILE_DIRS`, default `/run/secrets`). This Compose profile
still uses `secretref:env/` because it runs in development mode. The Compose smoke test starts the API with
`AXIOM_ENV=production` and checks the refusal, and starts it without the client secret and checks that it stops. A
production deployment's TLS and proxy arrangement is described in docs/DEPLOYMENT-TRUST-BOUNDARY.md (untested).

## Optional: the verification worker
Automated verification (ADR 0014) runs only when a tenant has a verification identity and a check endpoint is
configured for the case's project:
run the provisioning CLI with the provisioning login (`axiom_admin_cli`, as `app-init` does; the API container does not
hold that login):
```
python -m axiom.provisioning --dsn "host=... dbname=axiom user=axiom_admin_cli password=..." \
    create-verification-identity --tenant <tenant id> [--scope <project scope id>]
```
This step is not exercised by the Compose smoke test. Then create a connection with adapter `verification_check` (HTTPS base URL, optional `secretref:` bearer token) as a
user with `connection.configure`. No check endpoint ships with this profile; the worker has been tested only against
a local fixture endpoint.

## Verify an installation
`BUILD=1 scripts/verify/compose-smoke.sh` creates a throwaway project with new secrets and volumes, runs the API
checks, imports a real Trivy report through the worker, then drives a real Chromium browser
(`scripts/verify/compose_ui_check.py`): the UI is served with its CSP; alice signs in on the Keycloak page and moves
a case to investigating; audrey (auditor) is refused by the server; signing out revokes the session server-side.
It removes everything afterwards.

## Not production
Keycloak runs in development mode with in-container H2 storage, HTTP and an imported realm containing synthetic users
and secrets; the API uses plain HTTP and non-Secure cookies; there is one PostgreSQL instance and single-node object
storage; no TLS, backups or monitoring, and secrets come from environment variables. Sign-in has been tested only against this local Keycloak;
Microsoft Entra ID and other hosted identity providers are not tested.
