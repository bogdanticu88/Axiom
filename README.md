# Axiom

Evidence-backed vulnerability management platform: ingest findings, establish asset and business context,
investigate with deterministic checks and constrained AI, prioritise by versioned policy, coordinate approved
remediation, verify outcomes against the affected deployment, and report from recorded evidence. Supports a shared
multi-client installation and dedicated single-enterprise installations from one codebase.

**Status: work in progress; nothing here is production-ready.** Built and tested so far: the foundation (tenant
isolation, database roles, evidence storage, the case workflow), ingestion, a durable job runner, the action and
approval protocol, risk acceptance, policies, ownership, SLA clocks, reporting, evidence-backed investigation against a
**deterministic fake model** (no language model has been called), an analyst UI, OIDC sign-in tested **only against a
local Keycloak**, and a verification worker tested **only against a local fixture endpoint**. Connectors are at most
**fixture-tested**; none has been validated against a live service. Details: `docs/IMPLEMENTATION_STATUS.md`.

## Documents
* Design inputs: `docs/Axiom-Specification.md`, `...-Implementation-Plan.md`, `...-Data-and-Access-Design.md`
* Review of the supplied foundation: `docs/REVIEW-2026-10-22.md`
* Tracking: `docs/REQUIREMENTS.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/DECISIONS.md` and `docs/adr/`,
  `docs/VERIFICATION.md`, `docs/HANDOFF.md`
* Contributing: `CONTRIBUTING.md`

## Layout
```
backend/axiom/             API, auth, access control, domains (cases, risk, actions, evidence, assets, tenancy),
                           ingestion and adapters, job runner (axiom.jobs), verification worker, migrations
db/provision_roles.sql     cluster-level role provisioning (run once per cluster)
deployments/compose/       single-host install (PostgreSQL, SeaweedFS S3, init jobs, API, job worker)
scripts/dev/test-db.sh     disposable PostgreSQL cluster for tests
scripts/verify/            full verification and Compose smoke test
scripts/ci/run.sh          the CI pipeline (also called by .github/workflows/ci.yml, which has never run)
tests/                     unit, PostgreSQL-backed integration tests, opt-in restore drills (tests/drills)
experiments/               workflow-engine experiments (not product code)
docs/design-inputs/        supplied foundation code kept for reference
```

## Fresh install from source (development)
Requirements: Linux, Python 3.13, uv 0.11+, PostgreSQL 16 server binaries (for tests), Docker with Compose v2+.
```
uv sync --frozen
scripts/dev/test-db.sh start            # disposable cluster on 127.0.0.1:55432, writes .env.test
uv run pytest tests -q                  # unit + PostgreSQL tests (S3 tests skip without an endpoint)
scripts/verify/foundation.sh            # full verification on a separate fresh cluster incl. S3 (needs Docker)
scripts/ci/run.sh                       # foundation + physical restore drill + Compose smoke (rebuilds the image)
```
Background work (ingestion runs, action executions, risk sweeps) runs in `python -m axiom.workers.jobs`. Set
`AXIOM_RESTORE_WITNESS` (`dir:/path` or `s3:bucket/prefix`, outside the database's backup domain) so restored or rolled
back databases are detected before any external effect is repeated (ADR 0010); production refuses to start without it.

## Compose (single host, synthetic data)
```
cp deployments/compose/.env.example deployments/compose/.env    # replace every value
docker build -t axiom-backend:dev .                           # behind a TLS proxy: --secret id=ca,src=<ca.pem> --network host
docker compose -f deployments/compose/compose.yaml --env-file deployments/compose/.env up -d
TOKEN=$(docker compose -f deployments/compose/compose.yaml --env-file deployments/compose/.env exec -T api \
        python -m axiom.devtools mint --dir /var/lib/axiom/dev-idp --sub alice)
curl -H "Authorization: Bearer $TOKEN" -H "X-Axiom-Tenant: demo" http://127.0.0.1:8000/api/v1/cases
```
The analyst UI is at `http://127.0.0.1:8000/ui/`; sign in on the local Keycloak page as a seeded user (for example
`alice`) with the password from `AXIOM_DEMO_PASSWORD`. Full procedure, configuration and what fails closed:
docs/INSTALL-COMPOSE.md. Seeded synthetic users and roles are listed in `backend/axiom/devseed.py`. Automated
check: `scripts/verify/compose-smoke.sh` (needs `uv sync` and Chromium for its browser step).

## Restoring from a preservation archive
See `docs/HANDOFF.md`, section "Restore".

## Security model in one paragraph
Tenant isolation combines application authorisation, composite tenant-aware foreign keys and forced PostgreSQL
row-level security with transaction-bound context. Runtime database identities never own tables and are never
superuser or BYPASSRLS; the API refuses to start otherwise. RLS is defence in depth: an attacker who fully controls the
application process can choose any tenant context, so tenants needing stronger separation belong on a dedicated
installation (ADR 0002).
