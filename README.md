# Axiom

Evidence-backed vulnerability management platform: ingest findings, establish asset and business context,
investigate with deterministic checks and constrained AI, prioritise by versioned policy, coordinate approved
remediation, verify outcomes against the affected deployment, and report from recorded evidence. Supports a shared
multi-client installation and dedicated single-enterprise installations from one codebase.

**Status: foundation checkpoint (Phase A, partly complete).** See `docs/IMPLEMENTATION_STATUS.md`. Nothing here is
production-ready. Authentication is development token authentication only; no connectors exist yet.

## Documents
* Design inputs: `docs/Axiom-Specification.md`, `...-Implementation-Plan.md`, `...-Data-and-Access-Design.md`
* Review of the supplied foundation: `docs/REVIEW-2026-10-22.md`
* Tracking: `docs/REQUIREMENTS.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/DECISIONS.md` and `docs/adr/`,
  `docs/VERIFICATION.md`, `docs/HANDOFF.md`
* Contributing: `CONTRIBUTING.md`

## Layout
```
backend/axiom/          API, auth, access control, domains (cases, evidence, assets, tenancy), migrations
db/provision_roles.sql     cluster-level role provisioning (run once per cluster)
deployments/compose/       single-host install (PostgreSQL, SeaweedFS S3, init jobs, API)
scripts/dev/test-db.sh     disposable PostgreSQL cluster for tests
scripts/verify/            full verification and Compose smoke test
tests/                     unit and PostgreSQL-backed integration tests
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
```

## Compose (single host, synthetic data)
```
cp deployments/compose/.env.example deployments/compose/.env    # replace every value
docker build -t axiom-backend:dev .                           # behind a TLS proxy: --secret id=ca,src=<ca.pem> --network host
docker compose -f deployments/compose/compose.yaml --env-file deployments/compose/.env up -d
TOKEN=$(docker compose -f deployments/compose/compose.yaml --env-file deployments/compose/.env exec -T api \
        python -m axiom.devtools mint --dir /var/lib/axiom/dev-idp --sub alice)
curl -H "Authorization: Bearer $TOKEN" -H "X-Axiom-Tenant: demo" http://127.0.0.1:8000/api/v1/cases
```
Seeded synthetic users and roles are listed in `backend/axiom/devseed.py`. Automated check:
`scripts/verify/compose-smoke.sh`.

## Restoring from a preservation archive
See `docs/HANDOFF.md`, section "Restore".

## Security model in one paragraph
Tenant isolation combines application authorisation, composite tenant-aware foreign keys and forced PostgreSQL
row-level security with transaction-bound context. Runtime database identities never own tables and are never
superuser or BYPASSRLS; the API refuses to start otherwise. RLS is defence in depth: an attacker who fully controls the
application process can choose any tenant context, so tenants needing stronger separation belong on a dedicated
installation (ADR 0002).
