# Axiom foundation

Implementation checkpoint: domain transition guards, exact-scope grants, initial PostgreSQL schema and isolation verification script.

This is the beginning of the complete platform defined in the accompanying specifications. Authentication, API, storage service, workers, adapter catalogue, UI and remaining domain tables are not implemented yet.

## Run domain checks

From this directory:

    PYTHONPATH=backend python3 -m unittest discover -s tests -v

## Verify PostgreSQL

Use a fresh disposable PostgreSQL database. Migration creates a NOLOGIN group role; a privileged provisioning identity must apply it. Existing installations need a migration ledger and role provisioning strategy before automated upgrades.

    psql "$AXIOM_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/0001_foundation.sql
    psql "$AXIOM_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f scripts/verify_isolation.sql

Use runtime connections with membership in axiom_runtime, no ownership, no superuser or BYPASSRLS privileges. Tenant context must be transaction-local and set only after trusted authorisation. RLS does not protect against a compromised service that can select arbitrary tenant context.

Runtime grants currently permit reads and inserts only; mutation procedures are a subsequent implementation step. Domain objects must be constructed from trusted persisted state. Client-supplied closure flags must never be passed directly as validated evidence.

## Verification status

Python tests run locally. PostgreSQL migration and isolation script require live database verification. Docker daemon was unavailable in the authoring environment. No production-readiness claim is made.
