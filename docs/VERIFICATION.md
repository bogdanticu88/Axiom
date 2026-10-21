# Verification log

Every result below was produced by an actual run in this workspace. Separate runs are listed separately; results from
one run are never combined with another without saying so. Logs are stored under `docs/verification/`.

## Environment (recorded by run 1)
Linux container; Python 3.13.16; uv 0.11.32; PostgreSQL 16.15 server binaries (Ubuntu build) for test clusters;
Docker 29.9.1; Docker Compose v5.6.0. Locked packages: fastapi 0.143.0, psycopg 3.3.6, psycopg-pool 3.3.3,
pydantic 2.14.1, pyjwt 2.15.1, boto3 1.43.113, pytest 9.1.1. Compose images: PostgreSQL 16.15 (Debian build) and
SeaweedFS 4.48, both digest-pinned (ADR 0007).

## Run 0: supplied foundation, as received (2026-10-22, before any change)
Disposable PostgreSQL 16.15 cluster.
```
psql ... -v ON_ERROR_STOP=1 -f migrations/0001_foundation.sql      # exit 0
psql ... -v ON_ERROR_STOP=1 -f scripts/verify_isolation.sql        # "Isolation checks passed; fixture changes rolled back."
PYTHONPATH=backend python3 -m unittest discover -s tests -v        # Ran 8 tests ... OK
```
Probes and their observed results are in REVIEW-2026-10-22.md section 2.

## Run 1: complete foundation verification on a separate fresh cluster (2026-10-22 21:52Z)
Command: `scripts/verify/foundation.sh` (git HEAD 9eb5dd0 plus uncommitted tests and docs that are part of the
foundation checkpoint commit). Log: `docs/verification/2026-10-22/foundation-verify.log`.

| Check | Result |
|---|---|
| Fresh cluster (port 55433, new data dir) initialised, roles provisioned | ok |
| Role provisioning run a second time | ok (idempotent) |
| Database 1: migrate | `applied: 0001, 0002` |
| Database 1: migrate again | `applied: none` |
| Database 2 in the same cluster: migrate | `applied: 0001, 0002` |
| Edited migration through the runner | `rejected as expected: checksum mismatch for applied migration 0001_foundation.sql` |
| Structural audit as `axiom_app` | 28 tables with forced RLS; 2 without (`permissions`, `role_permissions`: global, non-secret catalogue, read-only to runtime); 0 not owned by `axiom_owner`; `axiom_app` superuser=f, bypassrls=f, owner member=f |
| Fresh SeaweedFS 4.48 container, bucket | created on first attempt |
| `pytest tests -v -rA` (unit + PostgreSQL + S3), new session database | **94 passed, 0 skipped, 1 warning in 29.49s** |
| Teardown | SeaweedFS removed, cluster destroyed, generated credentials deleted |

The warning is `StarletteDeprecationWarning` from `fastapi.testclient` about httpx; it does not come from platform
code.

Of the 94 passed test items (counted from the log; parametrised cases count individually): 31 unit
(tests/unit/test_rules.py), 27 case lifecycle, 16 isolation, 11 evidence/outbox, 7 API, 2 S3. The five tests added after the previous run (deferral, remediation target,
recorded authority, citation classification, audit redaction) are included and passed.

### What run 1 confirms
| Property | Tests |
|---|---|
| Fresh database can be provisioned | foundation.sh steps; conftest creates a new session database |
| Second database in the same cluster | foundation.sh step "database 2" |
| Re-applying migrations is a no-op | foundation.sh; iso::test_migration_ledger_is_idempotent_and_detects_edits |
| Changed checksums rejected | foundation.sh CLI check; iso::test_migration_ledger... |
| No tenant context leak across pooled transactions | iso::test_session_level_context_does_not_leak_into_next_transaction, ::test_pool_reuse_rollback_and_tenant_switching (single reused connection, rollback, tenant switch), ::test_cannot_switch_tenant_inside_transaction |
| Runtime credentials cannot bypass lifecycle commands | iso::test_direct_sql_cannot_bypass_case_commands, ::test_closure_without_valid_record_fails_at_commit, ::test_append_only_tables_reject_mutation_even_for_owner, ::test_runtime_role_self_check |
| Audit, event and outbox atomic with case changes | cases::test_audit_failure_prevents_transition (DB fault), ::test_audit_failure_in_application_prevents_transition, ::test_full_lifecycle... (9 events, 9 outbox rows, each event audited) |
| Evidence access and integrity controls | evo::test_upload_finalise_and_audited_download, ::test_digest_mismatch..., ::test_oversize..., ::test_only_uploader..., ::test_finalise_before_upload_rejected, ::test_classification_permissions_and_denial_audit, ::test_cross_tenant_evidence_is_not_found, ::test_storage_tampering..., ::test_tenant_object_store_refuses_foreign_keys, s3::test_s3_roundtrip_and_size_limit, s3::test_s3_evidence_finalise_and_tamper_detection |

## Run 2: Compose fresh-install smoke test (2026-10-22 21:53Z, separate from run 1)
Command: `BUILD=1 BUILD_CA=/root/.ccr/ca-bundle.crt scripts/verify/compose-smoke.sh`. Throwaway project
`axiom-smoke-215350`, new volumes, generated secrets, `down -v` afterwards. Image rebuilt from the working tree
(`sha256:1ec695eb...`). Log: `docs/verification/2026-10-22/compose-smoke.log`.

```
ok   fresh install: migrations applied, api healthy
ok   no token -> 401
ok   evidence upload -> verified -> download via S3 (SeaweedFS)
ok   digest mismatch -> rejected
ok   case create, start-investigation, stale version -> 409
ok   consultant in other tenant -> 404; non-member tenant selection -> 403
ok   case events linked to audit rows: 2
ok   re-running init: migrations 'applied: none', seed 'already seeded'
SMOKE PASS (axiom-smoke-215350)
```

## Run 3: Temporal experiment, independent rerun (2026-10-22 ~00:35 local)
`cd experiments/workflow-spike && ./scripts/fetch_temporal_cli.sh && uv sync --frozen && uv run --frozen pytest -v -s tests/`
Result: **9 passed in 76.11s**; Temporal CLI 1.9.1 (Server 1.32.0). Real SIGKILL to worker and server process groups
confirmed in `tests/harness.py`. This is an experiment, not product code.

## Earlier development runs (superseded by run 1)
Recorded for traceability: 22 case tests on first run; 38 integration after the pool fix (the pool reuse test
initially failed because the reset hook left connections in a transaction and the pool discarded them; fixed in
`db._reset`); 79 then 87 total; a deliberate mutation of two guards made the two expected tests fail, and the
database trigger independently rejected the forced wrong-digest pass.

## Manual checks
* API under uvicorn as `axiom_migrator` refuses to start: `unsafe runtime database role axiom_migrator: is a member of
  axiom_owner, owns platform objects, lacks axiom_runtime privileges` (ConfigurationError, "Application startup failed").

## Not verified (by design of this checkpoint)
Production SSO; any connector; ingestion; investigation; policies; actions and approvals in product code; reporting;
UI; Helm/AKS; backups and restore; retention and deletion; load, latency or cost; behaviour on a managed PostgreSQL
service. Nothing here demonstrates production readiness.
