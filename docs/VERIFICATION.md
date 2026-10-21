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

## Run 4: restore test of the preservation artifacts (2026-10-22 ~22:00Z, separate run)
Artifacts in `/home/dev/preservation/` (kept as release archives):
```
ac6b5fb745c13379f24bde6f5c17919f33894351cdc6847c07cb0ef7cb474d0d  axiom-foundation-20261022-18f0878-source.tar.gz
9c7f7ca23276739e209e7a1989e4a0bdb9d0b57893a1fadbc8917f1e5ab36829  axiom-foundation-20261022-18f0878.bundle
32c9cd7cb3d254bc2c272d8bc7cbc53b8fea15a56267901c0bb12dcf268adec1  axiom-foundation-20261022-18f0878-MANIFEST.txt
```
* `sha256sum -c SHA256SUMS`: all OK.
* `git clone <bundle>`: HEAD 18f0878, tag foundation-checkpoint-1 present, tree identical to the repository HEAD;
  `git bundle verify`: "is okay".
* Extracted source archive into an empty directory: 27 required paths present; no `.env`, `.env.test`, `*.pem`,
  `.venv` or data directories; no private keys; 101 files.
* From the extracted copy: `uv sync --frozen` then `pytest tests -q` against the disposable cluster:
  **92 passed, 2 skipped** (both S3 tests, skipped because no S3 endpoint was configured for this run), 1 warning.

## Phase B runs (2026-10-22, after the foundation checkpoint)

### Run 5: development suite with Phase B
`uv run pytest tests -q` on the long-lived test cluster: first attempt **1 failed, 122 passed, 2 skipped**. The
failure was a real authorisation bug: listing identity candidates required `asset.read` at the tenant root, so
project-scoped analysts got 403. Fixed by filtering candidates to readable scopes; rerun **123 passed, 2 skipped**
(S3 tests skipped: no endpoint configured for that run).

Mutation checks on the ingestion pipeline: forcing every run's coverage to "complete" made
`test_partial_scan...` and `test_tenable_identity...` fail (expected); removing the service-side lease check left
`test_stale_worker_is_fenced` passing because the database fence trigger still refused the stale page (expected,
defence in depth). Code restored and compared byte-for-byte afterwards.

### Run 6: full verification on a separate fresh cluster (2026-10-22 22:29Z)
`scripts/verify/foundation.sh`. Log: `docs/verification/2026-10-22-phase-b/foundation-verify.log`.
* Migrations: database 1 `applied: 0001, 0002, 0003`, re-run `applied: none`; database 2 in the same cluster
  `applied: 0001, 0002, 0003`; edited migration rejected (checksum mismatch).
* Structural audit: 40 tables with forced RLS, 2 global catalogue tables without, 0 not owned by `axiom_owner`;
  `axiom_app` not superuser, not BYPASSRLS, not an owner member.
* Fresh SeaweedFS; **125 passed, 0 skipped, 1 warning in 39.76s**. Per file: unit rules 31, adapters 12, cases 27,
  isolation 16, evidence/outbox 11, ingestion 12, sync 5, API 9, S3 2.

### Run 7: Compose fresh-install smoke with ingestion (2026-10-22 22:24Z to 22:28Z)
`scripts/verify/compose-smoke.sh` now also uploads the real Trivy fixture, imports it through `/api/v1/imports`,
and waits for the Compose `ingest-worker` to complete it.
* First attempt (BUILD=1): **failed** at the final re-initialisation check. The script slept a fixed 15 seconds and
  read the recreated init container's logs before it had run. Fixed to wait for the container to exit.
* Before the fix, two further runs passed (one with BUILD=1). After the fix, two consecutive runs passed:
  `SMOKE PASS (axiom-smoke-222712)` and `SMOKE PASS (axiom-smoke-222808)`, each including
  `Trivy import via API + ingest-worker: completed complete 30`. Logs: `docs/verification/2026-10-22-phase-b/`.

### Run 8: workflow experiments, independent reruns
* PostgreSQL-backed experiment (`experiments/workflow-pg-spike`): **26 passed in 96.53s** (my rerun; the original
  final run reported 26 passed in 95.52s).
* Temporal experiment with security and recovery probes (tests written in an earlier iteration whose run was stopped before
  it reported): my clean rerun `rm -rf .run && uv sync --frozen && uv run --frozen pytest -v -s tests/` in
  `experiments/workflow-spike`: **22 passed in 291.36s** (2026-10-22 01:34 to 01:39 local). The original
  first full run had also reported 22 passed (252.90s); its second run was cut off mid-test. Log:
  `docs/verification/2026-10-22-workflow/temporal-full-rerun.log`. Findings are summarised in ADR 0006.

### Run 9: strong-identifier conflict test (after commit 8bd94eb)
New test `test_strong_identifier_conflict_creates_conflict_asset_and_review` first **failed: 30 conflict assets
instead of 1** (each record of a conflicting import created its own holding asset and review candidate). Fixed with
a stable `identity_claim` key on the holding asset. Full suite afterwards: **124 passed, 2 skipped** (S3 not
configured for that run); ingestion file with the re-import assertion: 13 passed.
