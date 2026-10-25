# Verification log

Every result below was produced by an actual run in this workspace. Separate runs are listed separately; results from
one run are never combined with another without saying so. Logs are stored under `docs/verification/`.

Commit hashes in the run records refer to the original development repository. The history was rewritten when the
project was renamed to Axiom, so those hashes do not exist here; use the checkpoint tags instead. Paths in archived logs
were normalised (the build host's home directory reads `/home/dev/`).

## Correction (2026-10-23): local CI passes that depended on the workspace

The "clean-clone CI PASS" results of runs 13 to 22 were produced in this workspace with its environment inherited by
the CI script. Two settings in that environment hid test defects that GitHub Actions exposed on its first runs
(`bc2a6aa` and `8c0b483`):

* **Time zone.** The workspace runs in Europe/Bucharest, and the test PostgreSQL clusters were initialised with that
  zone. `test_actions_api::test_action_journey_with_idempotent_execution` (since run 13) reused an idempotency key
  with the expiry echoed back by the server. Rendered in +03:00 it differed in spelling from the UTC value first
  sent, so the request was rejected as the test expected; under UTC it matched and was replayed, and the test
  failed. The test was asserting an application defect: the digest compared timestamps by spelling.
* **Node trust settings.** `NODE_OPTIONS=--use-openssl-ca` (with `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS`) made
  Playwright's Node-based request client trust the TLS test's local CA. Without it, the CSRF checks in
  `test_tls_deployment::test_browser_sign_in_over_tls_…` (since run 20) failed with "unable to verify the first
  certificate".

The historical entries below are kept as they were recorded. Read their CI results as "passed in this workspace's
environment" (Europe/Bucharest, inherited certificate settings), not as environment-independent results. Both
defects are fixed and the results re-established with a declared environment in run 23.

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
Command: `BUILD=1 BUILD_CA=<proxy CA bundle> scripts/verify/compose-smoke.sh`. Environment note: the build sandbox
for this run reached package registries through a TLS-intercepting proxy, so `BUILD_CA` pointed at that proxy's CA
bundle (`/root/.ccr/ca-bundle.crt`, a path that exists only in that sandbox). Later CI runs used the same setting.
Users do not need this path; without such a proxy, leave `BUILD_CA` unset. Throwaway project
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
* First attempt (BUILD=1): **failed**. At the time I attributed it to the final re-initialisation check (fixed
  15-second sleep) and replaced the sleep with a wait for the container to exit. **That diagnosis was wrong or at
  least incomplete:** see run 10, where the same symptom recurred and the real cause was found (`grep -q` under
  `set -o pipefail`).
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

### Run 10: final verification at commit 3093609 (2026-10-22 22:40Z to 22:45Z)
* `scripts/verify/foundation.sh` at `3093609` (clean tree): migrations `applied: 0001, 0002, 0003`, re-run
  `applied: none`, second database `applied: 0001, 0002, 0003`; edited migration rejected; 40 tables with forced RLS;
  **126 passed, 0 skipped, 1 warning in 42.72s**. Log: `docs/verification/2026-10-22-final/foundation-verify.log`.
* `BUILD=1 scripts/verify/compose-smoke.sh`: **failed** with "migrations not applied on fresh install" although the
  logs contained `applied: 0001, 0002, 0003`. Root cause: `docker compose logs ... | grep -q` under `set -o pipefail`;
  `grep -q` exits at the first match, the log writer receives SIGPIPE and the pipeline reports failure depending on
  timing and log size. This is a defect in the test script, not in the platform, and it most likely explains the
  run 7 first failure too. Fixed by using `grep ... >/dev/null`.
* After the fix, three consecutive runs passed: `SMOKE PASS (axiom-smoke-224301)`, `(-224400)`, `(-224456)`, each
  including the Trivy import through the API and ingest worker. Logs in `docs/verification/2026-10-22-final/`.

### Run 11: restore test of the Phase B preservation set (2026-10-22 ~22:47Z)
Artifacts built from commit 0ce7b8d (tag `phase-b-checkpoint-1` points to 3ec1632):
```
7c21b76b5b1896e75eac6290be3dbf5780f1f96895a26f5b46d7f6bc6bbe4e27  axiom-phaseb-20261022-0ce7b8d-source.tar.gz
df66c33775bc30e92584fb311fdd631589bd2c09074e217e8321439e0fc9ac9b  axiom-phaseb-20261022-0ce7b8d.bundle
ba8416fc7142030c52bd582448648b9143b42e762ac19c1f90e74a730687a9ab  axiom-phaseb-20261022-0ce7b8d-MANIFEST.txt
```
`sha256sum -c`: all OK. Bundle: "is okay", both tags present, tree identical to repository HEAD. Extracted source:
165 files, no `.env`, keys, virtual environments or data directories. From the extracted copy with a fresh
SeaweedFS: **126 passed, 0 skipped**, 1 warning, 43.65s. (This entry was added after the archive was built, so the
archive's own copy of this file stops at run 10.)

### Run 12: job runner and ingestion on jobs (2026-10-22 ~23:00Z to 23:08Z)
* `tests/integration/test_jobs.py` first run: 22 passed, **2 failed**: `drain_status` used `NOT IN %s` with a tuple
  (psycopg 3 does not adapt tuples; now `<> ALL(%s)`), and the provisioning CLI could not read effect intents to
  report a restore (now a read-only column grant and policy for `axiom_provisioner`). Then 24 passed.
* Ingestion handler bug found while writing its tests: I had guessed the run's terminal statuses instead of using the
  schema's (`completed`, `failed`, `cancelled`), so a run finished by a fenced-out step would have left its job waiting
  forever. Fixed; `ingjob::test_run_finished_by_a_fenced_out_step...` fails when the guessed values are restored.
* Mutation checks (`docs/verification/2026-10-22-phase-b/jobs-mutation-checks.log`): caught when removing the job
  fingerprint check, lookup-before-create, the poison claim limit, the lease cap at the step deadline,
  effect-boundary revalidation, fencing of the final write, and the ingestion terminal statuses. **Not caught:**
  removing the heartbeat's `step_deadline_at > now()` condition; the lease cap (`LEAST(..., step_deadline_at)`)
  enforces the same deadline, so that condition is redundant rather than untested.
* `scripts/verify/foundation.sh` (fresh cluster, fresh SeaweedFS): migrations `applied: 0001, 0002, 0003, 0004`,
  re-run `applied: none`, second database `applied: 0001, 0002, 0003, 0004`; **154 passed, 1 warning in 60.32s**
  (includes job 24, ingestion-jobs 4, S3 2). Structural audit: 43 tables with forced RLS; 3 global tables without
  (`permissions`, `role_permissions`, and the new installation-level `recovery_acknowledgements`, which the runtime
  can only read and which is append-only); `axiom_app` not superuser, not BYPASSRLS, not an owner member.
  Log: `docs/verification/2026-10-22-jobs/foundation-verify.log`.
* Compose smoke, first attempt: **failed** (`import via worker: queued unknown None`) because I ran it without
  `BUILD=1`, so the stale image had no `axiom.workers.jobs` module. Log kept as `compose-smoke-stale-image.log`.
  With `BUILD=1`: `SMOKE PASS (axiom-smoke-230723)`, including
  `Trivy import via API + job-worker: completed complete 30`. Log: `docs/verification/2026-10-22-jobs/compose-smoke.log`.
* Not covered: database-server crash with the product runner (only in the experiment), load, CI.

### Run 13: action protocol, two-step risk acceptance, job operations, restore witness, CI (2026-10-22 ~06:00Z to 07:45Z)

> Correction (2026-10-23): this run's CI result depended on the workspace environment; see the correction at the top of this file.

Bugs found by the new tests while writing them (all fixed before the recorded runs):
* **Intent creation race**: two jobs creating the intent for one operation key at once both found no row; the second
  insert failed with a unique violation. Now `INSERT ... ON CONFLICT DO NOTHING` then re-read under lock
  (act::test_two_jobs_racing_on_one_operation_key_send_one_first_attempt).
* A duplicate pending risk request surfaced as a raw unique-index error; now a 409 `request_pending`.
* Test-side mistakes corrected: a viewer gets 404 (not 403) for proposals it cannot read; analysts hold `job.read`
  only at project scope, so tenant-wide job reads are 403 for them; `audit_events` uses `occurred_at`; the sweep
  result now includes lapsed requests and reassessment notices. A 80-day test value I picked was below the 90-day
  independence threshold, so the acceptance (correctly) went through; restored to 120 days.

Mutation checks (`docs/verification/2026-10-22-actions-mutation-checks.log`): 12 targeted mutations, 11 caught. The
one not caught removed only the proposal lock; the approval row lock still serialises reservations. Removing **both**
service locks was caught 3/3, and the database CHECK on use counts rejected the over-reservation each time
(raw `CheckViolation`), so no approval was over-used. Other mutations caught: no state re-read when marking executing;
lookup miss treated as proof; approval status, approver authority and preconditions ignored at execution; proposer
approval with only the DB trigger left; idempotency digest not compared; witness not checked; risk self-authorisation
with only the DB check left; stale risk requests; renewal chain ignored at expiry.

Timing-sensitive tests (stale worker x4 variants, two-job race, 4 workers x 12 executions): 5 consecutive runs,
7 passed each (`docs/verification/2026-10-22-actions/timing-tests-5x.log`).

CI pipeline `scripts/ci/run.sh` (this is a local execution; the hosted workflow has never run):
* **First run: failed** in three stages, none due to product code. The Docker daemon was not running after the
  workspace restarted (SeaweedFS could not start, so the 2 S3 tests failed with "object storage unavailable", and the
  Compose image build failed), and the restore drill could not start its cluster because port 55434 was held by a
  leftover cluster from an earlier run. My earlier "port free" check used `ss`, which is not installed here, so
  it proved nothing. Fixes: started `dockerd`; the drill now picks a free port and destroys its cluster even when
  start fails. Output kept as `docs/verification/2026-10-22-actions/ci-run1-failed.out`.
* **Second run: CI PASS** (on the working tree then committed unchanged as f07607b; only documentation changed after). Dependencies (locked), byte-compile, tracked-file secret scan (no keys, no `.env` files)
  passed. Foundation on a fresh separate cluster with fresh SeaweedFS: migrations `applied: 0001 ... 0007`,
  re-run `applied: none`, second database `applied: 0001 ... 0007`, edited migration rejected (checksum), RLS audit 51
  tables forced, 3 global tables without (`permissions`, `role_permissions`, `recovery_acknowledgements`), 0 not owned
  by `axiom_owner`; **199 passed, 1 skipped (the opt-in drill), 1 warning in 110.17s**. New files: actions 28,
  actions API 4, risk two-step 7, restore witness 5, jobs 25, ingestion jobs 4. Physical snapshot drill: **1 passed**.
  Compose smoke with a rebuilt image (`sha256:d0b2177a95ac...`), job worker running with a restore witness volume:
  `SMOKE PASS (axiom-smoke-074003)`. Logs: `docs/verification/2026-10-22-actions/`.

Not covered: any live tracker (the Jira-style integration is fixture-tested only); the S3 witness backend; hosted CI;
load beyond the 4 x 12 concurrency test; point-in-time recovery.

### Run 14: R7, per-class permissions, witness hardening, Phase D tracking, workflow adapters (2026-10-22 ~07:50Z to 08:15Z)

> Correction (2026-10-23): this run's CI result depended on the workspace environment; see the correction at the top of this file.

Problems found while building (fixed before the recorded run):
* Design flaw in my own witness: one overwritten record per worker could be **lowered** by a second instance sharing
  a worker ID. Replaced by write-once records (`<watermark>-<worker>`); the high-water mark is the largest name listed.
* Acknowledging a same-fingerprint rollback would have let a job carried across the restore run its effect again.
  Acknowledgements are now an append-only log, and jobs older than the latest one park until reconciled individually.
* An unreadable witness parked every action for an operator; it now makes the step retry (nothing is sent).
* The permission catalogue allows no dot after the colon, so class permissions use `action.approve:ticket_create`.
* Test-side mistakes: unescaped `%` in a LIKE pattern; an SLA test shifted the case's creation time instead of the
  timer's start; one test never set its object store; the adapter catalogue rename broke an older assertion; two of
  my R7 tests had assertions that could not fail (`pytest.raises(Exception)` and an `or`); both tightened.

Mutation checks (`docs/verification/2026-10-22-r7-mutation-checks.log`), 11 of 11 caught: R7 evidence check and
unresolved-effect check removed from the service (the database guard still refused; the tests fail on the raw error),
obsolete proposals not withdrawn, plan-epoch precondition ignored, failed check on an abandoned plan sent back to
remediating, every class checked as ticket.create, acknowledgement clearing carried jobs, one overwritten S3 object
per worker, SLA breach announced on every sweep, snapshot digest not checked, export digest not checked.

GitHub Actions pins: resolved with `git ls-remote` and shallow fetches from the official repositories; inputs checked
in each pinned `action.yml` (docs/ci-action-pins.md). `scripts/ci/check-action-pins.sh`: 3 ok.

S3 witness development runs used a separate local SeaweedFS (port 18335) with three identities (full, read+list,
read+write). The permission failures were confirmed to be `AccessDenied` on PutObject (read-only identity) and on
ListObjectsV2 (no-list identity) before the assertions were made strict.

CI pipeline `scripts/ci/run.sh`, **CI PASS on the first run** (local execution; hosted CI never run):
dependencies, byte-compile, secret scan, no `.env` files, action pins (3 ok); foundation on a fresh separate cluster
with fresh SeaweedFS and three identities: migrations `applied: 0001 ... 0011`, re-run `applied: none`, second
database `applied: 0001 ... 0011`, edited migration rejected, RLS audit 55 tables forced, 3 global tables without,
0 not owned by `axiom_owner`; **256 passed, 1 skipped (opt-in drill), 1 warning in 128.02s** (new or changed files:
R7 10, workflow adapters 18, tracking/reports 7, restore witness 7, S3 witness 5 with no skips, witness config 12,
actions 30, actions API 5); physical snapshot drill 1 passed; Compose smoke with a rebuilt image
(`sha256:d76aa782a774...`): `SMOKE PASS (axiom-smoke-081224)`. Logs: `docs/verification/2026-10-22-r7/`.

The run used the uncommitted working tree. Content hash of every tracked or new file under backend, tests, scripts,
deployments, Dockerfile, .github, pyproject.toml and uv.lock at run time (sorted `sha256sum` of each file, hashed):
`a12af0d98c129695f5c6b633ce74aec24958237153bd8b070d076393fbc2f813`; the code commit e7a2f3602674b264b15b426741497436e3881206 reproduces exactly this hash (recomputed from the commit with `git show` per file), so it is the tested code.

Not covered: any live tracker; the witness on a production object store; hosted CI; load; point-in-time recovery.

### Run 15: policies, ownership, SLA v2, reporting depth, witness pruning audit, journey (2026-10-22 ~08:40Z to 09:02Z)

> Correction (2026-10-23): this run's CI result depended on the workspace environment; see the correction at the top of this file.

**Tested object: the exact committed tree.** CI ran on a fresh `git clone` of commit
`4a3069ac903b2f7b991c70c72c0c3df95a52e85b` (tree `06603b6504afaef8414f68e1e353aecd2f99928c`). The new first stage,
`scripts/ci/input-manifest.sh`, refused nothing: the clone had no modified or untracked files, and no ignored files
under executable-input paths except caches. The executable-input digest is
`sha256:a98b5b6b1782de27f64158a6032c4effda3af2c986bfa6acfdac5473f9a7b216`. It covers `git ls-tree -r` of backend, db,
scripts, .github, deployments, tests, pyproject.toml, uv.lock, Dockerfile and .dockerignore.

Pinned inputs:
* `uv.lock`;
* the three container images, by digest;
* the three actions, by commit.

Not pinned by the tree, recorded only:
* Python 3.13.16;
* uv 0.11.32;
* PostgreSQL 16.15 from Ubuntu packages;
* Docker 29.9.1;
* the uv wheel installed by pip in the image build (version pinned, hash not pinned).

Mutable development data (`.var/`, clusters, evidence, object stores) is excluded. The clone was still clean after
the run.

Problems found while building (fixed before the recorded run):
* As-of reproducibility bug in my report query: revised SLA timers were excluded regardless of when they were revised,
  so a snapshot regenerated later for the same `as_of` differed. Found by
  `rpt::test_snapshot_as_of_is_reproducible_after_later_changes`; fixed (exclude only timers revised by `as_of`).
* Witness pruning matched the worker by suffix, so `w1` could prune `a-w1`'s records. The mark was never at risk,
  because only records below newer ones were deleted, but the "own records only" rule was broken. Fixed to an exact
  match.
* The ownership sweep only routed never-routed cases, so cases swept before a policy or context existed stayed
  unresolved forever. It now re-routes unresolved cases when a newer policy or business context exists, and never
  writes identical rows otherwise.
* Test-side mistakes, all fixed:
  * wrong module path;
  * a `public` classification that does not exist;
  * the wrong exception type;
  * an invalid reopen reason;
  * the remediation owner lacking `asset.manage` (the analyst records the redeploy instead);
  * response keys (`states`, not `items`);
  * one assertion with an `or` that could not fail, now tightened.

Mutation checks (`docs/verification/2026-10-22-checkpoint3/mutation-checks.log`) caught 5 of 5:
* the reproducibility fix reverted;
* pruning deleting all own records;
* suffix matching restored;
* a revised timer restarting from now;
* accepted risk ending the timer as `met`.

A dirty-tree run of `scripts/verify/foundation.sh` before the last changes was 321 passed, 1 skipped. It is superseded
by the clean-clone run below.

CI pipeline on the clean clone, **CI PASS** (local execution; hosted CI never run). Stages:
* input manifest;
* dependencies;
* byte-compile;
* secret scan;
* no `.env` files;
* action pins (3 ok);
* foundation on a fresh separate cluster with fresh SeaweedFS:
  * migrations `applied: 0001 ... 0012`, then `applied: none` on the re-run;
  * a second database `applied: 0001 ... 0012`;
  * an edited migration rejected;
  * RLS audit: 57 tables forced, 3 global tables without, 0 not owned by `axiom_owner`;
  * **322 passed, 1 skipped (opt-in drill), 1 warning in 151.46s**, with all 7 S3 witness tests run (none skipped);
* physical snapshot drill: 1 passed;
* Compose smoke with a rebuilt image (`sha256:b696e8aa3bb0...`): `SMOKE PASS (axiom-smoke-090112)`.

Logs, the input manifest and the journey step log are in `docs/verification/2026-10-22-checkpoint3/`.

The journey step log (`journey-steps.json`, 18 steps) was produced by running the same journey test from the commit
on the development cluster. Its labels are real, fixture, fake, manual and test-read.

Not covered:
* any live scanner, tracker or identity provider;
* the witness on a production object store;
* hosted CI;
* report performance at volume;
* business-hours SLA calendars;
* any UI.

### Run 16: Phase C evidence-backed investigation, evaluation harness, review fixes (2026-10-22 ~09:10Z to 10:10Z)

> Correction (2026-10-23): this run's CI result depended on the workspace environment; see the correction at the top of this file.

**Tested object: the exact committed tree.** The first CI attempt ran on a clean clone of `c96cf14` and **failed** on
the secret scan, which correctly flagged a literal private-key header in a redaction unit test (fake value). Every
other stage passed in that attempt: 401 passed, 2 skipped. The log is
`docs/verification/2026-10-22-phase-c/ci-run1-failed-secret-scan.out`. Commit `dae1051` builds that string at
runtime instead; the scanner was not weakened.

**CI PASS** on a fresh clone of commit `dae1051776cd4e4cc56821ce531bfc037f12a970`:
* tree `5e20261da14b68bd3a90393af14d2dc30257920e`;
* executable-input digest `sha256:e623e98438cf3c6dbc7b2c949a3302422d7c8839574e15039a9b1fcd7352228b`, now including
  `evaluation/`;
* clean after the run.

Stages:
* input manifest;
* dependencies;
* byte-compile;
* secret scan;
* no `.env` files;
* **requirements register**: 262 rows, every status recognised (new stage);
* action pins: 3 ok;
* foundation on a fresh separate cluster with SeaweedFS:
  * migrations `0001 ... 0013`, then `applied: none` on the re-run, and the same on a second database;
  * an edited migration rejected;
  * RLS audit: 65 tables forced, 3 global tables without, 0 not owned by `axiom_owner`;
  * **401 passed, 2 skipped, 1 warning in 213.16s**. The skips are the opt-in physical drill (run separately below)
    and the opt-in real-provider test (**never run**);
* evaluation report generated from this run's harness results;
* physical snapshot drill: 1 passed;
* Compose smoke with a rebuilt image (`sha256:5a605cc188b6...`): `SMOKE PASS (axiom-smoke-...)`.

Logs, input manifest, evaluation report and results are in `docs/verification/2026-10-22-phase-c/`.

Register reconciliation: `scripts/dev/register-counts.py` reads the Status column of every row. It counts
262 = 146 verified + 67 implementing + 2 implemented_unverified + 46 planned + 1 blocked (6 of the verified rows are
"verified (fake)"). The checkpoint-3 chat summary of 259 omitted the 2 implemented_unverified and 1 blocked rows. The
script found one row (X05) with its status in the wrong column; that row is fixed.

Problems found while building (fixed before the recorded run):
* **Metadata of above-classification evidence reached the model prompt.** Content was withheld, but digests and
  filenames were not. Found by `adv::test_content_above_the_route_classification_never_reaches_the_model`; content
  and metadata are now withheld together.
* **The validator accepted a conclusion against the latest observation** when a claim cited both sides of a recorded
  contradiction. Found by the evaluation harness (held-out H2, `stale_support` behaviour); there is now a
  `latest_observation_disagrees` downgrade.
* The migration needed `SET LOCAL ROLE axiom_authn` to add a function to `axiom_auth`.
* A plpgsql trigger must not reference record fields absent on other tables (separate branches).
* Test-side mistakes, all fixed:
  * a fabricated-citation expectation that ignored the honest severity claim;
  * a `public` classification that does not exist;
  * several assertions that could not fail (`... if False else ...`), removed before the first run.

Mutation checks (`docs/verification/2026-10-22-phase-c/mutation-checks.log`) caught 14 of 14:
* fabricated-reference check removed;
* relevance check removed;
* latest-observation rule removed;
* contradiction rule removed;
* metadata withholding removed;
* revocation check removed;
* route-status check removed (fallback);
* claim-review requirement removed;
* human-only database trigger disabled;
* tool grant check removed;
* redaction removed;
* SLA authorised-reason filter removed;
* package metadata gate removed;
* malformed-retry bound raised.

Some of these were caught by a resulting error rather than an assertion; each mutated run failed.

Evaluation (deterministic fake, 16 scenarios: 6 dev, 10 held-out):
* the fake agreed with the provisional reference on presence in 16 of 16 scenarios;
* 0 unsupported definite conclusions were accepted;
* the deterministic policy missed 1 of 3 reference-urgent cases (H7: a deliberate disagreement between the reference
  and the provisional matrix);
* across 50 adversarial runs, 0 wrong definite conclusions were accepted (20 claims rejected, 7 downgraded).

**These figures do not measure any language model.** The fake's rules and the reference labels were both written by
the author, so agreement is expected, and the labels are not human-reviewed.

Not covered:
* any real model call;
* human-reviewed references;
* any UI;
* enterprise SSO;
* live scanners and trackers;
* the witness on a production store;
* hosted CI;
* load.

### Run 17: analyst UI, enterprise sign-in, override expiry and preview, claim-check precision (2026-10-22 ~10:30Z to 12:07Z)

> Correction (2026-10-23): this run's CI result depended on the workspace environment; see the correction at the top of this file.

**Tested object: the exact committed tree.** The first CI attempt on a clean clone of `3d093ea` **failed** the secret scan: the checkpoint-4 foundation log, committed after that checkpoint's CI run and
never scanned, contained synthetic secrets that pytest had echoed into test IDs. Commit `3e95d46` gives the test
explicit IDs and replaces the four affected ID lines in the archived log with markers (original digest in
`docs/verification/2026-10-22-phase-c/REDACTION-NOTE.md`). The scanner was not weakened. Log:
`docs/verification/2026-10-22-checkpoint5/ci-run1-failed-secret-scan.out`.

**CI PASS** on a fresh clone of commit `3e95d461c7cc4f59686d4b07f33835b723c29b79`:
* tree `4c2384cbc20e45faa3bf0c665b0b428b7e970551`;
* executable-input digest `sha256:47ebe5d6905c4d1fffae4398eff1db3ecc9a68fe50ac0ed4a6985434bb83dffd`;
* stages: input manifest, dependencies, byte-compile, secret scan, no `.env` files, requirements register, action
  pins (3), **analyst UI build (new: `npm ci`, type check, production build)**, foundation, evaluation report,
  **evaluation review package (new)**, physical restore drill, Compose smoke.
* foundation on a fresh separate cluster with SeaweedFS:
  * migrations `0001 ... 0015`, `applied: none` on re-run, the same on a second database; an edited migration rejected;
  * RLS audit: 68 tables forced, 3 global tables without, 0 not owned by `axiom_owner`;
  * **453 passed, 2 skipped in 306.46s**. Skips: the opt-in physical drill (run as its own stage) and the opt-in
    real-provider test (**never run**; real-provider execution is not authorised). `AXIOM_REQUIRE_UI=1` was set, so the
    six browser tests and the eight Keycloak sign-in tests could not skip; all ran and passed.
* restore drill: 1 passed;
* Compose smoke with a rebuilt image (`sha256:10f8358fdfcd...`): `SMOKE PASS`. The Compose image does not yet contain
  the UI build.

Logs, manifest, evaluation report and results: `docs/verification/2026-10-22-checkpoint5/`.

Register: 262 = 147 verified (**18 of them only against fakes or fixtures**) + 69 implementing + 2
implemented_unverified + 43 planned + 1 blocked. The stricter counter found two rows (B08, A02) verified only against
fakes without the qualifier; both now carry it.

Problems found while building (fixed before the recorded run):
* **Deployment provenance was wrong.** The case-context endpoint marked every scanner-imported deployment "manually
  recorded", because ingestion never sets `source_evidence_id`. Found by the first browser test; provenance now comes
  from scanner observations of the deployment.
* **Analysts with project-level roles could not list model routes** (the check required a tenant-root permission).
  Found by the browser test; any investigation reader in the tenant can now list routes.
* **The outbox relay test was flaky** because earlier tests leave more than the claim limit of undelivered messages
  in the shared session database. The test now drains the backlog first; the relay is unchanged.
* Logout of an already-expired session returned 401 and left cookies; it now clears them (a CSRF failure on a valid
  session is still refused).
* Browser-test mistakes: a tenant picker read before the session loaded; users holding memberships in earlier tests'
  tenants; Keycloak's logout confirmation page.

Mutation checks (`mutation-checks.log`). **First round: 6 of 9 caught.** Three gaps, all fixed:
* the principal-kind mutation targeted a setting that does not exist (the database context carries only tenant and
  principal, so there is nothing client-supplied to trust); replaced with "the trigger treats every actor as human";
* `test_expired_override_does_not_restore_a_stale_priority` contained `(expected != before or True)`, which cannot
  fail, and its scenario could not distinguish restoring from reassessing; rewritten so it can;
* the callback-replay test passed for the wrong reason (the cleared binding cookie and the IdP's code-reuse rule
  refused the replay before the platform's single-use check mattered); it now replays with the copied binding cookie
  and asserts the platform's own refusal.

**Second round: 9 of 9 caught**: authority trigger opened; principal kind not read from identity records; policy
apply ignoring an active override; expiry restoring the earlier priority; CSRF check skipped; login state reusable;
nonce not checked; undetermined contradiction allowed to decide; development tokens accepted in production.

Evaluation (deterministic fake, eval-cases@3, labels author-generated and unreviewed): presence agreement 16 of 16;
0 unsupported definite conclusions accepted; policy missed 1 of 3 reference-urgent cases (H7, the deliberate
disagreement). Security-boundary arm, reported separately: 50 adversarial runs, 0 wrong definite conclusions accepted
(20 rejected, 7 downgraded). **None of this measures a language model.**

Not covered: Microsoft Entra ID or any hosted IdP; any real model call; human review of the evaluation labels;
browsers other than Chromium; browser tests of the approval, verification and report screens; accessibility; live
scanners and trackers; hosted CI; load.

### Run 18: checkpoint 6, finishing and verifying the existing workflow (2026-10-22 ~13:20Z to 14:40Z)

> Correction (2026-10-23): this run's CI result depended on the workspace environment; see the correction at the top of this file.


**1. Starting point (checkpoint 5), checked rather than assumed.** `docs/verification/2026-10-22-checkpoint6/starting-point-check.md`:
* the delivered checkpoint-5 files match `SHA256SUMS`; the bundle clones and `checkpoint-5` points at
  `622f216b155b48fb70581af564dc44d011a46735`; the source archive is identical to the tag's tree;
* clean-clone CI passed on `3e95d461c7cc4f59686d4b07f33835b723c29b79`; the 12 files changed afterwards are all under
  `docs/` (documentation-only: confirmed);
* **discrepancy 1:** the checkpoint-5 chat report listed two checksums against the wrong files (it gave the
  screenshots' digest for the source archive and the reverse). The files and `SHA256SUMS` were correct;
* **discrepancy 2 (workspace only):** the checkpoint-5 mutation harness left a stale, mutated bytecode file
  (`claims.cpython-313.pyc` from mutation M8, same source length and whole-second timestamp after restore), which made
  one test fail locally on unchanged code. The checkpoint-5 CI ran on a fresh clone and the 444-test local run predates
  the mutation runs, so the recorded checkpoint-5 results stand; the harness was unsafe and has been replaced.

**2. Tested object: the exact committed tree.** CI PASS on a fresh clone of commit
`9c7303ca47c89e24d94dad4b4c8447b0a3c7ffbf`:
* tree `95e0a9b5281639c0a26c96a1e348c896c1dbf26c`; executable-input digest
  `sha256:f2a94c56bceff434f6d80aaf21b5191872338d63b90e4eba14535cb64fb06357` (now including `frontend/`);
* every stage passed: input manifest, dependencies, byte-compile, secret scan, no `.env` files, requirements
  register, action pins (3), analyst UI build, foundation, evaluation report, evaluation review package, physical
  restore drill, Compose smoke;
* foundation on a fresh separate cluster with SeaweedFS: migrations `0001 ... 0016`, `applied: none` on re-run;
  RLS audit 68 forced, 3 global tables without, 0 not owned by `axiom_owner`; **489 passed, 2 skipped in 381.62s**.
  Skips: the physical drill (run as its own stage: 1 passed) and the opt-in real-provider test (**never run**;
  real-provider execution is not authorised). With `AXIOM_REQUIRE_UI=1` no browser or Keycloak test could skip: 6 + 5
  browser tests, 9 sign-in tests and 16 authority-boundary tests all ran and passed;
* Compose smoke with a rebuilt image (`sha256:bdb958aeec5f...`, UI built inside it): `SMOKE PASS`, including the new
  steps (UI served with CSP; alice signs in on the Keycloak page and moves a case to investigating; the server records
  it as alice's decision; audrey is refused `permission_denied`; the old session cookie is refused after sign-out;
  `AXIOM_ENV=production` with the development identity and a start without the client secret both refuse to start).

**3. After CI.** A local rerun of the browser tests then failed once, deterministically on that machine state:
`test_complete_verification_and_closure_in_the_ui` read the case header immediately after the success message, while
the header was still refetching (a race in the test, not a product defect). Commit `30044e9` changes that test file
only, to wait for the refreshed value. Scope of the rerun: both browser test files, three times (11 passed, 5 passed,
5 passed). The full suite and CI were not rerun for this test-only change.

**4. Problems found while building, all fixed before the recorded CI run**
* Authority boundary (ADR 0012 amendment 2): the 0014 database guard trusted the authority JSON; workload reopen for
  any reason; system reopen without a permission check in the service; nothing stopped binding a human role to a
  workload principal; the audit trail took the actor kind from the in-process context.
* UI defects found by the new browser tests: the verification screen tested for a workflow name (`verifying`) the
  server never returns, so the verification form never appeared; approvers were shown an empty payload (wrong field);
  success messages vanished when the case reloaded; one status message rendered twice.
* Compose: the API container cannot reach the public issuer URL; fixed with an internal discovery URL whose issuer
  must still match.

**5. Mutation checks** (`mutation-checks.log`, harness `mutation-harness.py`: no bytecode written, caches purged,
restored files compared byte-for-byte, all targeted tests rerun after restore). **First round: 8 of 9 caught.**
N6 (token-endpoint error status ignored) **survived**: every error response in the test also lacked an ID token or
JSON, so the login was refused for another reason. A test case with an HTTP 400 that carries an ID token was added;
**second round: N6 caught.** Caught: database trusting any workload permission; workload reopen for any reason;
role-binding kind guard disabled; audit kind from the context; PKCE verifier not sent (caught by the unit test and by
the Keycloak sign-in test); token errors accepted (round 2); client secret not resolved at start-up; production UI
without sign-in; risk history shown without audit.read. Sanity run after restore: 31 passed.

**6. Register**: 262 = 148 verified (**18 only against fakes or fixtures**) + 68 implementing + 2
implemented_unverified + 43 planned + 1 blocked. Integration catalogue: 7 fixture-tested, 13 planned, none
sandbox-validated or production-supported.

**7. Evaluation** (eval-cases@4; deterministic fake; labels author-generated and unreviewed; **no held-out set**:
H1 to H10 are now the regression split, evaluation/EXPOSURE.md). Presence agreement 16 of 16; 0 unsupported definite
conclusions accepted; the policy missed 1 of 3 reference-urgent cases (H7). Security-boundary arm, separate: 50
misbehaving-fake runs, 0 wrong definite conclusions accepted (20 rejected, 7 downgraded). **None of this measures a
language model or reasoning quality.** Independent review: **pending**.

**Verified, fixture-only, untested**
* Verified here: the authority boundary and the negative cases above; the risk-acceptance, approval, verification and
  report screens against the real API; sign-in against the local Keycloak, including in a fresh Compose install;
  start-up refusals.
* Fixture-only: ticket creation (local Jira-style fake); tracker states; Tenable and Azure Resource Graph sources.
* Untested: Microsoft Entra ID or any hosted IdP; a production secret resolver (none exists); any language model;
  browsers other than Chromium; accessibility; the change-report form in a browser; hosted CI; load.
* A passing test here demonstrates the behaviour it exercises on these inputs; it is not a general security guarantee.

### Run 19: checkpoint 7, assurance of the authority and sign-in changes; verification worker (2026-10-22 ~15:48Z to 16:55Z)

> Correction (2026-10-23): this run's CI result depended on the workspace environment; see the correction at the top of this file.


**1. Baseline (before any change)** — `docs/verification/2026-10-22-checkpoint7/baseline.md`, `baseline-ci.log`:
* the checkpoint-6 tag points at `1eed24c28e3240eaf92a5efa29ca443f06fad02a`; the six delivered checkpoint-6 files
  match `SHA256SUMS`; the checkpoint-5 files are unchanged;
* the post-CI commit `30044e9` changed only `test_analyst_ui_workflows.py`. Its effect was synchronisation, but it
  also replaced four exact-equality header assertions with `has_text` waits. Those are case-insensitive substring
  matches, so the assertions became slightly weaker. No false pass is possible with today's workflow values. The
  assertions are now tightened to anchored regular expressions (commit `d3a8694`);
* **clean-clone CI PASS on `1eed24c`** (tree `d9b683b3…`, executable inputs `sha256:6ff56a8b…`): foundation 489
  passed, 2 skipped; restore drill passed; Compose smoke passed. This is the first CI result that covers `30044e9`.

**2. Tested object: the final code and tests.** CI PASS on a fresh clone of commit
`b6170c68aa88d596f7348476a9bc643df38aca6f` (`docs/verification/2026-10-22-checkpoint7/ci-b6170c6.log`):
* tree `b9291b77c25974a100355c42a27e607bc0c55dae`; executable-input digest
  `sha256:42d037b96fad4285c22b1013ff096f7a64a496d812fb979b75cac1d3c54ee8cc`;
* every stage passed: input manifest, dependencies, byte-compile, secret scan, no `.env` files, register, action
  pins, UI build, foundation, evaluation report, evaluation review package, restore drill, Compose smoke;
* foundation: migrations `0001 … 0018`, then `applied: none` on re-run, and an edited migration is rejected. RLS
  audit: 69 tables forced, 3 global tables without RLS, 0 not owned by `axiom_owner`. Result: **583 passed, 2 skipped**
  in 441 s. The 2 skips are the physical drill, which runs as its own stage (1 passed), and the opt-in real-provider
  test (**never run**). Tests that ran include: 3 checkpoint-7 browser tests, 14 analyst-UI browser tests, 13
  local-Keycloak sign-in tests, 9 authority-review tests and 31 worker tests;
* Compose smoke used a rebuilt image (`sha256:cfd9ceaa42dd…`): `SMOKE PASS`;
* the only commit after `b6170c6` (this record, the CI log and the tag) changes files under `docs/` only.

**3. Reproducers on checkpoint-6 code** (`reproducers-on-cp6.txt`): with the checkpoint-7 fixes stashed, D1
(decisions and approvals), D2 and D3 (role and membership) reproduced the unauthorised result. H1's stale binding
was live and no remedy existed. H2's kind update succeeded for the owner. The `azp` gap was reproduced by the new
unit case before its fix.

**4. Mutation checks** (`mutation-checks.log`, `mutation-harness.py`, the checkpoint-6 safe harness). **21 of 21
caught**:
* authority: A1 to A5;
* sign-in and secrets: U1 to U6, including live key rotation at the local Keycloak;
* worker: W1 to W10.

The log names each failing test. Each failure was in the test written for that control, but the assertion messages
were not captured, so "the intended reason" was checked by test identity only. W4 needs a qualification. W4 removed
the first idempotency layer (the check for an existing observation for the job). The crash test failed on the job's
result status (`skipped` instead of `already_recorded`). No second verification was recorded, because the next layer
(nothing to do once the report is verified) stopped it. Sanity run after the files were restored: 78 passed.

**5. Not caught by any mutation here:** the UI label for worker results. It was not mutated because the harness does
not rebuild the frontend. The browser test asserts the labels.

**6. Register:** 262 rows = 149 verified (**19 only against fakes or fixtures**) + 68 implementing + 2
implemented_unverified + 42 planned + 1 blocked. Integration catalogue: 8 fixture-tested (the verification check
endpoint added), 13 planned.

**7. Evaluation:** unchanged (eval-cases@4; labels and splits not touched; no model called; review pending).

**Independently reproduced / fixture-only / untested**
* Reproduced against real local services (PostgreSQL with the production role layout, local Keycloak 26.4.2,
  Chromium, Compose):
  * the authority fixes and the revocation boundary at commit time;
  * the sign-in protections;
  * session rotation;
  * log redaction wiring;
  * production start-up refusals and the mounted-file secret path (a test directory, not a container mount);
  * the browser checks.
* Fixture-only: the verification worker's check endpoint (a local TLS server in the test process with a throwaway CA);
  tracker integrations.
* Untested deployment assumptions:
  * TLS termination at a reverse proxy;
  * sign-in over HTTPS;
  * Docker, Kubernetes or systemd secret mounts;
  * any hosted IdP (Microsoft Entra ID);
  * any real check service;
  * other browsers, screen readers and a WCAG review;
  * hosted CI.
* A passing test shows the behaviour it exercises on these inputs. It is not a general security guarantee.

### Run 20: checkpoint 8, trust boundaries (2026-10-22 ~18:50Z to 19:40Z)

> Correction (2026-10-23): this run's CI result depended on the workspace environment; see the correction at the top of this file.


**1. Baseline** (`docs/verification/2026-10-22-checkpoint8/baseline.md`): checkpoint-7 tag, manifest, checksums and
artifact contents verified in the private history and in the published Axiom history; the commits after each CI
commit change records only (plus a comment-only commit whose Python syntax trees are unchanged, and README text).

**2. Tested object.** CI PASS on a fresh clone of `7efc15c4788df960c477c04a8a4ddd89b4ad9723` (tree `06142307…`,
executable inputs `sha256:215dc363…`, `ci-7efc15c.log`): every stage passed; migrations `0001 … 0019`, re-run
`applied: none`; RLS audit 69 forced, 0 not owned by the owner role; **655 passed, 2 skipped** (the physical drill,
run as its own stage: 1 passed; the opt-in real-provider test, never run). New in this run and all executed: local
TLS deployment 9, database identity boundary 12, revocation boundary 5, worker destinations 14, worker lifecycle 9.
Compose smoke with a rebuilt image: `SMOKE PASS`. After this commit only this record, the CI log and the mutation
logs were added.

**3. Mutation checks** (`mutation-checks-round1..3.log`, `mutation-harness.py`; caches purged, restored files
compared byte for byte, targeted tests rerun after restore). 18 mutations. Round 1 exposed three tests that did not
isolate their property and one invalid mutation; each was fixed and rerun:
* W9 (one observation per job) **survived**: the duplicate row also violated the run-ID uniqueness. The test now
  changes the run ID; caught ("DID NOT RAISE UniqueViolation").
* W7 (redirects followed) was caught for the wrong reason (TLS failure at an untrusted redirect target). The redirect
  now points at a reachable, trusted URL; caught by the path assertion (`['/v1/checks', '/redirected']`).
* I4 (decisions append-only trigger) was first an invalid mutation (migration error). Corrected, it **survived**
  against the runtime-credential test because the runtime role has no UPDATE or DELETE privilege on decisions: the
  grant masks the trigger. The owner test did not cover decisions; it now does (UPDATE and DELETE) and catches it.
* W3 (connection not pinned) is caught because the unpinned client cannot resolve the test name at all; the test
  cannot show a different reachable address without controlling system DNS. Recorded as caught, with that limit.
Final: 18 of 18 caught, each by the test written for that control. Sanity after restore: all targeted tests pass.

**4. Register:** unchanged counts (262 rows; 149 verified, 19 of them fixture or fake only). No fixture-only result
was promoted.

**5. Evaluation:** unchanged; no model called; review pending.

### Run 21: after checkpoint 8, closing review and demonstration (2026-10-22 ~20:00Z to 21:00Z)

> Correction (2026-10-23): this run's CI result depended on the workspace environment; see the correction at the top of this file.


Records: `docs/verification/2026-10-22-after-checkpoint8/`. Tested commit for every result below:
`185af5b98fcb3eac46b52c736ffd2ecd58702877` (tree `90c22e34…`, executable inputs `sha256:43307896…`). After it, only
this record and the files in that directory were added.

**1. Destination pinning without system DNS** (`141d04a`, `mutation-checks-round4.log`). Two TLS servers on
127.0.0.1 and 127.0.0.2, same port, same certificate for `localhost`; a controlled resolver maps the name to the
allowed address. The validated server receives the request; the other receives none; the observation records
127.0.0.2. Removing the pinning is caught by "contacted an address the policy never checked"; removing the TLS
server name is caught because the validated server receives nothing (the handshake is checked against the address).
The checkpoint-8 limit for W3 (caught only because the unpinned name did not resolve) no longer applies.

**2. Principal disablement, suspension and expiry** (`ee98742`, `principal-status-reproduction.md`, ADR 0012
amendment 5). Reproduced violation of data design section 12 step 2: a disabled verification identity kept
recording results, and an approval by a since-disabled approver still executed. Fixed in the application check and
in `axiom.holds_permission` (migration 0020), without new locks. Suspension and expiry already applied at the next
request. None of the three waits for a command that has passed its check; a job in flight at suspension stays
leased (observed) and is not cancelled (TEN-16, still implementing).

**3. Defect found by the demonstration** (`3327c9d`): the API rejected the `verification_check` adapter the
installation guide tells operators to use. Fixed with a regression test that fails without the fix.

**4. Demonstration** (`demo/results.json`, run with `scripts/demo/run.sh` at the tested commit). Real Trivy 0.76.1
scans of two local services built with Jinja2 3.1.2; both imported (complete coverage) and bound to the digests Docker
reported for the running containers. Orders case `CVE-2024-22195`: investigation with the deterministic fake model,
approval in Chromium by a second person, ticket in the tracker fake, rebuild with Jinja2 3.1.6 and redeploy, worker
verification `passed` (rule `condition_absent`) on the redeployed digest, closed in Chromium. Controls on the unchanged
service: A (change reported against the running vulnerable deployment) `failed`, rule `condition_present`; B (fixed
image pushed, not deployed) `inconclusive`, rule `different_deployment`. Screenshots are delivered outside the
repository. Trivy database updated 2026-10-22T19:14Z.

**5. Tests.** Local full suite at the tested commit: 655 passed, 12 skipped (S3 opt-ins without an endpoint, the
physical drill, the real-provider test, the demonstration). Clean-clone CI (`ci-185af5b.log`): every stage passed;
**664 passed, 3 skipped** (physical drill, run as its own stage: 1 passed; real-provider test, never run;
demonstration, run separately as above); restore drill; Compose smoke `SMOKE PASS`.

**6. Register:** counts unchanged (149 verified, 19 of them fixture or fake only). TEN-16 stays implementing; INT-21
stays fixture-tested.

### Run 22: publication preparation (2026-10-22 ~23:05Z to 23:17Z)

> Correction (2026-10-23): this run's CI result depended on the workspace environment; see the correction at the top of this file.


Records: `docs/verification/2026-10-23-publication/`. Tested commit: `b2d2ae15c7b6abf7f9057dfc44a5fd2dd3a8eca5`
(tree `2a336e26…`, executable inputs `sha256:e713895c…`). After it, only this record and that directory were added.

**1. Changes since run 21's tested commit `185af5b`.** Records (run 21), two tests for the recovery of a job left
running by tenant suspension (`41ac0a2`), and documentation (`b2d2ae1`: CA path moved into the run 2 environment
note, explicit trust limits in the README and deployment document, the suspension recovery procedure, demonstration
prerequisites and recorded scanner metadata). No application code, migration, deployment configuration or demo code
changed.

**2. Clean-clone CI** (`ci-b2d2ae1.log`): every stage passed; **666 passed, 3 skipped** (physical drill, run as its
own stage: 1 passed; real-provider test, never run; demonstration, run separately); restore drill; Compose smoke
`SMOKE PASS`. The two new recovery tests are among the 666.

**3. Demonstration rerun** at the tested commit (`demo/results.json`): same Trivy 0.76.1 image and the same database
(`UpdatedAt` 2026-10-22T19:14:47Z, downloaded 20:15:30Z, not refreshed); orders case passed (`condition_absent`) and
closed; control A `failed` (`condition_present`); control B `inconclusive` (`different_deployment`).

**4. Delivered screenshots from run 21** (`screenshot-provenance.md`): the file store that holds deliveries inserted a
C2PA Content Credentials chunk into each loose PNG after delivery. Pixels unchanged; removing the chunk restores the
original bytes. The original checksum list of that delivery was restored after having been overwritten. Later
packages carry images inside archives only.

**5. Register:** counts unchanged.

### Run 23: environment-independent CI and the first hosted CI failures (2026-10-23 ~00:50Z to 01:45Z)

Records: `docs/verification/2026-10-23-ci-environment/`. Tested commit: `832bf5df1ac391a2da8b76f44c320d3380e8b17a`
(tree `4e21e590…`, executable inputs `sha256:2e83771e…`), branch `fix/ci-environment-independence`.

**1. Hosted CI before the fix** (`github-actions-failures-before-fix.txt`). GitHub Actions ran for the first time on
the pushes of `bc2a6aa` and `8c0b483`; both failed the foundation stage, every other stage passed. `bc2a6aa`: 1 failed
(the idempotency test). `8c0b483`: 2 failed (the idempotency test and the TLS browser test). Both reproduced locally
under `TZ=UTC` and without `NODE_OPTIONS` respectively. See the correction at the top of this file.

**2. Application defect fixed** (`b3daefb`). The idempotency request digest hashed timestamps as written, so the same
expiry with a different offset was a "different request". The contract (data design section 9: "same key with
different payload is a conflict") is about the payload's meaning. Timestamps are now digested as UTC instants. The API
test states both cases: the same instant with a +03:00 offset replays the stored response (`Idempotent-Replayed:
true`, identical body), and a different expiry with the same key is rejected with `idempotency_key_reused` and creates
nothing. Without the fix it fails in both time zones (no longer depending on the database's rendering). Unit tests
cover the digest. Retries of keys stored before the change with a non-UTC offset no longer match and are rejected.

**3. Test defect fixed** (`832bf5d`). The TLS browser test's two CSRF requests used Playwright's Node-based
`page.request`, whose trust came from inherited settings. They now use the test's httpx client, built with exactly the
local CA and host-name checking on, carrying the browser's cookies. A new test shows that client rejects a wrong host
name and an unrelated CA. The browser itself still trusts the server through the pinned key, as before.

**4. Affected tests** under `TZ=UTC` and `TZ=Europe/Bucharest` (with matching `PGTZ`), with `NODE_OPTIONS`,
`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE` and the other CA variables removed: idempotency tests 10 passed in each; TLS
deployment tests 10 passed in each.

**5. Clean-environment CI** on fresh clones with `env -i` and only the variables in `declared-environment.env`
(PATH, HOME, LANG, TZ, the Playwright browser location, `BUILD_CA` for image builds behind this workspace's proxy,
`UV_SYSTEM_CERTS=1` so uv trusts the system store, which includes that proxy's CA):
* attempt 1 failed at dependency installation (uv did not trust the proxy CA; `UV_SYSTEM_CERTS` added);
* attempt 2 lost the Docker daemon midway (the workspace stops it after two hours), failing every Docker-backed test;
* **UTC: CI PASS**, 670 passed, 3 skipped (physical drill, run as its own stage: 1 passed; real-provider test, never
  run; demonstration, opt-in), restore drill, Compose smoke `SMOKE PASS` (`ci-832bf5d-utc.log`);
* **Europe/Bucharest: CI PASS**, same counts and stages (`ci-832bf5d-europe-bucharest.log`).

**6. Application defect found, not fixed.** The API accepts timestamps without an offset (for example
`"2026-10-27T20:00:00"`). They are stored as the database session's local time, which is the server's configured
time zone: in Europe/Bucharest that is 18:00 UTC, in UTC 20:00 UTC. Rejecting such values, or fixing the session
time zone, changes the API contract and is left for a decision (HANDOFF, next tasks).

The GitHub Actions result for the pull request is recorded in the pull request, not here, because this record is part
of what it tests.


### Run 24: API timestamps must name an instant (2026-10-23 ~10:40Z to 11:10Z)

Records: `docs/verification/2026-10-23-timestamps/`. Tested commit: `7b9d50bc7dc5c55ce228cf71985ced710642344c`
(tree `977b2cd5…`, executable inputs `sha256:57943f8c…`), branch `fix/ci-environment-independence`. After it, only this
record and that directory were added.

**1. Contract correction** (`2fccebc`, ADR 0015, requirement API-10). Request fields that name an instant now require
RFC 3339 with `Z` or a numeric offset; offset-free values, bare dates and numbers are refused with `422` before any
handler runs, and accepted values are converted to UTC. The asset-version and role-assignment services refuse naive
values from internal callers; a list cursor without an offset is refused. No field in the API is date-only or
local-calendar. Import parsers already recorded offset-free source times as unknown (now covered by unit tests).

**2. UI** (`a1a7d81`). The default expiry of the risk-acceptance and override inputs was written in UTC and read as
local time; defaults are now local, values are still sent as UTC instants.

**3. Tests.** `test_api_instants.py` (8) and `test_import_instants.py` (10): offset-free values on all 10 affected
endpoints refused with nothing written (17 tables compared before and after), equivalent instants stored identically,
distinct instants kept distinct, services refuse internal callers. Run under `TZ`/`PGTZ` UTC and Europe/Bucharest
without inherited certificate settings: all pass. With the API schema change removed, 6 of the 7 API tests then
written failed in both zones (the storage test passes either way: PostgreSQL already stores instants once they are
explicit); the service-level test was added afterwards and was not run against the old code.

**4. Behaviour before the correction** (probe against the earlier code): an offset-free `observed_at` was stored as
20:00 UTC under UTC and 18:00 UTC under Europe/Bucharest; an offset-free role `valid_until` raised a server error and
stored nothing; the other fields were refused by their services. Asset versions recorded by hand before the correction
may therefore hold an ambiguous `observed_at`, and they cannot be identified from Axiom's records (ADR 0015).

**5. Clean-environment CI** (`env -i`, the declared environment of run 23): **UTC: CI PASS**, 688 passed, 3 skipped,
restore drill, Compose smoke `SMOKE PASS` (`ci-7b9d50b-utc.log`); **Europe/Bucharest: CI PASS**, same counts
(`ci-7b9d50b-europe-bucharest.log`).

**6. Register:** 263 rows, 150 verified (19 only against fakes or fixtures); API-10 added.

**Unresolved:** the Compose smoke image build that failed after two seconds on GitHub Actions (run 39884012334,
commit `5bff45c`) without output. The smoke test now prints build output on failure; it has not recurred.

### Run 25: final review of pull request 1 (2026-10-23)

**Legacy idempotency keys.** A compatibility check (`tests/unit/test_idempotency_legacy_keys.py`, which recomputes the
digest exactly as the code at `8c0b483` did) found that the normalised digest of `b3daefb` wrote UTC as `+00:00`,
while the earlier encoding wrote `...Z`. Run 23's statement "retries of keys stored before the change with a non-UTC
offset no longer match" was therefore incomplete for the commits it tested: keys first sent with `Z` or `+00:00`
would not have matched either. Fixed: the API digests the schema-normalised body as before. Matrix (ADR 0015): keys
first sent with `Z` or `+00:00` replay for every equivalent retry; keys first sent with a nonzero offset or without
one are rejected (`idempotency_key_reused`) whatever the retry's spelling; retries without an offset are refused by
validation.

**Diff review** of `8c0b483..` the final head: code changes are limited to the request schema, the list cursor, the
digest, two service checks, the UI's expiry helpers and the smoke script's build output; the rest is tests,
documentation and verification records. No unintended change found.

The historical-data limitation (ADR 0015) and the CI corrections (runs 13 to 23) stand as recorded.

**GitHub Actions on the review head** (`063347b`, run 39946416834): foundation passed (692 passed, 3 skipped); the
Compose smoke failed in its UI check, which waited 30 s for "Investigation started." after starting an investigation
in the browser. Neither the page state nor the API log was captured, so the cause is not established. The UI check
and the button's code are unchanged since `bc0fddf`, whose run passed; the same smoke test passed in the local
Europe/Bucharest CI of `3f8aaea` and in three further local runs. Unresolved, like the image build failure of run
39884012334; the UI check now prints the page's state and the API and job-worker logs on failure.

### Run 26: demonstration on main for the documentation (2026-10-23 12:41Z to 12:43Z)

`scripts/demo/run.sh` at `a05c01f7cf81b1bfd162c302cbe1177254bd11f6` (main after pull request 1), Trivy 0.76.1 with
the database of 2026-10-22T19:14:47Z. Demonstrated case passed (`condition_absent`) and was closed in the browser;
control A failed (`condition_present`); control B inconclusive (`different_deployment`). Records:
`docs/verification/2026-10-23-demo-main/`. Four of its screenshots are in `docs/demo/`, unedited, with checksums and
a check that they carry no metadata chunks (`docs/demo/PROVENANCE.md`).

GitHub Actions on the first head of the documentation pull request (`8cfe42e`, run 39955949204): every stage passed
except the Compose smoke, where `docker compose up` failed after sixteen seconds with its output discarded. The commit
changed only documentation and screenshots relative to `a05c01f`, whose run passed; the next commit, which added only
these failure records, passed. That is evidence, not a cause: the cause is unknown. Recorded as the third unexplained
smoke-stage failure (docs/IMPLEMENTATION_STATUS.md).

GitHub Actions on `8bc0ac1` (run 39969148347): every stage passed except the Compose smoke's browser check, which
timed out waiting for "Investigation started.". The diagnostics added in run 25 established the mechanism: the API
returned 200 for the command, the captured page showed the case `investigating` and no status element, and the UI
renders that message inside a section that is removed once the reloaded case is no longer `received`. The check races
the reload. Not fixed in this change. Run 39946416834 had the same symptom without diagnostics and is not confirmed to
share the cause.

### Run 27: Compose smoke diagnostics (2026-10-23)

Records: `docs/verification/2026-10-23-smoke-diagnostics/`. On any failure the smoke script now prints the
`docker compose up` output, container states, exit codes, OOM flags, health status and the last health-check results,
and the last lines of each service's log. An ERR trap reports an unexpected failing command with its line and keeps
its exit status. No retry, timeout increase or skipped check was added, and the application is unchanged.

**Correction to the first version of this change.** It stated that collection was bounded at "about two minutes
overall" and recorded "about 140 s" for a hung Docker. Measured again, the 140 s was 120 s of collection plus 21 s of
cleanup; the limit was checked only between steps, so collection itself could reach about 140 s; commands that
ignored SIGTERM were never killed; and cleanup had no limit. Now collection ends within 120 s including SIGKILL of
anything that overruns, and cleanup within 60 s plus 10 s, so a failure adds at most about 190 s. Measured: 114 s and
119 s of collection with a hung Docker (the second ignoring SIGTERM), and cleanup stopped at 70.0 s when Docker stayed
hung, with the exit status still 1 and a message that the project may remain.

**Redaction.** Every path that prints failure output now goes through one filter (`scripts/verify/smoke_redact.py`,
with unit tests): the image build output (not filtered before), the `docker compose up` output, the browser check
output and its `ok` lines, failure messages (some included command output and were not filtered before), the
unexpected-failure line and everything diagnostics collect, including errors from the collection commands
themselves. It replaces the generated secrets, JWT-shaped strings, `Authorization` header values, user information in
URLs and private key blocks. It is a filter for known values and shapes, not a guarantee. The rendered Compose
configuration and container environments are still never printed.

Controlled failures, all on images already present here: build failure with credentials in its output (exit 1,
replaced), held host port (exit 1, bind error shown), browser check printing five kinds of secret (exit 1, all
replaced), unexpected failing command (exit 7 kept, line reported), Docker failing during collection (exit 1), Docker
hanging (exit 1, 114 s), Docker hanging and ignoring SIGTERM (exit 1, 119 s), Docker hung through the cleanup (exit 1,
cleanup stopped at 70 s). A normal run passed. The browser-check race found in run 39969148347 is not addressed here.

GitHub Actions on `main` after merging pull request 2 (`305b0fc`, run 39975479973): every stage passed except the
Compose smoke, whose image build failed because `public.ecr.aws` returned HTTP 429 (Too Many Requests) for the pinned
`python:3.13-slim` manifest. Established from the build output the smoke test has printed since run 23. Not retried,
and no change made to work around it.

GitHub Actions on pull request 3: `e88ef06` passed (run 39975650264). `9de264a` (run 39977205040): every stage passed
except the Compose smoke; the image build succeeded and `docker compose up` failed while pulling the pinned
`public.ecr.aws` PostgreSQL image, with `toomanyrequests: Rate exceeded`, shown by the `compose up` output the
diagnostics preserved. `d9a5069` (run 39980128200): the image build failed with HTTP 429 and "toomanyrequests: Data
limit exceeded" from `public.ecr.aws` for the Python base image's manifest. Not retried. Later results are recorded in
the pull request's conversation, not by commits made only to start another run.

### Run 28: the start-investigation confirmation (2026-10-23)

The browser-check failure of run 39969148347 was traced to the application. After a successful start the page reloads
the case; the "Start investigation" section, shown only while the case is `received`, is then removed, and the
confirmation "Investigation started." was rendered inside it. The confirmation was therefore gone every time the
reload finished: unstable feedback for a user, and a race for the check that waited for it.

* **Shown before the fix:** a new browser test
  (`tests/integration/test_analyst_ui.py::test_start_investigation_records_the_decision_and_its_confirmation_stays`)
  waits until the page shows the reloaded case as `investigating`, then asserts that the confirmation is visible, that
  the decision is recorded for alice with the case `investigating`, and that a fresh page load still shows
  `investigating`. Against the unchanged UI it failed four times out of four, on the confirmation.
* **Fix:** the command's result (confirmation or refusal) is rendered outside the conditional section. The same test
  then passed three times out of three; the three browser test files passed together (15 tests).
* **Smoke browser check:** it now waits for the durable outcome first (the reloaded case shows `investigating`), then
  for the confirmation as a `status` element, then loads the page again and checks the workflow. The smoke script's
  existing server-side check, that the decision was recorded as alice's human principal, is unchanged. No sleep was
  added and no timeout changed.
* **Local clean CI** (declared environment, UTC) at `2389664`: CI PASS, foundation 693 passed and 3 skipped, Compose
  smoke passed with the new check. That run rebuilt the image but used base images already on this machine, so it was
  not a cold install.

Run 39946416834 had the same symptom without diagnostics. It is consistent with this cause but not confirmed by it.

### Run 29: one sequential pull per pinned image in the Compose smoke test (2026-10-24)

Records: `docs/verification/2026-10-24-image-prepull/`. Before the build and before `docker compose up`, the smoke test
now pulls each distinct image it needs once, one at a time, by its pinned digest: the Dockerfile's two base images
(with `BUILD=1`) and the Compose services' images, read from those files. An image already present under its pinned
reference is not pulled again; a failed pull stops the test with exit 1 and the pull's output, filtered like all other
failure output. An image reference without a digest stops the test. Registries, digests, timeouts and checks are
unchanged, there is no retry, and nothing is cached between runs.

Why: in run 39977205040 Compose started two simultaneous pulls of the same PostgreSQL image (`postgres` and `db-init`),
and the registry answered "Rate exceeded". Sequential, de-duplicated pulls remove that duplicate request. They do not
reduce the data downloaded, so they cannot prevent a "Data limit exceeded" refusal like those of runs 39980128200 and
40009459095.

Checked locally: with the registry unreachable, the build used a present pinned base image without contacting the
registry; the pull-failure path stopped the test with exit 1 and the registry error; a normal run with a rebuild
passed. These were cached runs, not cold installs. The Dockerfile syntax image is still resolved by tag from Docker Hub
on every build.

Hosted CI (run 29's change merged with runs 27 and 28 in pull request 5): on the tested head `a35aab3`, run
40054331646 passed every stage (699 passed, 3 skipped). On that fresh runner the smoke test pulled the Python, Node and
PostgreSQL images once each, in sequence; Keycloak and SeaweedFS were already present, pulled earlier in the same run
by the foundation stage, and nothing was cached between runs. Merged as `3d4d997`, whose tree is identical to
`a35aab3`; the push run on `main`, 40055087635, passed every stage (699 passed, 3 skipped). Pull requests 3 and 4 were
closed as superseded. Runs 39884012334, 39946416834 and 39955949204 remain unexplained.

### Run 30: Python and PostgreSQL from `mirror.gcr.io`, Dockerfile frontend pinned (2026-10-24)

Records: `docs/verification/2026-10-24-image-sources/`. `public.ecr.aws` kept refusing the pinned Python and
PostgreSQL images with "Data limit exceeded", including a sequential pull in run 40056023921. Both images now come
from `mirror.gcr.io/library` with unchanged digests, verified byte-identical there before the move, with every
linux/amd64 layer retrieved. The Dockerfile frontend, previously resolved by tag from Docker Hub on every build, is
pinned in both Dockerfiles as `mirror.gcr.io/docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e`,
the digest the tag resolved to on both registries. The smoke test's sequential pull now includes it. Every image CI
pulls is pinned by digest.

Checked locally with registry access cut: with the images present the build and smoke passed, so no pinned reference
needs the registry once pulled; with the frontend removed, the pull step stopped the test with exit 1 and the registry
error. A normal run passed. These were cached runs. No retry, fallback, credential or cross-run cache was added; this
moves away from a source that was refusing pulls and does not guarantee the new one stays available.

### Run 31: an expired lease is lost at every write (2026-10-24)

Records: `docs/verification/2026-10-24-expired-lease/`. All results are from the PostgreSQL test database
(`scripts/dev/test-db.sh`); coordination is on database state (lease timestamps moved with the database clock, the
blocked backend found through `pg_blocking_pids`), not on elapsed time.

* **Final write after expiry.** `test_result_returned_after_the_lease_expired_is_discarded_and_the_job_stays_reclaimable`,
  every outcome with and without a cancellation request: on `main` at `5be8aee`, 10 of 10 failed with "the expired
  worker's outcome was written".
* **Heartbeat revival.** `test_running_heartbeat_does_not_revive_an_expired_lease_for_the_final_write`, with the worker's
  own heartbeat thread: on the first head of this change (`0b86a5c`, final write already fixed) the heartbeat renewed the
  expired lease and the final write then recorded `succeeded`.
* **Expiry while waiting for the row lock.** `test_lease_that_expires_while_waiting_for_the_row_lock_is_not_accepted`:
  with the expiry test inside the locking query, a lease valid when the final write started waiting and expired during
  the wait was accepted when the blocking transaction had only locked the row ("succeeded"); it was rejected when that
  transaction had changed the row, because PostgreSQL evaluated the condition again on the new row version.
* **Fix:** one authorization check for the job-row writes (attempt counter, heartbeat, final write) and for handler
  transactions that call `JobContext.fenced` (`lock_held_lease`: lock by token and state, then test expiry with the
  lock held); the heartbeat reports `heartbeat_lease_lost` and never revives a lease
  (ADR 0006 amendment 1).
* **With the fix:** all 21 lease tests pass, including valid renewal capped at the step deadline, heartbeat after expiry
  without reclaim, heartbeat after a reclaim, and an attempted revival followed by the final write. The 21 test files
  that drive the job runner passed (231 passed, 1 opt-in demonstration skipped).
* **Fix removed:** with the previous authorization semantics put back into the new code (heartbeat without the expiry
  test; expiry inside the locking query), the 20 lease tests that existed at that point were run: 6 failed, each for
  its intended reason: "the heartbeat
  renewed a lease that had already expired" (three), "an outcome was accepted although the lease expired before the row
  lock was acquired", "the heartbeat revived an expired lease", and a heartbeat after expiry that returned True. The
  other 14 passed, as they test cases the previous code already handled. The 21st, the database-boundary test below,
  was added afterwards and was not run with the previous semantics; it writes through the runtime credential directly
  and does not exercise the changed checks.
* **Database boundary:** `test_lease_expiry_is_enforced_by_the_worker_not_by_the_database` shows the runtime credential
  can finish a job whose lease expired, and cannot change it once finished. Lease expiry is application-enforced,
  consistent with the trusted runtime credential (ADR 0006 amendment 1, ADR 0012 amendment 4).

Discarding a job's outcome does not undo writes the handler committed earlier in fenced transactions, or external
effects.

### Run 32: action execution transitions after the effect are lease-fenced (2026-10-24)

Records: `docs/verification/2026-10-24-execution-transitions/`. PostgreSQL test database; workers coordinated through
events inside the effect gate and the adapter's lookup, lease timestamps moved with the database clock, no sleeps.

* **Confirmed on `main` (`8f8a3e6`).** `test_stale_denial_cannot_fail_the_execution_and_return_the_use_while_the_current_worker_creates`:
  worker A's gate denied (approver suspended) and sent nothing; A's lease expired, the membership was restored, worker
  B reclaimed the job and reached its lookup; A marked the execution `failed` and returned the approval use; B created
  the ticket. Observed: 1 ticket, execution `failed`, no external reference, reservation `released`; a second
  execution of the same single-use approval was allowed and created a second ticket.
* **Confirmed on `main`, every post-effect transition.**
  `test_execution_transition_after_the_lease_is_lost_is_discarded_and_the_observation_kept`: with the lease lost right
  after the gate returned, a worker without the lease set the execution `succeeded` (use consumed), `reconciling`
  (verification mismatch, and a parked gate), or `failed` (denial, use returned).
* **Fix:** each of those transitions commits only after `JobContext.fenced` in the same transaction; otherwise the
  observation is recorded as `execution_transition_discarded` and the step stops. Effect-gate observations unchanged.
* **Operator adoption** (`test_operator_reconciles_a_discarded_stale_success_from_the_recorded_evidence`): with only the
  fence, adopting a discarded stale success left the execution `reconciling` with no reference while the job was
  `succeeded` (`fence-without-reconcile-fix.txt`). With the reconcile fix, `adopt` and `not_applied` both end
  `succeeded` with the recorded reference, the use consumed and one create request; a contradicting reference is
  refused.
* **Results:** on `main` all 8 new tests failed for their intended reasons (`on-main.txt`); with the fix all 8 passed;
  the action, action API, workflow adapter and job test files passed (107 passed).
* **Reproduced, not fixed:** a cancellation applied at claim time after the previous worker's lease expired leaves the
  execution `prepared` and the reservation `reserved` with the job `cancelled` (`probe-cancel-after-worker-loss.py.txt`).
  Addressed in run 33.

Accepted assumptions: the runtime credential is trusted (ADR 0012 amendment 4); external effects are at most one first
attempt per operation key, with duplicates stopped only by provider deduplication or fencing (ADR 0010). Nothing here
makes execution exactly-once.

### Run 33: a cancellation is settled from the effect evidence (2026-10-25)

Records: `docs/verification/2026-10-25-cancellation/`. PostgreSQL test database; workers coordinated through events
inside the adapter (paused before the gate authorizes a dispatch, or after it and before the request is sent), inside
the fake provider (request held) and after the gate returns, with lease timestamps moved by the database clock; no
sleeps. Every test asserts the execution, the job, the effect intent and the approval accounting together.

* **Established before changing it** (`probe-abandon-and-cancel.py.txt`, output `probe-on-prior-pr-head.txt`, on the
  previous head of this change, `5e17eff`): abandoning a job the restore witness parked before any intent existed
  ended `failed` with the use `released` and a second execution of the single-use approval allowed; abandoning a
  carried job with a `prepared` intent consumed the use; cancelling a job queued after an unknown outcome (a ticket
  existed) recorded the execution `cancelled`; cancelling a parked (`reconciling`) execution raised the database's
  transition guard error.
* **New tests** (`tests/integration/test_action_cancellation.py`, 23): on `5e17eff` 19 failed and 4 passed
  (`on-prior-pr-head.txt`); on `main` (`8f8a3e6`, with this change's test helpers) 19 failed and 4 passed
  (`on-main.txt`); with the change 23 passed (`after-change.txt`, regenerated in run 34). The four that pass everywhere guard behaviour that
  was already right: a worker that keeps its lease meets the cancellation at the authorization and returns the use; a
  dispatch reported not applied is accounted for; a request that succeeds after the cancellation was requested ends
  `succeeded` (two variants).
* **Failures on the previous head, by reason:** a claim-time cancellation left the execution `executing` and the use
  `reserved` with the job `cancelled` (takeover before authorization, takeover after authorization, recorded success
  before the claim, the stale-worker test); a lost acknowledgement after the cancellation ended the job `cancelled` with
  the execution open and the outcome unknown (two variants); cancelling with an earlier dispatch still in flight
  returned the use, and that request then created the ticket; cancelling a queued job with an unknown outcome recorded
  `cancelled` (three operator variants); cancelling a carried, never-run job returned the use; cancelling a parked
  execution, including one whose success was already recorded, raised the transition guard error; abandoning a
  witness-parked job returned the use; the generic job operations did not refuse an action job (two). On `main`, where
  post-effect transitions are not yet fenced, three fail differently: the stale worker itself cancelled the execution
  and returned the use (stale-worker test); the stale worker marked the execution `succeeded` while the claim cancelled
  the job (recorded success before the claim); and the precondition of the parked-execution variant does not arise
  because the stale worker finished the execution itself.
* **Adoption the gate cannot verify** (found by a review of the whole change, `adopt-on-earlier-code.txt`): on
  `5e17eff` adopting a witness-parked execution with an invented reference (`SEC-7`, no ticket existed) ended the
  execution `succeeded` with that reference, and adopting a recorded object that had failed verification closed it
  `succeeded`; on `main` both left the job `succeeded` and the execution `reconciling`.
  `test_adopt_without_a_verifiable_record_is_refused` (2) now expects `effect_evidence_missing` with nothing changed.
* **Fix** (ADR 0010 amendment of 2026-10-25, ADR 0006 amendment 3): the settlement rule and the handler's
  `on_cancel`, called at claim time and in the lease holder's final write; `cancel_execution` settles only jobs no
  worker holds; abandon never returns the use and records `external_effect: unknown`; generic job cancel and
  effect resolution refuse action execution jobs; adoption without an open intent needs a matching, uncontested
  recorded success; the gate's observation writes lock the job row before the intent.

Accepted assumptions: the runtime credential is trusted (ADR 0012 amendment 4); external effects are at most one first
attempt per operation key, with duplicates stopped only by provider deduplication or fencing (ADR 0010). Nothing here
makes execution exactly-once.

### Run 34: returning a use needs restore-witness clearance; observation lock order (2026-10-25)

Records: `docs/verification/2026-10-25-cancellation/` (`witness-on-24e2dfd.txt`, `lock-order-control.txt`,
`after-change.txt`). Same database and coordination as run 33; the witness is a real `FileWitness` in a temporary
directory, set ahead of the database's effect watermark (a worker recorded an effect the rolled-back database no longer
has), at it (healthy), or removed (unreadable).

* **Reproduced on `24e2dfd`** (the head after run 33): with the witness ahead of the database and the execution's
  intent absent, `cancel_execution` through the API cancelled the execution and released the use at once (job
  `cancelled`, uses 1 reserved / 1 released); the same with the witness unreadable. The lease holder's final write
  did the same with the witness ahead or unreadable. Of the 6 witness tests, 4 failed for that reason; the healthy API
  case also failed, because the API now leaves the release to a worker by design; the healthy lease-holder case passed.
* **Fix:** `release_clearance` in the releasing transaction (ADR 0010, amendment of 2026-10-25); the API never returns
  a use on missing records and requeues the job for a worker; held when clearance is missing.
* **Lock order.** `test_recording_a_provider_answer_while_a_cancellation_is_settled_completes_without_deadlock`: B's
  claim holds the job row inside the settlement while A's provider call returns success; the test proceeds once
  PostgreSQL reports A's backend blocked by B's. With the observation write's job-row lock removed (control), PostgreSQL
  reported `deadlock detected`, aborted A's outcome record, and the intent stayed `executing` while the ticket existed.
  With it, A waits, the settlement holds the use (`needs_operator`, `reconciling`, `reserved`), the success is recorded,
  A's transition is discarded, and the operator's adoption then ends `succeeded`.
* **Database guard review:** the release trigger enforces a structural invariant (no release once an intent has left
  `prepared`) and no more; the restore, in-flight and witness rules are application-enforced (ADR 0010 amendment,
  "The database guard on returning a use"). Documentation that described the guard as ensuring the effect was never
  attempted is corrected.
* **Existing tests changed:** `test_cancel_before_any_attempt_returns_the_use` and
  `test_cancel_after_an_attempt_reported_not_applied_returns_the_use` now drive a worker before expecting the use back,
  and the first also asserts the use is still reserved right after the API call.

### Run 35: approval use across a physical rollback (2026-10-25)

Records: `docs/verification/2026-10-25-cancellation/` (`rollback-drill-final.txt`, `rollback-drill-on-24e2dfd.txt`).
`tests/drills/test_action_restore_boundary.py` (opt-in drill, part of the CI restore-drill stage) starts its own
cluster and runs `tests/drills/action_restore_child.py` against it: a real execution request, a stopped-cluster
snapshot, the execution (one ticket, witness advanced to watermark 1), an application session opened, cluster stopped,
data directory rolled back, cluster started.

* **Both runs:** the open session failed on its next statement (`OperationalError`); the restored database showed the
  execution `prepared`, the job `queued`, no intent and the use reserved, while the ticket existed.
* **On `24e2dfd`:** the API cancellation cancelled the execution and released the use (uses 1 reserved / 1 released);
  after `acknowledge-recovery`, a fresh execution of the single-use approval was allowed and created a **second
  ticket**.
* **Final head:** the API cancellation left everything unchanged; a worker's `run_once` refused (`behind the external
  witness`); a worker claiming as if past its preflight held the cancellation (`needs_operator`, `reconciling`, use
  reserved, reason "database effect watermark 0 is behind the external witness 1"); after `acknowledge-recovery` a
  fresh execution was refused (`approval_exhausted`); one ticket.
* **What the existing physical drill did not cover:** it runs a generic ticket job, not the action path, and closes its
  connection pool before each stop, so neither approval release nor a session open across the rollback was tested.
* **Not covered:** in-place restores into a live database, restoring while workers run, proxies, failover and
  point-in-time recovery (ADR 0010 amendment of 2026-10-25, "Supported restore boundary").

### Run 36: GitHub Issues opt-in test prepared; unreadable credential at create (2026-10-25)

Local only; nothing contacted the target repository and no real credential was used.

* **Confirmed on `main` (`fa25f6c`):** with the credential readable for the lookup and unreadable when the create was
  built, no request was sent but the intent was recorded `unknown` (the job would then park for an operator).
  `test_github_credential_unreadable_at_create_is_not_an_unknown_outcome` failed with `('queued', 'unknown', 0)`.
* **Fix:** the adapter resolves the credential before sending and reports `DefinitelyNotApplied` when it cannot; the
  test passes (the job retries and then creates one issue against the fake).
* **Opt-in test** `tests/integration/test_github_issues_optin.py` and manual workflow
  `.github/workflows/github-issues-optin.yml`: plan in `docs/integration-tests/github-issues.md`. Rehearsed against
  the local GitHub fake with real network blocked: normal 6 passed (4 fake issues), readonly 1 passed, revoked 1
  passed. Not yet run against GitHub; the adapter stays fixture-tested.

