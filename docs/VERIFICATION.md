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
