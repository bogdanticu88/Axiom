# Handoff

## Current checkpoint
* Foundation checkpoint commit: recorded in "Checkpoint record" at the end of this file (a commit cannot contain its
  own hash). Git tag: `foundation-checkpoint-1`.
* Branch: `main`. No remote is configured. **Nothing has been pushed or published.** A permanent repository location
  has not been chosen; preservation archives and a git bundle were kept as release archives.
* The first commit imports the supplied foundation archive; its contents predate this repository.

## What works (verified)
Tenant-isolated schema with forced RLS and transaction-bound context; role provisioning and checksummed migrations;
case lifecycle commands with database guards and five closure routes (including asset retirement); atomic audit,
event and outbox; leased outbox relay; evidence upload, finalisation, classified and audited reads, tamper detection
(filesystem and S3); /api/v1 for the above; Compose single-host install. Details: IMPLEMENTATION_STATUS.md,
VERIFICATION.md.

## Explicit gaps
Development token authentication only (no production SSO); single-step risk acceptance (no request/authorise/renew);
job runner without metrics or ops API; no investigation, policies, actions, reporting, UI, Helm,
observability, backup/restore, retention; no connectors at any support level. See REQUIREMENTS.md "Known gaps".

## State after the Phase B checkpoint
* Phase B core is built and verified (ADR 0009): import pipeline, fenced pages, replay safety, quarantine, coverage,
  strong/weak identity with review candidates, case correlation and recurrence, Trivy/SARIF (fixture-tested with real
  tool output), Tenable/Azure Resource Graph (fixture-tested with synthetic data and local fakes), interim worker.
* Both workflow experiments are complete and independently rerun; **ADR 0006 is proposed and awaits the project owner's
  confirmation** (recommendation: PostgreSQL-backed runner for Phases B-D, Temporal as named alternative).

## State after the job-runner checkpoint
* ADR 0006 accepted. `axiom.jobs` built and verified for single-effect jobs (see ADR 0006 "Status of the
  conditions"); ingestion runs and an hourly risk-expiry sweep run on it through `python -m axiom.workers.jobs`
  (Compose service `job-worker`). The interim ingestion dispatcher is gone.
* After restoring a database backup, workers refuse to start until `python -m axiom.provisioning --dsn ...
  recovery-status` has been reviewed and `acknowledge-recovery --by ... --note ...` run.

## State after the actions checkpoint
* Action protocol (ADR 0010): proposals with DB-computed digests, approvals bound to version and digest, locked
  use reservations, pre-execution re-check, API idempotency keys, capability-based effect gate, operator
  reconciliation. Jira-style ticket integration is **fixture-tested only**.
* Two-step risk acceptance (request / authorise / reject / withdraw / renew / reassessment / lapse) with interim
  thresholds D-RISK-1 (DECISIONS.md).
* Job operations API, worker Prometheus endpoint, operator retry (migration 0006), CI pipeline `scripts/ci/run.sh`
  plus `.github/workflows/ci.yml` (never run on a hosted service).
* Restore detection: fingerprint plus external witness (`AXIOM_RESTORE_WITNESS=dir:...|s3:...`, required in production).
  Rolling back database and witness together is undetectable by design; keep the witness in another backup domain.
* R7 was still open at this checkpoint; it was decided and implemented at the next one.

## State after the R7 checkpoint
* R7 approved (Option A with conditions) and implemented: `withdraw_remediation`, migration 0008, Specification S 4
  amended, database backstops for the evidence and unresolved-effect conditions.
* Per-effect-class action permissions (migration 0009); production.change and pull_request.create stay disabled.
* Restore: write-once witness records (directory and S3), start-up probe and refusal, acknowledgement never
  authorises replay (migration 0010). S3 tested against SeaweedFS only; production storage assumptions in ADR 0010.
* Phase D tracking: inbound ticket polling, SLA timers (defaults D-SLA-1), immutable exposure snapshots, JSON/CSV
  exports (migration 0011). ServiceNow and GitHub Issues ticket adapters: fixture-tested only.
* GitHub Actions pinned to verified commit hashes (docs/ci-action-pins.md); hosted CI still never run.

## Next tasks (in order)
1. Reporting depth: query versions, coverage and denominators in snapshots (RPT-01/02), evidence packages for
   auditors (RPT-05, J08), export classification and expiry (RPT-06), webhook-based inbound ticket events (ING-08).
2. Ownership routing and attestations (RPT-08, J03); per-class delegation limits for approvers.
3. Sandbox validation of any workflow integration once a Jira Cloud site, ServiceNow developer
   instance or GitHub org/app (needs explicit authorisation to connect).
4. Witness on the intended production store: run `tests/integration/test_s3_witness.py` against it and record the
   storage properties ADR 0010 lists.
5. Phase B remainder (AST-03 merge/split, ING-08 webhooks, ING-10 connector health, real CodeQL/Semgrep SARIF,
   production secret resolution); production SSO (AUTHZ-14); Phase C (which also supplies the priority command the
   material-change and SLA tests currently inject).
6. Hosted CI once a remote is authorised.

## Commands
```
uv sync --frozen
scripts/dev/test-db.sh start                 # disposable cluster 127.0.0.1:55432; writes .env.test (gitignored)
uv run pytest tests -q
scripts/verify/foundation.sh                 # separate fresh cluster + SeaweedFS; log in .var/verify/<stamp>/
scripts/ci/run.sh                            # full CI pipeline: foundation + restore drill + Compose smoke (BUILD=1)
AXIOM_RUN_DRILLS=1 uv run pytest tests/drills   # physical snapshot rollback drill on its own cluster (free port)
python -m axiom.provisioning --dsn ... recovery-status --witness-dir DIR   # after any restore
BUILD=1 scripts/verify/compose-smoke.sh      # behind a TLS proxy add BUILD_CA=<ca bundle>
scripts/dev/test-db.sh destroy               # remove the disposable cluster
```

## Restore
From the git bundle (full history):
```
git clone axiom-<stamp>.bundle axiom
cd axiom && git log --oneline | head
```
From the source archive (no history): `tar -xzf axiom-source-<stamp>.tar.gz`, then follow README "Fresh install".
Verify downloads with `sha256sum -c SHA256SUMS`. Neither artifact contains secrets, `.env` files, database data,
virtual environments or uploaded evidence; generate new credentials (`deployments/compose/.env.example`,
`scripts/dev/test-db.sh` generates its own).

## Checkpoint record
| Date | Commit | Tag | Notes |
|---|---|---|---|
| 2026-10-22 | 1c60fe570017e50beb40f0501f5cb6dc0657f2a2 | foundation-checkpoint-1 | Foundation checkpoint; verification runs 1-3 in VERIFICATION.md; experiments excluded (in progress) |
| 2026-10-22 | 3ec1632f2382b04e4f1e129b8053c8188b524a05 | phase-b-checkpoint-1 | Phase B core + ADR 0006 proposed; verification run 10 (126 passed; Compose smoke 3x pass after script fix) |
| 2026-10-22 | 8aa13c177c9d7c4b48d1feeed788e3cef8775991 | job-runner-checkpoint-1 | ADR 0006 accepted; axiom.jobs; ingestion and risk sweep on jobs; verification run 12 (154 passed; Compose smoke pass) |
| 2026-10-22 | eeae2b9286a1a30a6826a525118102ccd00b9438 | actions-checkpoint-1 | Action protocol (ADR 0010), two-step risk acceptance, job operations and metrics, restore witness, CI script; run 13 (CI PASS: 199 passed + drill + Compose smoke) on the working tree committed as f07607b (only docs changed afterwards) |
