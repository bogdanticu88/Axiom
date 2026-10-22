# Handoff

## Current checkpoint
* Latest checkpoint: see "Checkpoint record" at the end of this file (a commit cannot contain its own hash).
* Branch: `main`. No remote is configured. **Nothing has been pushed or published.** A permanent repository location
  has not been chosen; preservation archives and a git bundle were kept as release archives.
* The first commit imports the supplied foundation archive; its contents predate this repository.

## What works and what is missing
The sections below are a history by checkpoint; the latest is "State after checkpoint 3". For the current position
against the complete register, read "Core product status" in IMPLEMENTATION_STATUS.md and "Core gaps" below.
The foundation-era gap list has been superseded.

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

## State after checkpoint 3 (policies, ownership, SLA v2, reporting depth, journey)
* Migration 0012 and ADR 0011: versioned policies (priority, ownership, SLA, freshness) with independent publishing;
  `apply-priority-policy` and `override-priority` commands (tests no longer inject priority); ownership routing with
  an unresolved queue, overrides and no conferred authority; SLA v2 (triage vs remediation, pause on deferral,
  revise-not-reset, accepted risk never "met"); reports reconstructed as of a time with separate denominators,
  per-source coverage/completeness/freshness and explicit unknowns; classification-aware auditor evidence packages.
* Restore witness pruning audited (ADR 0010 "Witness pruning"): exact identity match (a suffix-match bug fixed),
  invariant that the maximum record is never deleted, tests with randomised listings, interruption, pagination and
  concurrency. Production storage properties remain unverified.
* HTTP journey test (`tests/integration/test_journey_end_to_end.py`) from a real Trivy import to verified closure
  and a report, with each step labelled real / fixture / fake / manual / test-read
  (`docs/verification/2026-10-22-checkpoint3/journey-steps.json`).
* CI now starts with `scripts/ci/input-manifest.sh`, which refuses a dirty tree and records the commit, tree hash
  and an executable-input digest, plus the pinned and unpinned inputs.
* All thresholds are provisional defaults (D-SLA-2, D-PRIO-1, D-FRESH-1, D-RISK-1, D-ACT-1).

## Core gaps (do not let runner work hide these)
* **Investigation (Phase C) is not built**: no evidence snapshots, tool or model gateway, claims or AI analysis.
* **No user interface** exists; all journeys are API-only.
* **No enterprise SSO**; development token authentication only.
* No connector is sandbox-validated; trackers are fakes; no deployment or rescan integration (the journey supplies
  the redeploy and the rescan manually).

## Next tasks (in order)
1. Phase C foundations: evidence snapshots and policy snapshot frozen per investigation (INVS-01), investigation runs
   with explicit incomplete results (INVS-06), claims with supporting/contradicting observations (INVS-04), schema-
   checked model output with reference validation (A06) behind a provider-neutral gateway, adversarial suite (A05).
2. UI for the verified API journeys (ARC-05; J02, J03, J04, J07, J08, J09 first).
3. Enterprise OIDC SSO (AUTHZ-14) with an IdP integration test (Keycloak in Compose).
4. Priority impact preview and override expiry (PRI-05, PRI-06); reassessment on policy change (A14).
5. Sandbox validation of a tracker and of the witness store, once access to them.
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
| 2026-10-22 | 4fc326f2d09400b521d3765e03b4dea46ae48ed4 | r7-checkpoint-1 | R7 and the rest of the 2026-10-22 instruction set; run 14 CI PASS on the working tree committed as e7a2f36 (content hash a12af0d9...); documentation only afterwards |
| 2026-10-22 | (this documentation commit; see `git log`) | checkpoint-3 | Policies, ownership, SLA v2, reporting depth, witness pruning audit, journey; run 15 CI PASS on a clean clone of code commit 4a3069ac903b2f7b991c70c72c0c3df95a52e85b (tree 06603b65...); only docs/verification files changed afterwards |
