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
workflow engine undecided (ADR 0006 pending); no ingestion, investigation, policies, actions, reporting, UI, Helm,
observability, backup/restore, retention; no connectors at any support level. See REQUIREMENTS.md "Known gaps".

## State after the Phase B checkpoint
* Phase B core is built and verified (ADR 0009): import pipeline, fenced pages, replay safety, quarantine, coverage,
  strong/weak identity with review candidates, case correlation and recurrence, Trivy/SARIF (fixture-tested with real
  tool output), Tenable/Azure Resource Graph (fixture-tested with synthetic data and local fakes), interim worker.
* Both workflow experiments are complete and independently rerun; **ADR 0006 is proposed and awaits the project owner's
  confirmation** (recommendation: PostgreSQL-backed runner for Phases B-D, Temporal as named alternative).

## Next tasks (in order)
1. On confirmation of ADR 0006: build `axiom.jobs` (step timeouts, claim counter for poison runs, RLS-compatible
   claiming, operator tooling, metrics, restore marker, CI kill suite) and move the ingestion dispatcher onto it.
2. Phase D groundwork on that runner: action proposals, approvals bound to digest/scope/expiry/uses, reservations,
   intents, reconciliation, idempotency-key storage (API-07); then RISK-02 request/authorise/renew.
3. Phase B remainder: merge/split execution for confirmed identity candidates (AST-03), webhooks (ING-08), connector
   health and freshness (ING-10), real CodeQL/Semgrep SARIF fixtures, production secret resolution (Key Vault /
   workload identity), Defender for Cloud and AWS inventory (Phase E list).
4. Production SSO (AUTHZ-14) and CI (DEP-08).
5. Decide open item R7 (route back from planned/remediating to review).

## Commands
```
uv sync --frozen
scripts/dev/test-db.sh start                 # disposable cluster 127.0.0.1:55432; writes .env.test (gitignored)
uv run pytest tests -q
scripts/verify/foundation.sh                 # separate fresh cluster + SeaweedFS; log in .var/verify/<stamp>/
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
