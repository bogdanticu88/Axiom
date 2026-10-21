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

## In-flight work at the time of writing
* `experiments/workflow-pg-spike/`: PostgreSQL-backed workflow experiment (background agent). Check its RESULTS.md.
* `experiments/workflow-spike/`: additional Temporal security and recovery probes (SECURITY-AND-RECOVERY.md).
* Both feed ADR 0006. If they are incomplete when you resume, rerun their suites (commands in each README) before
  relying on any result.

## Next tasks (in order)
1. Complete ADR 0006 from both experiments' observed results; record the decision and the requirements that stay
   regardless of engine.
2. Phase B ingestion (REQUIREMENTS section 8): migration 0003 with connections, ingestion runs, pages, quarantine,
   source objects, observations and occurrence history; generic import pipeline with original evidence preservation,
   replay deduplication and run coverage; Trivy JSON, SARIF 2.1.0 and Tenable export parsers with synthetic fixtures
   (fixture-tested at most); Azure Resource Graph context adapter (fixture-tested; live validation blocked without a
   subscription); asset identity candidates with explicit uncertainty.
3. Build the chosen durable runner for actions and approvals (Phase D groundwork), then RISK-02 two-step acceptance.
4. CI pipeline (DEP-08) running `scripts/verify/foundation.sh` equivalents.

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
