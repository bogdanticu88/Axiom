# Handoff

## Current checkpoint
* Latest checkpoint: see "Checkpoint record" at the end of this file (a commit cannot contain its own hash).
* Branch: `main`, published at https://github.com/bogdanticu88/Axiom. Each checkpoint was also kept as a git bundle
  and a source archive.
* The project was renamed to Axiom before publication, and the history was rewritten at the same time. Commit hashes
  quoted in these documents and in docs/VERIFICATION.md refer to the original development repository; the checkpoint
  tags in this repository mark the corresponding commits.
* The first commit imports the supplied foundation archive; its contents predate this repository.

## What works and what is missing
The sections below are a history by checkpoint; the latest is "State after checkpoint 8". For the current position
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

## State after checkpoint 4 (Phase C: evidence-backed investigation)
* Register reconciled. The checkpoint-3 chat summary said 259 because it left out 2 implemented_unverified and 1
  blocked. `scripts/dev/register-counts.py` now generates the counts and is a CI stage; it also found and fixed one
  row with a misplaced status column.
* Migration 0013 and ADR 0012 add:
  * frozen evidence snapshots (observation versions, runs with coverage and freshness, asset versions, context,
    evidence; contradictions and gaps kept);
  * per-tenant model routes (two-person approval, registered destinations, classification limit, no fallback);
  * a gateway with redaction and usage accounting;
  * durable investigation runs (budgets, deadline, cancellation, revocation, crash recovery);
  * read-only typed tools with an OSV lookup behind a registered destination;
  * claim validation (rejected, downgraded or references_checked; entailment never claimed);
  * mandatory human claim review before an assessment may cite a run;
  * a database trigger that stops workload principals recording consequential decisions, approvals or reviews.
* **No language model has been called.** CI uses `DeterministicFakeProvider`. The Anthropic adapter follows the
  documented API shape and is tested against a local transport; the opt-in test
  (`tests/integration/test_real_provider_optin.py`) has never run because there are no credentials and external access
  is not authorised.
* Evaluation: `evaluation/cases.json` (16 scenarios, 6 dev and 10 held-out) and `tests/integration/test_evaluation_harness.py`
  with policy, AI-assisted (fake) and adversarial arms; `evaluation/report.py`. Reference labels are
  author-drafted, **not human-reviewed** (D-EVAL-1). The harness found a validator gap (a conclusion against the
  latest observation was accepted when both sides were cited), which is now fixed.
* Reviews done:
  * deferral pauses the SLA only for policy-authorised reasons, with gross, paused and adjusted time reported;
  * evidence metadata (digest, size, filename) needs explicit permission in packages, snapshot reads and model
    prompts. A test also found that metadata of above-classification evidence was reaching the prompt; fixed.
* The API journey replaces the manual assessment with snapshot, investigation, human claim review and an assessment
  that cites the run.

## State after checkpoint 5 (analyst UI, enterprise sign-in, preview and override expiry)
* **Claim checks described precisely** (ADR 0012 amendment): deterministic record checks only (existence and
  membership, availability, identifier equality, recorded status, freshness, scan-time-ordered contradiction rules,
  deployment scoping), never semantic relevance or entailment. Import time never orders evidence; ties, missing scan
  times and different sources leave a contradiction `undetermined` and open for a person. Tests cover the five cases
  in the brief; a reference whose identifiers and status match but whose content does not support the statement's
  wording is **not** detected and is left to human review.
* **System authority** (migration 0014): humans make discretionary decisions; system identities may record only
  policy-authorised results within the permission in their recorded authority (prioritisation, verification
  observations, reopen on recurrence or acceptance expiry). Principal type comes from identity records via
  `axiom_auth.principal_kind`. VER-04 and override-expiry reassessment were blocked by the earlier human-only trigger and
  are now possible; VER-04 is still not built.
* **Overrides expire** (default 90 days, max 365, D-PRIO-2) and expiry re-applies the current policy with provenance;
  the earlier priority is never restored. **Impact preview** is read-only and verified by state comparison.
* **Enterprise sign-in** (ADR 0013, migration 0015): OIDC code flow with PKCE (Authlib 1.8.0, joserfc 1.7.5),
  single-use browser-bound login state, hashed server-side sessions with CSRF, logout, membership revocation,
  production refusal of development tokens at startup and runtime. Verified against a **local Keycloak 26.4.2
  container only. Entra ID is not tested.**
* **Analyst UI** (`frontend/`, React/TypeScript/Vite, served at /ui under a strict CSP): coverage and freshness, case
  queue and unresolved ownership, asset/deployment context with provenance, evidence snapshots with withheld content
  and metadata, investigations (progress polling, limitations, claims, review), assessment, priority and overrides,
  proposals/approvals/execution/reconciliation, verification and closure, reports and auditor packages, policy
  preview, model routes. Labels for the fake model, unverified routes, fixture-tested integrations and manual
  records; loading, empty, denied, not-found, stale-version and dependency-failure states. Six Chromium tests sign in
  through Keycloak's real login page.
* Found while building the UI: the case-context endpoint marked every scanner-imported deployment "manually
  recorded" (ingestion never sets `source_evidence_id`); provenance is now derived from occurrence observations.
  Analysts with project-level roles could not list model routes; any investigation reader in the tenant now can.
* **Evaluation review package** (`evaluation/export_review.py`, eval-cases@3 with a rationale per label): dev and
  held-out folders, frozen evidence per scenario (credential-shaped text redacted), reviewer CSV, fake output in a
  separate folder, security-boundary results separate. Labels remain author-generated and unreviewed.
* The register counter reports rows verified only against fakes or fixtures separately (18 of 147) and fails when
  such a row lacks the qualifier.

## State after checkpoint 6 (finish and verify the existing workflow)
* **Starting point verified** (docs/VERIFICATION.md run 18): the checkpoint-5 artifacts match their checksums, the
  tag points at 622f216, CI passed on 3e95d46 and only documentation changed afterwards. Two discrepancies found and
  disclosed: the checkpoint-5 chat report gave two checksums against the wrong files (the files and SHA256SUMS were
  right); the checkpoint-5 mutation harness left a stale mutated bytecode file in the workspace (not in any artifact).
* **Authority boundary** (ADR 0012 amendment 2, migration 0016): the database now checks a system principal's real
  role bindings instead of trusting the decision's authority JSON; workload reopening is limited to recurrence and
  acceptance expiry; system reopening needs case.reopen in the service too; workload principals can hold only workload
  roles; the audit trail records the kind from identity records. Every system action is listed in the ADR.
* **Browser coverage**: approval (self-approval and stale version refused, exact payload shown, execution against the
  local fake tracker), verification (person-entered, recomputed, auditor and stale refusals, closure), reports
  (export refused for analysts in the UI and at the API, auditor download digest-checked, evidence package) and the
  new **risk-acceptance screen** (request, independence and permission refusals, expiry by the system sweep, history
  with and without audit access). The tests found four UI defects (see VERIFICATION), all fixed.
* **Compose delivers the UI** with a local Keycloak; docs/INSTALL-COMPOSE.md. The smoke test signs in through
  Keycloak in Chromium, completes a workflow, checks an auditor refusal and server-side logout, and checks that the
  API refuses production mode with development identity and refuses to start without the client secret.
* **Deprecated Authlib client replaced** by Authlib's core PKCE helpers and a direct token request; all sign-in
  regression tests pass against the local Keycloak, including replayed and failed logins.
* **Evaluation**: the former held-out set is disclosed as exposed (evaluation/EXPOSURE.md) and is now the
  `regression` split; a blind review procedure, worksheet, sealed author labels and a comparison tool exist;
  independent review is **pending**.

## State after checkpoint 7 (assurance of the authority and sign-in changes; verification worker)
* **Baseline** (docs/verification/2026-10-22-checkpoint7/baseline.md): tag, checksums and history verified; the
  post-CI test-only commit 30044e9 only changed synchronisation but loosened four header checks to substring matches
  (tightened again); clean-clone CI passed on the final checkpoint-6 revision 1eed24c before any change.
* **Authority review** (ADR 0012 amendment 3, migration 0017): three demonstrated defects fixed — a bound
  transaction could record a decision or approval as another principal (D1), re-bind another principal (D2), and a
  revocation could commit between a command's permission check and its commit (D3). Hardening: pre-0016 bindings are
  reviewed and incompatible ones revoked with a security event; a principal's kind is immutable. The revocation
  guarantee is stated at the transaction boundary.
* **Sign-in review** (ADR 0013 amendment 2): library versus application responsibilities listed; `azp` now checked
  whenever present (gap found); login rotates the session; sign-in query strings are redacted from the access log;
  live signing-key rotation at the local Keycloak is followed.
* **Production configuration** (docs/DEPLOYMENT-TRUST-BOUNDARY.md): secrets as mounted files (`secretref:file/`),
  the only form accepted in production; TLS ends at an operator proxy and forwarding headers are ignored. Still not
  tested over TLS or behind a proxy.
* **Verification worker** (ADR 0014, migration 0018): a per-tenant verification identity with three permissions,
  authority re-read at execution and commit, explicit outcome rules, provenance rows, one job per reported change;
  tested only against a local TLS fixture endpoint.
* **UI**: change-report form browser tests (keyboard-only success, permission and stale refusals); focused
  accessibility checks (not an audit); worker results labelled separately from people's.
* **Evaluation**: unchanged labels and splits; review still pending (outstanding steps in
  evaluation/REVIEW-PROCEDURE.md).

## State after checkpoint 8 (trust boundaries made explicit and tested)
* **Baseline:** the checkpoint-7 tag, manifest, checksums and artifact contents verified in the private history and in
  the published Axiom history; the commits after the CI commit change records only (plus the comment-only commit,
  checked to leave the code unchanged, and README text).
* **Database identity (ADR 0012 amendment 4):** the shared runtime login can bind any tenant and any principal, so a
  holder can read any tenant, act as anyone, approve through impersonation and attribute audit rows to anyone; it
  cannot rewrite history or escape its role. This is an accepted trust assumption, now stated precisely and tested.
  The earlier "of its tenant" wording was wrong and is corrected; the D1/D2 fixes are narrowed to integrity checks
  against application defects.
* **Revocation:** failed and rolled-back commands release the authority locks at once; shortening a membership waits
  like a suspension; disabling a principal and suspending a tenant are documented as outside the boundary.
* **Verification worker (ADR 0014 amendment 1):** operator-allowed destinations only, addresses checked and pinned,
  TLS names verified, responses bound to job, nonce and asset, echoed credentials redacted; lifecycle tests check the
  records, not only job status.
* **Local TLS deployment:** the documented proxy arrangement with production settings and a mounted secret, tested in
  Chromium end to end. Local only.
* **Evaluation:** unchanged; independent review still pending.

## Core gaps (do not let UI work hide these)
* **No language model verified**; real-provider execution is not authorised.
* **Entra ID (or any hosted IdP) not tested**; no back-channel logout, JIT/SCIM provisioning or workload identity;
  sign-in over TLS and behind a reverse proxy untested (secrets can now be mounted as files).
* **No held-out evaluation set; label review pending.**
* UI: no identity-candidate, integration-configuration or job-operations screens; Chromium only; focused
  accessibility checks only, no audit.
* Verification worker tested against a local fixture endpoint only; no real check service; no connector
  sandbox-validated; trackers are fakes.
* The application database credential is equivalent to administrator access to every tenant of the installation
  (ADR 0012 amendment 4). A tenant that needs stronger separation needs a dedicated installation.

## Next tasks (in order)
1. Independent label review with evaluation/REVIEW-PROCEDURE.md; a new held-out set written by someone else.
2. With authorisation: an Entra ID test tenant; a staging deployment with a real certificate and proxy.
3. A real check service behind the verification worker (adapter or shim for `axiom-check/2`), validated in a sandbox.
4. Identity-candidate screens; an accessibility audit; a second browser.
5. With authorisation: the real-provider test and real-model evaluation arm.
6. Hosted CI and sandbox validation once a remote and accounts are authorised.

## Commands
```
uv sync --frozen
scripts/dev/test-db.sh start                 # disposable cluster 127.0.0.1:55432; writes .env.test (gitignored)
uv run pytest tests -q                       # browser tests need: (cd frontend && npm ci && npm run build); Docker for Keycloak
(cd frontend && npm ci && npm run build)     # analyst UI; serve with AXIOM_UI_DIST_DIR=frontend/dist
docs/INSTALL-COMPOSE.md                      # Compose with the UI and a local Keycloak
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
| 2026-10-22 | (this documentation commit; see `git log`) | checkpoint-4 | Phase C investigation, evaluation harness, SLA and metadata reviews; run 16 CI PASS on a clean clone of dae1051776cd4e4cc56821ce531bfc037f12a970 (tree 5e20261d...) after a recorded secret-scan failure on c96cf14; only docs/verification files changed afterwards |
| 2026-10-22 | (this documentation commit; see `git log`) | checkpoint-5 | Analyst UI, OIDC sign-in (local Keycloak only), override expiry and preview, claim-check precision, system authority, evaluation review package; run 17 CI PASS on a clean clone of 3e95d461c7cc4f59686d4b07f33835b723c29b79 (tree 4c2384cb...) after a recorded secret-scan failure on 3d093ea; only docs/verification files changed afterwards |
| 2026-10-22 | (this documentation commit; see `git log`) | checkpoint-6 | Authority boundary review and fixes (migration 0016), workflow browser tests, risk-acceptance screen, UI and local Keycloak in Compose, deprecated OIDC client replaced, held-out exposure disclosed; run 18 CI PASS on a clean clone of 9c7303ca47c89e24d94dad4b4c8447b0a3c7ffbf (tree 95e0a9b5...); afterwards one test-only commit (30044e9, browser tests rerun) and documentation |
| 2026-10-22 | (this documentation commit; see `git log`) | checkpoint-7 | Authority review fixes (migration 0017), sign-in review fixes, mounted-file secrets, verification worker (migration 0018, fixture endpoint only), change-report and focused accessibility browser tests; baseline CI PASS on 1eed24c; run 19 results and the revision each covers are in VERIFICATION.md |
