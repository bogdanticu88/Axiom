# Implementation status

This is the single entry point for the current state. "Current status" below describes `main` at
`a05c01f7cf81b1bfd162c302cbe1177254bd11f6` (2026-10-23, the merge of pull request 1). The sections after it are the
detailed status by area from the review of 2026-10-22, kept as written except where marked; where they disagree with
"Current status", "Current status" wins. Requirement-level detail is in REQUIREMENTS.md.

## Current status

### Implemented and tested
Exercised by tests that were run. The latest full run on `main` is GitHub Actions run 39950928655 at `a05c01f`:
every stage passed, 692 tests passed and 3 were skipped (the physical restore drill, which runs as its own stage and
passed; the opt-in real-provider test, never run; the opt-in demonstration). These counts describe that run only.

* Tenant isolation: application authorisation, composite tenant-aware foreign keys, forced row-level security,
  transaction-bound tenant context; runtime roles own no tables and are neither superuser nor BYPASSRLS (ADR 0002,
  0003).
* Authority: scoped role bindings with expiry and revocation; disabled principals, suspended tenants and expired
  bindings refused at the next request; a revocation that commits after a command's check waits for that command
  (ADR 0012 amendments 3 to 5).
* Case workflow with optimistic concurrency, database guards, append-only decisions, events and audit (ADR 0004).
* Evidence storage with digests, classification-aware reads and tamper detection (ADR 0005).
* Ingestion with fenced, resumable imports, coverage, quarantine and replay safety (ADR 0009).
* Durable job runner, action proposals with human approval bound to the exact payload, idempotency keys, effect gate
  and reconciliation (ADR 0006, 0010).
* Two-step risk acceptance, versioned policies, ownership routing, SLA clocks, as-of reports and auditor evidence
  packages (ADR 0011).
* Investigation runs over frozen evidence snapshots, with claim checks and human claim review (ADR 0012), against the
  deterministic fake only.
* Verification worker with destination policy, pinned connections, request-bound responses and redacted credentials
  (ADR 0014).
* API timestamps must name an instant; offset-free values are refused (ADR 0015).
* Analyst UI for the covered screens, in Chromium; OIDC sign-in against a local Keycloak, including behind a local TLS
  proxy in production mode (ADR 0013).
* Compose single-host install (development profile), checked by the Compose smoke test with a real browser.
* The local end-to-end demonstration (docs/DEMO.md). Latest recorded run: `a05c01f`, 2026-10-23,
  `docs/verification/2026-10-23-demo-main/`.

### Tested only against fixtures, fakes or local services
* Scanner and context sources: Trivy and SARIF with recorded real output; Tenable and Azure Resource Graph with
  synthetic data and local fakes. None validated against a live service.
* Ticket integrations (Jira-style, ServiceNow-style, GitHub Issues): local fakes only.
* Investigation: the deterministic fake model only. No language model has been called.
* Verification worker: a TLS test fixture and the local demonstration check service (`scripts/demo`), which is not a
  supported component.
* Sign-in: a local Keycloak; TLS: a local nginx with a throwaway CA.
* S3 storage and the restore witness: SeaweedFS.

### Not tested
* Any hosted identity provider (for example Microsoft Entra ID), a public CA or a real reverse proxy deployment.
* Any language model, any real check service, any live scanner, tracker or cloud API.
* Load, scale and long-running operation; backup and restore of a real installation.
* Browsers other than Chromium; an accessibility audit; usability testing.
* Independent review of the trust boundaries or of the evaluation labels (docs/INDEPENDENT-REVIEW.md).

### Known limitations
* **The shared application database credential has cross-tenant authority.** One runtime login serves every tenant;
  whoever holds it can read and change any tenant's data, act as any user and attribute audit records to anyone. It
  cannot rewrite recorded history. Tenants that need stronger separation need a dedicated installation (ADR 0012
  amendment 4, docs/DEPLOYMENT-TRUST-BOUNDARY.md).
* **A check endpoint can report false results.** Axiom binds each answer to the request, asset and reported
  deployment, but cannot prove it true; a dishonest endpoint can cause a false pass or a false failure (docs/DEMO.md).
* **Timestamps accepted before ADR 0015.** Asset versions recorded by hand before the correction may hold an
  `observed_at` that was read in the server's time zone. Such records cannot be identified from Axiom's records, and
  nothing has been reinterpreted. Idempotency keys stored before the change replay only if first sent with `Z` or
  `+00:00` (ADR 0015, compatibility matrix).
* **Tenant suspension does not cancel work.** A running job is left `running` until the tenant is reactivated; the
  tested recovery procedure is in docs/INSTALL-COMPOSE.md (requirement TEN-16, implementing).
* **Disabling a principal does not stop a command that has already passed its check** (ADR 0012 amendment 5).
* Retried or crashed verification steps can leave stored evidence that nothing cites.
* `axiom.holds_permission` in the database duplicates the application's authority evaluation.
* **Evaluation:** labels are the author's and unreviewed; there is no held-out set (evaluation/EXPOSURE.md).
* The demonstration depends on the daily Trivy database; a later run can fail honestly (docs/DEMO.md).

### Intermittent CI failures
One-off failures on GitHub Actions, each in the Compose smoke stage, with every other stage passing.

**Cause established for one, by its diagnostics:** run 39969148347 (commit `8bc0ac1`). The browser check waits for the
message "Investigation started." after starting an investigation. The API log shows the command succeeded (200), and
the page, when captured, showed the case as `investigating` and no status message at all. In the UI
(`frontend/src/pages/CaseEvidence.tsx`), that message is rendered inside the "Start investigation" section, which is
shown only while the case is `received`; after success the page reloads the case and the section, with its message,
disappears. The check passes only if it sees the message before the reload completes. This is a race between the
check and the UI, not a server failure; it is not fixed yet.

**Cause established for another, by the build output added in run 23:** run 39975479973 (merge commit `305b0fc` on
`main`). The image build failed about two seconds into the stage because `public.ecr.aws` answered the request for
the pinned Python base image's manifest with HTTP 429 (Too Many Requests): the registry refused the pull. Nothing in
Axiom caused it, and the build has no retry; a later run is needed to show `main` green again.

**Cause not established:**
* run 39946416834 (commit `063347b`): the same symptom (timeout waiting for "Investigation started."), but the page
  state and API log were not captured, so it is consistent with the race above without being confirmed by it;
* run 39884012334 (commit `5bff45c`): the image build failed after two seconds; its output was discarded. The timing
  matches the rate-limited pull above, but without the output that is not confirmed;
* run 39955949204 (commit `8cfe42e`): `docker compose up` failed sixteen seconds into the stage; its output is
  discarded and no container logs existed yet. That commit changed only documentation and screenshots relative to a
  passing `main`; this narrows where to look but does not establish that the change played no part.

None could be rerun from here. On failure the smoke test now prints the build output, the `docker compose up` output,
every container's state, exit code and health results, the last lines of each service's log, and the page state of
the browser check, bounded and with its own secrets redacted (verification runs 23, 25 and 27). The browser-check race
above is not fixed by that change.

### Statements this supersedes
Historical records are kept as written. These statements in them are no longer correct:

| Earlier statement | Where | Superseded by |
|---|---|---|
| "Clean-clone CI PASS" as an environment-independent result | runs 13 to 22 in docs/VERIFICATION.md; checkpoint reports | the correction at the top of docs/VERIFICATION.md; runs 23 and 24 (CI with a declared environment, UTC and Europe/Bucharest) |
| Hosted CI never run | the CI row below (before this update), README, HANDOFF | GitHub Actions runs on pull requests and on `main` since 2026-10-22; its first runs failed and exposed the above (run 23) |
| A compromised runtime credential acts only within its own tenant | checkpoint-7 trust statement | ADR 0012 amendment 4: it reaches every tenant |
| The authority check ignores principal status | ADR 0012 amendment 4, revocation list | ADR 0012 amendment 5: disabled principals are refused at the next check |
| Pinning was shown only with an unresolvable name | run 20, mutation W3 | run 21: two servers and a controlled resolver |
| Legacy idempotency keys: "a retry with a non-UTC offset is rejected" | run 23; a delivery note outside the repository (after-checkpoint-8-v3) | ADR 0015 compatibility matrix; run 25 |
| The API accepted timestamps without an offset | earlier API behaviour | ADR 0015 |

### Where the history is
* docs/VERIFICATION.md: every verification run, with the CI correction at the top and a pointer under each affected
  run.
* docs/adr/: decisions and their amendments, 0001 to 0015. The trust boundaries are in 0002, 0012 (amendments 3 to 5),
  0014 and 0015.
* docs/REQUIREMENTS.md: the register; counts below.
* docs/HANDOFF.md: state by checkpoint and the next tasks.

## Detailed status by area (review of 2026-10-22)

Capability states used here:
* **verified**: built and exercised by tests that were run.
* **implemented**: built, not yet exercised.
* **experimental**: a throwaway experiment, not product code.
* **incomplete**: partly built.
* **blocked**.
* **not started**.

### Core product status against the complete register

The action runner and approval protocol received most of the recent effort. The table below shows where the core
product actually stands, so that work does not hide what is missing.

| Area | State | What exists | What is missing |
|---|---|---|---|
| Ingestion | **verified core, fixture-tested sources** | Fenced, resumable import and API-sync pipeline; coverage rules; quarantine; replay safety. Trivy and SARIF use real tool output; Tenable and Azure Resource Graph use synthetic data and fakes | Webhooks; Defender and AWS; 13 catalogue sources; no source validated against a live service |
| Asset context | **verified (incomplete scope)** | Strong and weak identity; review candidates; immutable versions with digests; business context from source tags and user assertions with effective dates (0012) | Merge and split execution; asset relationships and exposure paths; CMDB import |
| Investigation | **built and verified against a deterministic fake; no language model called** | Frozen evidence snapshots with contradictions and gaps; approved model routes with classification limits and no fallback; durable runs with budgets, deadlines, cancellation, revocation and crash recovery; read-only typed tools; claim validation; human claim review before an assessment may cite a run; adversarial tests; evaluation harness | Real provider verification (real-provider execution not authorised); human-reviewed evaluation references; per-tenant quotas; evidence types beyond scanner data (reachability, runtime) |
| Prioritisation | **verified (deterministic part)** | Versioned priority policy with independent publishing; apply command; overrides that expire and are then reassessed by policy with provenance (never restored); read-only impact preview; AI output cannot carry priority | Second approver for overrides; reachability and threat-intelligence inputs |
| Ownership | **verified** | Versioned rules on explicit context; unresolved queue; append-only history with overrides; re-routing when inputs change; no authority conferred | CMDB-sourced ownership; owner notifications |
| SLA | **verified (provisional targets)** | Separate triage and remediation clocks; pauses only for policy-authorised reasons with recorded intervals; gross, paused and adjusted time reported separately; revise-not-reset; breach once; accepted risk never met | Business-hours calendars; escalation delivery |
| Reporting | **verified (exposure summary, evidence packages)** | As-of reproducible snapshots; separate denominators; coverage, completeness and freshness per source; explicit unknowns; auditor packages where content needs read permission and metadata needs read or explicit metadata permission | Case membership lists in snapshots; framework mappings; GRC attestations; portfolio views; performance at volume |
| User interface | **verified for the covered screens (Chromium only); delivered through Compose** | React/TypeScript analyst UI at /ui against the real API: coverage and freshness, case queue and unresolved ownership, asset/deployment context, evidence snapshots with withheld content and metadata, investigations with progress, limitations, claims and review, assessment, priority and overrides, proposals/approvals/reconciliation, verification and closure, reports and auditor exports, policy preview, model routes, risk acceptance; honesty labels; loading, empty, denied, stale-version and dependency-failure states. ui::* (6), uiw::* (5) and uicp7::* (3) browser tests; Compose smoke drives a real browser against a fresh install | Identity candidates, integration configuration and job operations screens; accessibility audit (only focused checks exist: uicp7::); other browsers; usability testing |
| Enterprise authentication | **verified against a local Keycloak only** (also in Compose, and behind a local TLS proxy in production mode) | OIDC code flow with PKCE (Authlib, joserfc); identity by issuer and subject; single-use browser-bound login state; hashed server-side sessions with CSRF; logout; membership revocation; development tokens refused in production (ADR 0013) | **Entra ID or any hosted IdP not tested**; no public CA or real proxy deployment tested; back-channel logout; JIT/SCIM provisioning; workload identity federation |

Register counts, generated by `scripts/dev/register-counts.py` (263 requirement rows; the 21-row integration catalogue
is counted separately). The script now counts rows verified only against fakes or fixtures separately and fails if a
row verified only against fakes lacks that qualifier; it found two such rows (B08, A02) and they are now qualified.

| Status | Now (after the timestamp contract correction) | Checkpoints 7 and 8 | Checkpoint 6 |
|---|---|---|---|
| verified | 150, **of which 19 only against fakes or fixtures** | 149 (19) | 148 (18 against fakes or fixtures) |
| implementing | 68 | 68 | 68 |
| implemented_unverified | 2 | 2 | 2 |
| planned | 42 | 42 | 43 |
| blocked | 1 | 1 | 1 |
| **total** | **263** | **262** | **262** |

New row API-10 (timestamps must name an instant, ADR 0015). At checkpoint 7 the new verified row was VER-04
(verification worker), verified only against a local fixture endpoint.
Integration catalogue: 8 fixture-tested (the verification check endpoint added), 13 planned, none sandbox-validated
or production-supported.

### Phase A: Foundation and recovery contracts

| Item | State | Evidence / gap |
|---|---|---|
| Repository, layout, design inputs preserved | verified | ADR 0001; commit 6ef0e0d holds the archive unmodified |
| Cluster role provisioning, ledgered migrations | verified | Fresh cluster, two databases, re-migration, edited-checksum rejection (every verification run) |
| Tenancy, scoped permissions, hierarchy, expiry, revocation, delegation, emergency access | verified | iso::, cases::, unit:: |
| Transaction-bound tenant context, forced RLS, composite FKs | verified | ADR 0002; iso:: |
| Authentication | **incomplete** | Development tokens (refused in production) and OIDC sign-in verified against a local Keycloak (ADR 0013); **Entra ID not tested** |
| Case commands with optimistic concurrency and DB guards (incl. R7) | verified | cases::, r7::, iso::test_direct_sql... |
| Atomic audit, events and outbox; leased relay; inbox dedupe | verified | B12/A19 tests, evo:: |
| Evidence upload, finalisation, classified audited reads, tamper detection | verified | evo::, s3:: |
| HTTP API (/api/v1) | verified for implemented endpoints | api::, act_api::, jrn::, Compose smoke |
| Compose single-host install | verified (development profile) | PostgreSQL, SeaweedFS, init, API with the analyst UI, job worker and a local Keycloak; fresh-install smoke signs in through Keycloak in Chromium (docs/INSTALL-COMPOSE.md) |
| Durable job runner (ADR 0006, accepted, provisional) | verified (single-effect jobs) | job::*, metrics, operations API; no operations UI, no multi-step workflows |
| CI pipeline | verified | `scripts/ci/run.sh` on GitHub Actions for pull requests and `main` (since 2026-10-22), and locally with a declared environment (runs 23, 24). Updated 2026-10-23; until then this row said hosted CI had never run |

### Phase B: Ingestion and inventory - incomplete (core verified)

| Item | State | Evidence / gap |
|---|---|---|
| Import pipeline, resume, replay safety, coverage, quarantine | verified | ing::, sync::, ingjob:: (ADR 0009) |
| Asset correlation with explicit uncertainty | verified | Merge and split execution **not built** |
| Business context: source tags and user assertions | verified | sync::, ppo::, jrn:: |
| Trivy JSON, SARIF 2.1.0 | **fixture-tested** | Real Trivy 0.76.1 output; real CodeQL and Semgrep output not tested |
| Tenable export, Azure Resource Graph | **fixture-tested** | Synthetic data, local fakes; no live validation |
| Webhooks, connector health metrics and UI | not started | Freshness now appears in reports (ING-10 partial) |

**Phase B gate:**
* Repeat import is stable: met.
* Partial ingestion is visible: met.
* Ambiguous assets stay separate: met.
* Live access validates the advertised operations: **not met**, because there are no vendor accounts.

### Phase C: Investigation and prioritisation - incomplete

| Item | State | Evidence / gap |
|---|---|---|
| Versioned policies (priority, ownership, SLA, freshness) with independent publishing | verified | ppo::test_publishing_needs_a_second_person_and_supersedes (service and DB) |
| Deterministic prioritisation command and recorded override | verified | ppo::, jrn::; direct database priority injection removed from tests |
| Evidence snapshots, model gateway, investigation runs, tools, claims, human review | verified against the fake | inv::, adv::, invu::, eval:: (ADR 0012); real provider unverified |
| Evaluation harness (policy vs AI-assisted vs reference, regression split, security-boundary arm) | implementing | eval::, evaluation/report.py; **no held-out set** (evaluation/EXPOSURE.md); blind review package and comparison tool; independent review pending |
| Priority impact preview, override expiry | verified | ovr::, ui::test_policy_preview... (ADR 0011 amendment); second approver not built |
| Claim checks described precisely; scan-time ordering; unresolved contradictions kept for people | verified (fake) | inv::, adv::, invu:: (ADR 0012 amendment) |
| Authority-aware decision trigger (system identities record only policy-authorised results) | verified | ovr::, sab:: (migrations 0014 and 0016: real bindings checked, workload roles only; ADR 0012 amendment 2) |

### Phase D: Remediation and GRC lifecycle - incomplete (action, risk, ownership, SLA, reporting verified)

| Item | State | Evidence / gap |
|---|---|---|
| Action proposals, approvals, reservations, idempotency, effect gate, reconciliation | verified against fakes | act::, act_api::, wf:: (ADR 0010) |
| Jira-style, ServiceNow, GitHub Issues ticket integrations | **fixture-tested** | Local fakes only |
| Two-step risk acceptance, R7, per-class permissions | verified | risk2::, r7::, act:: |
| Inbound ticket synchronisation (polling) | verified | track::, wf::; webhooks not built |
| Ownership routing | verified | ppo:: (ADR 0011) |
| SLA timers v2 | verified | sla::; targets provisional (D-SLA-2) |
| Report snapshots (as-of, coverage, freshness, unknowns) and exports | verified | rpt::, track::, jrn:: |
| Auditor evidence packages, classification-aware | verified (API) | rpt::test_evidence_package..., jrn:: |
| Verification worker (VER-04) | **fixture-tested** | vw::, vcu::, vdst::, vlc:: (ADR 0014 and amendment 1: destination policy, pinned connections, request-bound responses, lifecycle); local TLS fixture endpoints, plus the opt-in demonstration against a local Trivy-rescan check service (docs/DEMO.md); closing after a pass stays human |
| Approved ticket automatically advancing the case | not built by design so far | The owner records the ticket as external work (CASE-07) |
| Pull requests, production change | not started | Production change disabled by design |
| Framework mappings, portfolio reports, attestations | not started | RPT-04, RPT-07, RPT-08 |

**Phase D gate** (Plan 8). The journey test (jrn::) runs over HTTP and covers:
* ingestion of real scanner output;
* context and ownership;
* versioned priority;
* an approved ticket in the **fake** tracker;
* external status;
* verification of the deployed digest;
* closure;
* a report with its coverage limits.

The redeploy record and the rescan evidence are supplied manually in the journey test (the verification worker, added at checkpoint 7, is tested separately against a fixture endpoint). Unknown action outcomes reconcile safely, which is
met against fakes only.

### Phase E: Integration breadth - not started
Seven catalogue integrations are fixture-tested and 13 are planned. None is sandbox-validated or production-supported.

### Phase F: Production operations and evaluation - not started (restore detection drills only)

| Item | State | Evidence / gap |
|---|---|---|
| Restore detection: fingerprint and external witness | verified with documented blind spots | rw::, s3w::, drills; ADR 0010 |
| Witness pruning invariant | verified (algorithm) | prune::, s3w:: (SeaweedFS); production storage unverified |
| Backup procedure, RPO/RTO drill, Helm/AKS, traces, retention and deletion, evaluation | not started | |
