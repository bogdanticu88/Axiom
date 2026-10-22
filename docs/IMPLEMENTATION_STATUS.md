# Implementation status

Last updated: 2026-10-22, checkpoint 3 (policies, ownership, SLA v2, reporting depth, end-to-end journey).
Requirement-level detail is in REQUIREMENTS.md.

Capability states used here:
* **verified**: built and exercised by tests that were run.
* **implemented**: built, not yet exercised.
* **experimental**: a throwaway experiment, not product code.
* **incomplete**: partly built.
* **blocked**.
* **not started**.

## Core product status against the complete register (review of 2026-10-22)

The action runner and approval protocol received most of the recent effort. The table below shows where the core
product actually stands, so that work does not hide what is missing.

| Area | State | What exists | What is missing |
|---|---|---|---|
| Ingestion | **verified core, fixture-tested sources** | Fenced, resumable import and API-sync pipeline; coverage rules; quarantine; replay safety. Trivy and SARIF use real tool output; Tenable and Azure Resource Graph use synthetic data and fakes | Webhooks; Defender and AWS; 13 catalogue sources; no source validated against a live service |
| Asset context | **verified (incomplete scope)** | Strong and weak identity; review candidates; immutable versions with digests; business context from source tags and user assertions with effective dates (0012) | Merge and split execution; asset relationships and exposure paths; CMDB import |
| Investigation | **not started** | Analysts record assessments with limitations and evidence by hand | All of Phase C: evidence snapshots, tool and model gateways, claims, schema-checked model output, adversarial suite (INVS-01..12, A05, A06) |
| Prioritisation | **verified (deterministic part)** | Versioned priority policy with independent publishing; apply command from explicit inputs, with conservative substitution recorded as limitations; recorded override; history keeps policy versions | Impact preview; override expiry and second approver; reachability and threat-intelligence inputs; any AI assistance (none exists) |
| Ownership | **verified** | Versioned rules on explicit context; unresolved queue; append-only history with overrides; re-routing when inputs change; no authority conferred | CMDB-sourced ownership; owner notifications |
| SLA | **verified (provisional targets)** | Separate triage and remediation clocks; pause on deferral; revise-not-reset on priority change; breach recorded once; accepted risk never counted as met | Business-hours calendars; other pause reasons; escalation delivery |
| Reporting | **verified (exposure summary, evidence packages)** | As-of reproducible snapshots; separate denominators; coverage, completeness and freshness per source; explicit unknowns; classification-aware auditor packages | Case membership lists in snapshots; framework mappings; GRC attestations; portfolio views; performance at volume |
| User interface | **not started** | None. Every journey is exercised over the HTTP API only | ARC-05 and all UI parts of J01 to J10 |
| Enterprise authentication | **not started** | Development token authentication with a generated key; JWKS-URI support in code | OIDC SSO integration, IdP tests and a revocation strategy (AUTHZ-14) |

Register counts (262 rows with an ID; the integration catalogue is listed separately):

| Status | Now | Previous checkpoint |
|---|---|---|
| verified | 133 | 115 |
| implementing | 56 | 47 |
| implemented_unverified | 2 | 2 |
| planned | 70 | 84 |
| blocked | 1 | 1 |

Integration catalogue: 7 fixture-tested, 13 planned, none sandbox-validated or production-supported.

## Phase A: Foundation and recovery contracts

| Item | State | Evidence / gap |
|---|---|---|
| Repository, layout, design inputs preserved | verified | ADR 0001; commit 6ef0e0d holds the archive unmodified |
| Cluster role provisioning, ledgered migrations | verified | Fresh cluster, two databases, re-migration, edited-checksum rejection (every verification run) |
| Tenancy, scoped permissions, hierarchy, expiry, revocation, delegation, emergency access | verified | iso::, cases::, unit:: |
| Transaction-bound tenant context, forced RLS, composite FKs | verified | ADR 0002; iso:: |
| Authentication | **incomplete** | Development token authentication verified; **production enterprise OIDC/SSO not implemented** (ADR 0008) |
| Case commands with optimistic concurrency and DB guards (incl. R7) | verified | cases::, r7::, iso::test_direct_sql... |
| Atomic audit, events and outbox; leased relay; inbox dedupe | verified | B12/A19 tests, evo:: |
| Evidence upload, finalisation, classified audited reads, tamper detection | verified | evo::, s3:: |
| HTTP API (/api/v1) | verified for implemented endpoints | api::, act_api::, jrn::, Compose smoke |
| Compose single-host install | **incomplete** | PostgreSQL, SeaweedFS, init, API and job worker; no UI and no real IdP |
| Durable job runner (ADR 0006, accepted, provisional) | verified (single-effect jobs) | job::*, metrics, operations API; no operations UI, no multi-step workflows |
| CI pipeline | **incomplete** | `scripts/ci/run.sh` run locally on a clean clone of the exact commit; GitHub workflow pinned to verified action commits; **never run on a hosted service** |

## Phase B: Ingestion and inventory - incomplete (core verified)

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

## Phase C: Investigation and prioritisation - incomplete

| Item | State | Evidence / gap |
|---|---|---|
| Versioned policies (priority, ownership, SLA, freshness) with independent publishing | verified | ppo::test_publishing_needs_a_second_person_and_supersedes (service and DB) |
| Deterministic prioritisation command and recorded override | verified | ppo::, jrn::; direct database priority injection removed from tests |
| Investigation workspace, tool and model gateways, claims, AI analysis | **not started** | INVS-01..12; A05, A06 |
| Priority impact preview, override expiry | not started | PRI-05, PRI-06 |

## Phase D: Remediation and GRC lifecycle - incomplete (action, risk, ownership, SLA, reporting verified)

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

The redeploy record and the rescan evidence are supplied manually. Unknown action outcomes reconcile safely, which is
met against fakes only.

## Phase E: Integration breadth - not started
Seven catalogue integrations are fixture-tested and 13 are planned. None is sandbox-validated or production-supported.

## Phase F: Production operations and evaluation - not started (restore detection drills only)

| Item | State | Evidence / gap |
|---|---|---|
| Restore detection: fingerprint and external witness | verified with documented blind spots | rw::, s3w::, drills; ADR 0010 |
| Witness pruning invariant | verified (algorithm) | prune::, s3w:: (SeaweedFS); production storage unverified |
| Backup procedure, RPO/RTO drill, Helm/AKS, traces, retention and deletion, evaluation | not started | |
