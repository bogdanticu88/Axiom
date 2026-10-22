# Implementation status

Last updated: 2026-10-22 (Phase B checkpoint). Requirement-level detail is in REQUIREMENTS.md.

Capability states used here:
**verified** (built and exercised by tests that were run), **implemented** (built, not yet exercised),
**experimental** (throwaway experiment, not product code), **incomplete** (partly built), **blocked**, **not started**.

## Phase A: Foundation and recovery contracts

| Item | State | Evidence / gap |
|---|---|---|
| Repository, layout, design inputs preserved | verified | ADR 0001; commit 6ef0e0d holds the archive unmodified |
| Cluster role provisioning, ledgered migrations | verified | Fresh cluster, two databases, re-migration, edited-checksum rejection (VERIFICATION.md run 1) |
| Tenancy schema: tenants, scopes, memberships, roles, bindings, delegation limits | verified | iso::, cases:: tests |
| Transaction-bound tenant context, forced RLS, composite FKs | verified | ADR 0002; iso:: tests |
| Authentication | **incomplete** | Development token authentication verified; **production enterprise OIDC/SSO not implemented** (ADR 0008) |
| Scoped permissions, hierarchy, expiry, revocation, delegation rules, emergency access | verified | unit::, cases::test_tenant_admin..., ::test_permission_scope... |
| Case commands with optimistic concurrency and DB guards | verified | cases:: (27 tests), iso::test_direct_sql... |
| Atomic audit, events and outbox; leased relay; inbox dedupe | verified | B12/A19 tests, evo::test_outbox..., ::test_concurrent_relays... |
| Evidence upload, finalisation, classified audited reads, tamper detection | verified | evo::, s3:: |
| HTTP API (/api/v1) | verified for implemented endpoints | api:: tests and Compose smoke |
| Compose single-host install | **incomplete** | PostgreSQL, SeaweedFS, init, API and job worker verified by fresh-install smoke; UI and real IdP not included |
| Workflow engine decision (ADR 0006) | **accepted** | PostgreSQL-backed runner chosen on the project owner's "Proceed"; Temporal is the named alternative with revisit triggers |
| Durable job runner `axiom.jobs` | **verified (single-effect jobs)**; operations API, metrics and CI added (see Phase D and ADR 0006 condition table) | job::* (24 tests incl. real SIGKILL and pg_dump/pg_restore drill), mutation-check log; leases capped at step deadline, claim counter dead-letters poison jobs, fenced results, per-tenant cap, version pinning and migration, cancellation, operator tooling, effect gate with intents, lookup-before-create, operator parking and restore detection. **Not built:** an operations UI, hosted CI execution, multi-step workflows, cancellation after an external call has started |
| CI pipeline | not started | DEP-08 |
| Phase A ADRs (workflow engine, isolation, evidence retention) | incomplete | 0002, 0005 and 0006 (accepted) written; retention rules not yet decided |

**Phase A gate** (Plan 8): tenant isolation tests pass (met); audit failures roll back commands (met); object
finalisation is safe (met for API-streamed uploads); workflow survives crash/restart and approval waiting without
duplicate action (**met for single-effect jobs with a fake integration**: job::test_sigkill_after_effect_before_outcome_recorded,
job::test_wait_then_done; approval records themselves are Phase D, so approval waiting is shown with `Wait`, not real approvals).

## Phase B: Ingestion and inventory - incomplete (core verified)

| Item | State | Evidence / gap |
|---|---|---|
| Import pipeline: runs, fenced page commits, resume, replay safety | verified | ing:: tests incl. real SIGKILL resume; ADR 0009 |
| Original evidence preservation and re-verification | verified | ing::test_tampered_original_fails_the_run |
| Source identities, observations, occurrence history | verified | ing::test_replayed_import..., ::test_partial_scan... |
| Quarantine and partial-import coverage | verified | ing::, sync::, API quarantine listing |
| Asset correlation with explicit uncertainty (strong/weak identifiers, candidates, review decisions) | verified | strong conflicts and weak overlaps; merge/split execution **not built** |
| Case correlation and recurrence reopening | verified | ing::test_recurrence_after_verified_closure_reopens |
| Trivy JSON | verified at **fixture-tested** level | real Trivy 0.76.1 output |
| Generic SARIF 2.1.0 | verified at **fixture-tested** level | real Trivy SARIF + synthetic; real CodeQL/Semgrep not tested |
| Tenable export (parser + API client + sync) | verified at **fixture-tested** level | synthetic chunks, local fake API; **no live Tenable validation** |
| Azure Resource Graph context (client + sync + tag context) | verified at **fixture-tested** level | synthetic pages, local fake API; **no live Azure validation**; production credential resolution (Key Vault / workload identity) not built |
| Connections with secret references; checkpoints after complete runs | verified | sync:: tests |
| Ingestion dispatch | verified | run requests enqueue an `ingestion.run` job in the same transaction; generic worker `axiom.workers.jobs` (Compose `job-worker`); ingjob::* tests; interim dispatcher removed |
| Scheduled risk-expiry sweep | verified (scheduling) | one `cases.risk_expiry_sweep` job per tenant per hour bucket (ingjob::test_risk_expiry_sweep_is_scheduled_once...); expiry behaviour itself: cases::test_risk_acceptance_limits_owner_and_expiry_reopens; notification delivery not built |
| API: imports, runs, quarantine, connections, sync, adapters, identity candidates, asset view | verified | api:: tests, Compose smoke |
| Webhooks, connector health/freshness metrics, connector operations UI | not started | ING-08, ING-10 |
| Defender for Cloud, AWS inventory and other Phase E connectors | not started | catalogue lists them as planned |

**Phase B gate** (Plan 8): repeat import is stable (met); partial ingestion is visible (met); ambiguous assets stay
separate (met for weak overlaps); live access validates advertised API operations (**not met**: no vendor accounts,
so no adapter is advertised beyond fixture-tested).

## Phase C: Investigation and prioritisation - not started
## Phase D: Remediation and GRC lifecycle - incomplete (action protocol and risk flow verified)

| Item | State | Evidence / gap |
|---|---|---|
| Action proposals (immutable versions, DB-computed binding digest, preconditions, expiry) | verified | act::* (ADR 0010) |
| Approvals bound to version and digest; SoD in service and DB; expiry; use counts; revocation | verified | act::*, mutation checks |
| Pre-execution re-check (approver and requester authority, membership, revocation, preconditions, connection) | verified | act::test_revocation..., ::test_approver_losing_membership..., ::test_material_change... |
| Transactional use reservation; uses returned only if never attempted | verified | act::test_concurrent_reservations..., ::test_a_use_is_never_returned... |
| API idempotency keys (required on execution) | verified | act::test_idempotency..., act_api:: |
| Effect gate: capability-based repeat rule, race-safe first attempt, lost-ack and stale-worker handling | verified against fakes | act::test_lost_ack..., ::test_stale_worker_already_past_the_boundary[4 variants], ::test_two_jobs_racing..., ::test_concurrent_workers_many_executions_no_duplicates |
| Jira-style ticket integration | **fixture-tested** | local fake only; not Jira support |
| Operator reconciliation (adopt / not applied / abandon), preserves approvals, audited | verified | act::test_lost_ack_with_lagging_search..., ::test_operator_actions_are_audited..., act_api:: |
| Two-step risk acceptance: request, independent authorisation, reject, withdraw, renew, reassessment notices, lapse | verified | risk2::*, act_api::test_risk_request..., defaults D-RISK-1 |
| ServiceNow, GitHub, pull requests, production change | not started | production change disabled by design |
| SLA timers, ownership routing, inbound ticket sync, immutable report snapshots, GRC exports | not started | |

**Phase D gate** (Plan 8): ingestion through approved ticket (**met against the fake tracker only**), deployed fix
verification and closure (met in case tests), recurrence (met), unknown action outcome reconciles safely (met against
fakes; see ADR 0010 for the exact guarantee and its limits).
## Phase E: Integration breadth - not started
All 20 catalogue connectors are at "planned". None is fixture-tested, sandbox-validated or production-supported.
## Phase F: Production operations and evaluation - not started

## Capability summary

| Capability | State |
|---|---|
| Tenant isolation (DB, API, objects) | verified |
| Tenant isolation (jobs) | verified (job::test_jobs_are_tenant_isolated; RLS on all job, action and risk tables) |
| Tenant isolation (caches, search, exports, credentials, model requests) | not started (components do not exist) |
| Case lifecycle and closure routes, including asset retirement | verified |
| Request/authorise/renew risk acceptance | verified (thresholds are interim defaults) |
| Approvals and external actions in product code | verified against fakes; Jira-style integration fixture-tested |
| Restore detection | fingerprint plus external witness; blind spots tested and documented (ADR 0010) |
| Job operations (API, metrics, retry, reconciliation) and CI | verified locally; hosted CI never run |
| Production SSO | not started |
| Ingestion and correlation | verified core (see Phase B) |
| Connectors | 4 fixture-tested, 16 planned, none sandbox-validated |
| Investigation, model gateway, policy engine | not started |
| Reporting, GRC, exports | not started |
| Web UI | not started |
| Helm, AKS, observability, backup/restore, retention | not started |
| Evaluation dataset and benchmarks | not started; release thresholds blocked on a business decision |
