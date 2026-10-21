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
| Compose single-host install | **incomplete** | PostgreSQL, SeaweedFS, init and API verified by fresh-install smoke; workers, UI, workflow engine and real IdP not included |
| Workflow engine experiments and ADR | **experimental; decision proposed** | Temporal 22/22 and PostgreSQL-backed 26/26 (independent reruns); ADR 0006 recommends PostgreSQL-backed runner, awaiting confirmation; product runner not built |
| CI pipeline | not started | DEP-08 |
| Phase A ADRs (workflow engine, isolation, evidence retention) | incomplete | 0002 and 0005 written; 0006 pending; retention rules not yet decided |

**Phase A gate** (Plan 8): tenant isolation tests pass (met); audit failures roll back commands (met); object
finalisation is safe (met for API-streamed uploads); workflow survives crash/restart and approval waiting without
duplicate action (**not met in product code**: shown only in the Temporal experiment).

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
| Ingestion worker | **interim** | dispatcher pending ADR 0006; included in Compose and smoke-tested |
| API: imports, runs, quarantine, connections, sync, adapters, identity candidates, asset view | verified | api:: tests, Compose smoke |
| Webhooks, connector health/freshness metrics, connector operations UI | not started | ING-08, ING-10 |
| Defender for Cloud, AWS inventory and other Phase E connectors | not started | catalogue lists them as planned |

**Phase B gate** (Plan 8): repeat import is stable (met); partial ingestion is visible (met); ambiguous assets stay
separate (met for weak overlaps); live access validates advertised API operations (**not met**: no vendor accounts,
so no adapter is advertised beyond fixture-tested).

## Phase C: Investigation and prioritisation - not started
## Phase D: Remediation and GRC lifecycle - not started
Partial domain groundwork exists: remediation reports, verification runs, single-step risk acceptance with expiry
sweep (RISK-02 two-step flow missing), closure records.
## Phase E: Integration breadth - not started
All 20 catalogue connectors are at "planned". None is fixture-tested, sandbox-validated or production-supported.
## Phase F: Production operations and evaluation - not started

## Capability summary

| Capability | State |
|---|---|
| Tenant isolation (DB, API, objects) | verified |
| Tenant isolation (jobs, caches, search, exports, credentials, model requests) | not started (components do not exist) |
| Case lifecycle and closure routes, including asset retirement | verified |
| Request/authorise/renew risk acceptance | not started (single-step only) |
| Approvals and external actions in product code | not started (experiment only) |
| Production SSO | not started |
| Ingestion and correlation | verified core (see Phase B) |
| Connectors | 4 fixture-tested, 16 planned, none sandbox-validated |
| Investigation, model gateway, policy engine | not started |
| Reporting, GRC, exports | not started |
| Web UI | not started |
| Helm, AKS, observability, backup/restore, retention | not started |
| Evaluation dataset and benchmarks | not started; release thresholds blocked on a business decision |
