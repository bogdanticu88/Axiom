# Implementation status

Last updated: 2026-10-22 (foundation checkpoint). Requirement-level detail is in REQUIREMENTS.md.

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
| Workflow engine spike and ADR | **experimental / pending** | Temporal experiment passed 9/9; PostgreSQL-backed comparison in progress; ADR 0006 pending |
| CI pipeline | not started | DEP-08 |
| Phase A ADRs (workflow engine, isolation, evidence retention) | incomplete | 0002 and 0005 written; 0006 pending; retention rules not yet decided |

**Phase A gate** (Plan 8): tenant isolation tests pass (met); audit failures roll back commands (met); object
finalisation is safe (met for API-streamed uploads); workflow survives crash/restart and approval waiting without
duplicate action (**not met in product code**: shown only in the Temporal experiment).

## Phase B: Ingestion and inventory - not started
Generic import pipeline, Tenable, Trivy, SARIF, Azure context, asset history, deduplication, quarantine, connector
operations UI. Schema has minimal `assets`, `asset_versions`, `finding_occurrences` and links used by case verification.

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
| Ingestion, correlation, connectors | not started |
| Investigation, model gateway, policy engine | not started |
| Reporting, GRC, exports | not started |
| Web UI | not started |
| Helm, AKS, observability, backup/restore, retention | not started |
| Evaluation dataset and benchmarks | not started; release thresholds blocked on a business decision |
