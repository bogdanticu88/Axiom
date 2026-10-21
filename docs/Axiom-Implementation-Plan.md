# Axiom: Implementation Plan
Date: 21 October 2026
Status: proposed implementation design derived from the agreed behavioural specification.
Companion: Axiom-Specification.md.
This plan specifies delivery of the complete platform. A completed phase is an engineering checkpoint, not a claim that the entire product is ready.

## 1. Architecture decisions
Use a modular application with separate worker deployments, not a service per domain.
Proposed baseline: React/TypeScript UI, Python/FastAPI API and adapter layer, PostgreSQL, S3-compatible object storage, Temporal durable workflows, OIDC and Kubernetes/Helm.
Temporal is a candidate requiring a recovery and approval spike before commitment. Verify supported versions and licensing against official documentation during dependency selection. Avoid adding a second task queue unless a demonstrated requirement justifies it.
Use PostgreSQL relational edges for asset relationships initially. Introduce a graph database only if measured query requirements justify its operational cost.
Use PostgreSQL search first. Vector search is optional retrieval support and never an authoritative evidence store.

### Deployable components
| Component | Responsibility | Authority |
|---|---|---|
| UI | Case review, approvals, evidence inspection, operations | Delegated user session |
| API | Authorisation, validated commands, queries and transactions | Scoped application identity |
| Integration worker | Inventory, findings, intelligence and ticket synchronisation | Per-connection credentials |
| Investigation worker | Evidence plans, approved checks and model analysis | Per-job tool grants |
| Action worker | Approved ticket/PR operations and separately enabled changes | Exact action grant |
| Verification worker | Collect outcome evidence against acceptance criteria | Scoped check credentials |
| Workflow engine | Durable orchestration, timers, signals and recovery | Dispatch only; no implicit target access |
| Model gateway module | Routing, redaction, schemas, budgets and usage | Approved provider credentials |

Components can share a codebase. Worker task queues and runtime identities remain separate. Scheduler behaviour uses durable workflow timers where appropriate.

## 2. Repository layout
- apps/web: browser application.
- backend/platform/api: HTTP routes and authentication.
- backend/platform/domains: assets, ingestion, cases, investigations, policies, actions, verification, reporting and tenancy.
- backend/platform/workflows: orchestration with deterministic workflow code.
- backend/platform/adapters: scanner, context, intelligence, workflow and evidence-provider interfaces.
- backend/platform/tools: constrained investigation checks.
- backend/platform/model_gateway: provider adapters and data policies.
- backend/platform/persistence: migrations, repositories, outbox and object references.
- contracts: versioned schemas and generated OpenAPI.
- deployments/compose and deployments/helm.
- tests/contracts, integration, acceptance, isolation, adversarial, recovery and evaluation.
- fixtures: synthetic/redacted vendor samples with origin and licence metadata.
- docs/adr, runbooks, threat-model and operator-guide.
Keep model calls and external IO outside deterministic workflow execution.

## 3. Transaction and evidence boundaries
PostgreSQL owns business state and its version. Object storage owns evidence bytes. The workflow engine owns orchestration progress, not authoritative business decisions.
An API command validates scope and expected version, commits state and audit event atomically, and writes an outbox entry.
Consumers track processed message identities. Delivery is at least once.
Evidence upload creates a pending record, uploads bytes, verifies size/hash, then finalises the reference. Unfinalised evidence cannot support consequential decisions.
Reads enforce tenant and evidence classification. Never expose arbitrary object-store paths.
Object writes use tenant-scoped namespaces and restricted identities. Buckets alone are not an authorisation mechanism.

## 4. API contract conventions
All endpoints are versioned under /api/v1.
Derive tenant and actor context from validated authentication and authorised selection; do not trust body fields as authority.
Mutating commands accept expected record version. External-effect commands require an idempotency key and persist its request digest and outcome.
Return structured errors: code, safe message, correlation ID and retryability. Use 409 for stale state/transition conflicts; separate permission denial from dependency failure without leaking hidden records.
Long-running work returns 202 and a job/run reference.
Use cursor pagination, bounded exports and auditable download access.

### Core API groups
| Group | Representative commands |
|---|---|
| Connections | Create configuration, test access, rotate secret reference, request sync |
| Imports | Initiate upload, finalise verified upload, inspect ingestion run/quarantine |
| Assets | List versions, inspect links, propose/approve merge or split |
| Cases | Query, assign, investigate, propose disposition, inspect history |
| Investigations | Inspect claims/evidence/tool outcomes, cancel a run, request additional checks |
| Policies | Draft, validate, simulate, approve/publish, inspect impact |
| Actions | Propose, approve/reject, execute, revoke, reconcile |
| Risk | Request acceptance, authorise, renew, expire |
| Verification | Define criteria, request run, inspect outcome |
| Reports | Create immutable snapshot, inspect coverage, export |
| Operations | Job health, dependency status, audit access, recovery controls |

State changes use explicit domain commands rather than a generic unrestricted status PATCH.

## 5. Adapter contracts
Scanner adapter: capabilities(), validate_config(), discover_scope(), fetch_page(cursor), normalise(record), health().
Context adapter: resolve_assets(), collect_versions(), collect_relationships(), collect_ownership() with provenance and scope.
Intelligence adapter: retrieve records with retrieval time, licence constraints and feed version.
Workflow adapter: create_or_reconcile(), update_with_version(), fetch_external_state(), handle_authenticated_event().
Evidence provider: execute typed check against explicit subject and grant; return observations, errors and coverage.
All APIs are conceptual interfaces, not vendor capability promises.

Every adapter includes:
- Configuration and least-privilege permission documentation.
- Redacted fixtures, field mapping, missing-field semantics and schema version handling.
- Limits, pagination, partial-success behaviour and bounded retry classification.
- Live contract tests for advertised operations.
- Replay, stale data, token expiry and duplicate event tests.
- Capability status: planned, fixture-tested, sandbox-validated or production-supported.
Never turn unsupported or unknown values into false.

## 6. Investigation contract
Input: case and asset version references, frozen evidence/policy snapshot, explicit questions, tool grant, deadline and cost budget.
Output: structured claims with evidence and contradictions, unresolved questions, check coverage, proposed remediation and concise rationale.
Priority is applied by policy after validation.
Tools receive typed arguments and registered destinations. URL fields from reports cannot directly drive unrestricted outbound requests.
Limit call count, response bytes, execution duration, parallelism, provider spend and recursion.
Record tool principal, requested subject, actual destination, time and result digest. Redact secrets.
Investigators cannot self-approve, publish policy, grant themselves tools or accept risk.
Evidence and action plans are independently validated before use.

## 7. External action protocol
1. Persist canonical proposal and effect classification.
2. Obtain matching unexpired approval when required.
3. Recheck current actor/service authority and target preconditions.
4. Persist execution intent with stable external operation identity.
5. Execute using provider idempotency if available.
6. Record observed result or unknown outcome.
7. Reconcile unknown outcome; require operator intervention if uniquely identifying the effect is impossible.
8. Append verified external reference and complete workflow.
An approval is not reusable for a changed resource, scope or payload. Do not promise exactly-once execution.
Ticket creation can be policy-automated independently of infrastructure change permissions.

## 8. Delivery phases and gates
### Phase A: Foundation and recovery contracts
Deliver repository, schemas, tenancy, OIDC/RBAC, migrations, audit/outbox, evidence upload, Compose, CI and workflow engine spike.
Gate: tenant-isolation tests pass; audit failures roll back commands; object finalisation is safe; workflow survives crash/restart and approval waiting without duplicate action.
Produce ADRs for workflow engine, isolation and evidence retention.

### Phase B: Complete ingestion and inventory subsystem
Deliver generic import pipeline, Tenable/Trivy/SARIF, Azure asset context, asset history, deduplication, quarantine and connector operations UI.
Gate: repeat import is stable; partial ingestion is visible; ambiguous assets stay separate; live access validates advertised API operations.
This phase does not complete the platform.

### Phase C: Investigation and prioritisation
Deliver constrained tools, provider gateway, policy engine, structured claims, analyst review UI, snapshotting and reassessment.
Gate: deterministic fixtures reproduce decisions; fabricated evidence references fail; malicious inputs cannot expand tools; missing evidence cannot cause dismissal.
Publish evaluation baseline against scanner severity and policy-only prioritisation.

### Phase D: Remediation and GRC lifecycle
Deliver Jira/ServiceNow/GitHub integrations, approvals, ownership, expiring risk acceptance, SLA timers, verification and immutable report snapshots.
Gate: demonstrate ingestion through approved ticket, deployed fix verification, closure and recurrence; unknown action outcome reconciles safely.
No acceptance based solely on ticket closure.

### Phase E: Integration breadth
Deliver Qualys, Rapid7, Semgrep, Snyk, ZAP, Burp, Defender for Cloud and AWS Security Hub/inventory, with remaining context and intelligence integrations.
Gate: each advertised adapter meets its support contract. Record separately any integration blocked by vendor access; do not declare complete support.
Verify current vendor API details before coding each connector.

### Phase F: Production operations and evaluation
Deliver Helm/AKS reference deployment, workload identities, network controls, restore automation, observability, upgrade procedures, capacity testing, complete documentation and independent acceptance run.
Gate: all behavioural acceptance scenarios pass; restore meets adopted objectives; supported connectors validated; numerical quality thresholds met on held-out data.
Production changes remain disabled unless their separate execution/isolation controls are implemented and accepted.

## 9. User journeys required for release
- Operator installs platform, configures SSO and scoped integrations, checks ingestion health.
- Analyst reviews a correlated case and follows every material conclusion to evidence.
- Asset owner corrects ownership or business importance with a recorded effective date.
- Approver reviews exact remediation scope and authorises or rejects it.
- Risk owner accepts scoped exposure with a reason and expiry.
- Remediation owner supplies deployment evidence and requests verification.
- Verifier confirms or rejects resolution against the correct deployment.
- Auditor reconstructs a decision and exports an evidence package.
- Manager inspects verified risk reduction, accepted exposure and missing coverage.
- Operator restores a backup and reconciles uncertain external actions before resuming them.
All journeys must work through supported APIs and UI, with access control and failure paths.

## 10. Validation strategy
Use contract tests for adapters; database-backed integration tests for invariants; end-to-end tests for user journeys; fault injection for durable actions; isolation tests across all storage and execution paths.
Maintain a separate labelled evaluation dataset with blinded reference review and recorded disagreements.
Track urgent exposures missed, unsupported dismissals, evidence correctness, verified closure accuracy, reviewer effort and cost.
Release thresholds and benchmark volume must be decided before results are used as release evidence.
Do not substitute a large unit-test count for lifecycle and recovery evidence.

## 11. Deployment requirements
Compose must start a functional platform with documented development identity and synthetic data; insecure defaults must not silently carry into production.
Helm must support external PostgreSQL, object storage, identity provider and workflow services, restricted workloads, signed/pinned images, backup integration and configurable tenant data policies.
Deploy API and worker queues independently. Size capacity from measured workload.
Specify upgrade compatibility between schema, API, workflow histories and connector versions. Rolling back binaries does not imply database downgrade safety.

## 12. Decisions to settle before implementation commitment
- Decided: support both a shared multi-client consulting installation and dedicated enterprise installations. Scale and capacity targets remain to be measured.
- Decided: shared tenancy is a first production requirement. Dedicated installations use the same application with one customer tenant; no separate product fork.
- Model/data residency constraints and approved providers.
- Vendor credentials and licences available for integration validation.
- Prioritisation policy owner, approval delegation and separation-of-duty rules.
- Retention and deployment cost envelope.
- Release quality and performance thresholds.
Use written ADRs for unresolved choices. Do not treat a convenient local development default as an enterprise requirement.

## 13. Definition of finished
The complete platform is finished only when all required user journeys, supported integration commitments, security boundaries, recovery exercises, reporting accuracy checks and evaluation gates are satisfied.
A demo, a collection of parsers, or model-generated tickets alone does not satisfy this definition.


## 14. Approved deployment and tenancy decision
Decision: support both shared multi-client and dedicated enterprise installations. Approved by the project owner on 21 October 2026.

- A tenant is a customer data and authority boundary. Projects, accounts and environments are scopes inside it.
- An installation can host multiple customer tenants or one customer tenant. Identical domain contracts apply in both modes.
- Users may belong to multiple tenants through explicit memberships; every request and background job has exactly one active tenant context. Switching tenants requires fresh authorisation.
- Client evidence, credentials, integration cursors, investigations, approvals, policies, model requests and reports remain tenant-scoped.
- Consulting operators receive explicit client memberships and delegated roles. Installation administration does not grant routine access to client evidence.
- Cross-client portfolios use a separate authorised aggregation path. They must not bypass row-level permissions or expose raw client evidence by default. Every included metric retains its source tenant and coverage.
- Customer-specific provider, residency, retention and approval policies are enforced. A policy requiring stronger physical or regional separation routes that client to a dedicated deployment.
- Shared mode must isolate quotas and concurrency so one tenant cannot monopolise connectors, investigation workers or model budgets.
- Dedicated mode supports customer identity, secrets and managed infrastructure without maintaining a fork.
- No cross-client training or retrieval corpus is enabled by default. Any shared intelligence requires separately authorised, documented data handling.

Acceptance additions: run identical lifecycle tests in shared and dedicated profiles; test users with multiple memberships, stale tenant context, background job tampering, export paths, shared caches, object access and administrative access. Exercise per-tenant quotas and model/data policies.

Proposed mechanism, pending ADR validation: PostgreSQL row-level security plus application authorisation, transaction-scoped tenant context, composite tenant-aware references, tenant-scoped object access and distinct service privileges. Migration roles are separated from runtime roles. Table owners, superusers and roles with BYPASSRLS are not runtime application identities. Test connection-pool context reuse explicitly. This mechanism is a proposal, not a completed isolation guarantee.
