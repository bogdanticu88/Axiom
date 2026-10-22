# Evidence-backed Vulnerability Management Platform
## Behavioural specification and architecture baseline
Date: 21 October 2026
Status: agreed behavioural baseline with proposed implementation design.
Working title only. This document specifies a complete platform target; it does not claim implemented functionality, certified compliance, or measured superiority.

## 1. Product purpose and scope
Ingest security findings, establish asset and business context, investigate using deterministic checks and constrained AI, propose defensible priorities, obtain approvals, coordinate remediation, verify outcomes, and report from recorded evidence.
The target is a fully working operational platform. Implementation phases partition delivery, not the intended feature set.
Support infrastructure, application, dependency, container, cloud configuration and dynamic application findings. Support single-organisation installations and enforced tenant boundaries for shared deployments.
Production mutation is a separately authorised capability. Automatic exploitation is outside the baseline.

## 2. Non-negotiable invariants
B01 Original observations remain distinguishable from conclusions and human decisions.
B02 Every consequential decision references its evidence snapshot, applicable policy version and actor authority.
B03 Missing, stale or contradictory evidence cannot by itself justify dismissal, priority reduction or verified closure.
B04 A failed or partial synchronisation never implies remediation.
B05 Untrusted findings, source files and retrieved content cannot grant authority, change policies or select unrestricted tool destinations.
B06 All records, jobs, objects, credentials, caches and model requests enforce tenant boundaries.
B07 Approvals bind to the exact action, arguments, resources, tenant, validity period and permitted use count.
B08 Unknown external action outcomes require reconciliation before another attempt. No exactly-once guarantee is claimed.
B09 Previously recorded decisions remain retrievable after reassessment.
B10 Report figures derive from reproducible queries over an identified snapshot. Model prose cannot invent measurements.
B11 Model output is analysis; independently collected observations and authorised records are its supporting evidence.
B12 Audit commitments and event delivery use transactional mechanisms. A failed audit write must prevent a consequential state change from committing.

## 3. Core records
Every record has tenant ID, stable ID, schema version and creation time.
- SourceConnection: provider, scoped credential reference, capability declaration, health and cursor.
- IngestionRun: source, scope, observed interval, completeness, cursor, errors and raw object references.
- Observation: immutable source fact or claim, collection and source times, provenance, original evidence hash, subject and freshness.
- Asset / AssetVersion: resource identity, environment, deployment identifiers and effective interval.
- IdentityLink: candidate asset relationship, matching method, evidence, confidence category and reviewer.
- FindingOccurrence: source finding on a specific asset/component/version with stable external identity.
- FindingCase: correlated occurrences, assessment, priority, workflow, disposition and owner.
- InvestigationRun: evidence snapshot, checks, tool calls, model and prompt configuration, budget and outcome.
- Claim: proposition, supporting and contradicting observation IDs, limitations and assessment.
- PolicyVersion / Decision: deterministic rule inputs, outcome, explanation and override details.
- ActionProposal / Approval / Execution: canonical scope, preconditions, authority and external reconciliation identifiers.
- RiskAcceptance: accountable owner, rationale, affected scope, compensating controls and expiry.
- Verification: acceptance criteria, observed deployment, checks, coverage and result.
- AuditEvent / ReportSnapshot: actor and event lineage; query definitions, data cut-off and coverage.

Raw evidence is access-controlled and retained according to tenant policy. Hashes detect changes relative to trusted records; they do not prove the source claim is true. Where stronger integrity is needed, use immutable retention and independently stored signed checkpoints. Corrections append superseding records rather than silently overwriting history. Retention and deletion rules explicitly cover originals, derivatives, backups and legal holds.

## 4. State model
Assessment: unassessed | supported | not_supported | inconclusive.
Priority: pending | urgent | high | medium | low.
Workflow: received | investigating | review_required | remediation_planned | remediating | awaiting_verification | closed.
Disposition: unset | remediate | accept_risk | defer | duplicate | dismiss.
Job execution: queued | running | waiting_dependency | waiting_approval | reconciling | succeeded | failed | cancelled.
Operational job failure does not erase the case's last valid business state.

### Allowed case transitions
| From | To | Required guard |
|---|---|---|
| received | investigating | Valid scope and scheduled investigation |
| investigating | review_required | Recorded assessment, limitations and policy decision, or explicit escalation |
| review_required | investigating | Reviewer requests more evidence |
| review_required | remediation_planned | Authorised remediation decision and assigned owner |
| remediation_planned | remediating | Approved action or recorded externally initiated work |
| remediation_planned | review_required | Authorised, recorded withdrawal decision with rationale; no unresolved external effect (amendment R7) |
| remediating | awaiting_verification | Reported change with affected deployment identified |
| remediating | review_required | Verified evidence that no change was deployed; no unresolved external effect (amendment R7) |
| awaiting_verification | closed | Verification passes and authorised closure policy permits |
| awaiting_verification | remediating | Verification fails |
| awaiting_verification | review_required | Verification inconclusive or scope changed |
| review_required | closed | Approved acceptance, supported dismissal or validated duplicate, with distinct closure reason |
| closed | investigating | Relevant change, recurrence, acceptance expiry or authorised reassessment |

Amendment R7 (approved by the product owner 2026-10-22): when remediation is abandoned and a change was deployed,
partially deployed or its deployment state is unknown, the case goes through verification (remediating to
awaiting_verification on an abandoned-remediation report); verification may conclude inconclusive or failed and return
the case to review. Returning to review never bypasses an executing or unresolved external effect, which must be
reconciled first; it keeps linked tickets, approvals, consumed approval uses, action history and evidence, never closes
tickets or restores uses, and makes existing proposals for the superseded plan unable to execute.

Deferral remains open with review date and reason. Risk acceptance closes the treatment workflow but does not remove the exposure from reports. Duplicate closure retains links and original observations. Inconclusive assessments cannot close as verified remediated.
Cancellation affects a run; it cannot silently resolve a finding.
Unsupported transition requests return a structured conflict and commit no partial state change. Concurrent changes use optimistic version checks. Reopening appends an event and preserves previous closure.

## 5. Ingestion and correlation behaviour
Adapters declare supported operations and schema versions. Imports retain original files and source-specific fields, validate records and quarantine invalid input.
API synchronisation handles pagination, provider rate limits, resumable cursors and bounded backoff. Advance checkpoints only after durable writes. Replays deduplicate using tenant/source identity and observation version, not CVE alone.
Each run reports complete, partial, failed or unknown coverage for its declared scope. A deletion/tombstone from a provider is a source observation, not automatic closure.
Asset matching prefers immutable provider identifiers and deployment digests. Names, IPs and tags alone may require review. Conflicting identifiers block automatic merging. Merges and splits remain reversible through recorded links.
Correlate cases without discarding per-scanner identities or differences in scope.

## 6. Investigation and AI behaviour
1. Freeze the initial evidence and policy snapshot.
2. Determine necessary questions and approved checks.
3. Collect scoped read-only evidence; record unsuccessful checks.
4. Evaluate deterministic tests and construct supported/contradicted/unknown claims.
5. Produce schema-validated AI analysis with actual evidence references.
6. Apply deterministic priority policy and request review.
7. Preserve the run and its limitations.
Evidence references must exist and belong to the same tenant and permitted scope. Checking references does not establish that a claim follows from them; material conclusions require deterministic checks or reviewer validation.
AI cannot change ownership, accept risk, dismiss cases or mutate production through narrative output. No requirement exists to retain private model chain-of-thought; retain concise explanations, tool records and decision inputs.
Provider timeout, invalid output or budget exhaustion produces an explicit incomplete result. Fallback providers must be permitted by tenant data policy. No silent data routing.
Treat confidence as evidence completeness and supported uncertainty categories; do not invent calibrated probabilities.
New evidence can supersede a run but cannot rewrite it.

## 7. Prioritisation
Inputs can include scanner severity, affected version, exploit intelligence, exposure, reachability evidence, privileges, asset criticality and compensating controls.
Policy rules are versioned and testable. AI cannot directly set the authoritative priority.
Unknown context triggers conservative rules and evidence collection. Unsupported reachability is not evidence of unreachability.
Record all inputs, source freshness and rule outcomes. Overrides require scope, reason, actor and expiry or review date. Policies decide when overrides require a second approver.
Policy changes support impact preview before activation. Historical decisions retain their original policy.

## 8. Authority matrix
Proposed default roles, constrained further by tenant, project and asset scope:
| Role | Permitted responsibility |
|---|---|
| Viewer | Read authorised cases and reports |
| Analyst | Investigate, propose priority overrides, remediation and closure |
| Remediation owner | Update assigned work and supply change evidence |
| Approver | Approve specified action classes within delegated scope |
| Risk owner | Accept risk within documented limits |
| Policy administrator | Publish approved policies and integration configuration |
| Auditor | Read authorised evidence and decision history without mutation |
| Integration identity | Execute only declared synchronisation operations |
| Investigation worker | Use allowlisted tools with job-scoped credentials |

Administration does not automatically grant risk acceptance or production change authority. High-impact decisions prohibit self-approval by default. Emergency access is time-limited, attributable and retrospectively reviewed. Support and service operators have no implicit tenant evidence access.

## 9. Remediation and external effects
Proposals include exact scope, intended change, preconditions, owner, rollback guidance where applicable and verification criteria.
Execution rechecks authorisation, revocation, approval validity and relevant resource version immediately before the effect.
Use durable action intent, provider idempotency keys where available and reconciliation records. External ticket closure does not close the platform case.
Material changes invalidate approval. Credentials remain server-side, scoped and short-lived where possible.
Automatic production mutation requires a separately enabled policy and execution integration. Normal operation can collect evidence and coordinate remediation without that capability.

## 10. Verification and reassessment
Verification identifies the deployed asset/version and tests the original condition plus applicable acceptance criteria.
Results: passed | failed | inconclusive. Unavailable systems or incomplete scans produce inconclusive, not passed.
Changes in deployment, exposure, exploit intelligence, ownership or exception validity can enqueue reassessment. Deduplicate event storms without losing relevant triggers.
The interface distinguishes verified remediated, accepted risk, dismissed, duplicate and retired asset. Asset retirement needs independent lifecycle evidence and does not count as a fix.

## 11. GRC and reports
Capture approved policies, decisions, exception expiry, owner attestations and evidence provenance. Framework mappings are versioned references to relevant requirements; they are not certification or compliance verdicts.
Reports show as-of time, source coverage, freshness, unresolved ownership, inconclusive cases and accepted exposure.
Define denominators explicitly: unique cases, source occurrences and assets are different measures. Preserve historical snapshots to avoid changing old reports after deduplication or asset merges.
AI-written summaries cite case/query identifiers; quantities must match snapshot calculations.

## 12. Complete integration target
Proposed catalogue, subject to actual licensed access and validated vendor capabilities:
- Infrastructure: Tenable, Qualys, Rapid7 InsightVM.
- Application and packages: CodeQL, Semgrep, Snyk, Trivy; generic SARIF.
- DAST: OWASP ZAP, Burp Suite DAST.
- Cloud: Defender for Cloud and Azure Resource Graph; AWS Security Hub and resource inventory.
- Workflow/context: Jira, ServiceNow, GitHub and structured business inventory imports.
Scanner, asset-context, threat-intelligence and action adapters are separate interfaces.
Supported status requires representative fixtures plus live contract validation for advertised API operations. Track supported versions, limits, scopes, permissions and evidence losses. Do not advertise all vendor capabilities simply because one report format parses.
Commercial API access, licensing and exact vendor editions remain validation dependencies.

## 13. Proposed architecture
React/TypeScript UI; Python/FastAPI modular API; PostgreSQL operational records; S3-compatible evidence storage; durable workflow engine; independently scalable integration and investigation workers.
Use transactional outbox/inbox patterns for durable event publication and consumer deduplication. Engine selection is an architecture decision after retry, approval and recovery requirements are exercised.
Model gateway enforces approved providers, redaction, schema validation, usage budgets and observability.
Docker images package components. Compose provides a complete single-host installation. Helm supports Kubernetes with external managed data services.
Production deployment includes workload identity, scoped secret retrieval, network policies, restricted service accounts, resource limits, health checks and independent worker scaling.
Disposable execution environments have explicit egress rules and no ambient production credentials. Container or Kubernetes boundaries alone are insufficient for hostile code; stronger execution isolation must be selected before that capability ships.
AKS is a proposed reference deployment, with cloud-neutral application interfaces.
Witness may be an optional evidence provider. The platform must run without it.

## 14. Security and operations
OIDC SSO; scoped RBAC; tenant isolation at API, database, worker, object and cache boundaries; encryption; secret rotation; permission revocation and access logging.
Define data classification and residency before transmitting source code or raw evidence to models. Redact before logging or provider submission; retain raw originals only within authorised storage.
Support retention, export, tenant deletion and auditable legal holds. Backups must follow the documented deletion lifecycle.
Deliver metrics, traces, connector freshness alerts, worker health, model cost monitoring, database migrations, backup/restore procedures and disaster recovery exercises.
Proposed acceptance targets, to validate by deployment profile: internal API monthly availability 99.9%; production RPO 15 minutes and RTO 4 hours. External provider outages are separately measured and still surfaced. Workload volume, latency and cost targets remain to be established with representative datasets.

## 15. Acceptance scenarios
A01 Reimport the same report and replay its job: no duplicate occurrences, decisions or external actions.
A02 Fail after an external ticket is created but before acknowledgement: reconcile to the existing ticket or pause; never blindly repeat.
A03 Complete only half a scan: retain existing cases, show partial coverage, close none merely due to absence.
A04 Supply conflicting asset identifiers: require review; do not merge across tenants or deployments.
A05 Place malicious instructions in scanner descriptions: no changed policy, authority or destination.
A06 Submit a model conclusion citing a nonexistent observation: reject the result as invalid.
A07 Remove evidence access or revoke approval before execution: deny the action and record why.
A08 Change proposal arguments after approval: require new approval.
A09 Close an external ticket without deployment proof: retain awaiting-verification state.
A10 Lose a connector or model: preserve work, expose dependency failure, resume within bounded retry policy.
A11 Expire risk acceptance: reopen review and notify the accountable owner.
A12 Restart workers at each durable workflow boundary: recover without lost decisions or unauthorised repeated effects.
A13 Attempt cross-tenant access through API, jobs, object paths, exports and caches: deny and audit.
A14 Change policy after an assessment: retain old decision and produce a separately versioned reassessment.
A15 Restore backup: demonstrate documented RPO/RTO and reconcile pending external effects before resuming them.
A16 Generate a report: reproduce quantities from its frozen snapshot and disclose missing coverage.
A17 Submit concurrent contradictory decisions: one valid version commits; the other receives a conflict.
A18 Report fix against the wrong image digest: verification remains inconclusive or failed.
A19 Fail the audit persistence transaction: consequential transition does not commit.
A20 Delete tenant data: apply retention and legal-hold rules, terminate access and track backup expiry.

## 16. Evaluation and completion gates
Use labelled cases spanning true findings, unsupported findings, ambiguous evidence, stale context, contradictions and malicious input.
Compare with scanner severity alone, deterministic policy alone and human-reviewed reference decisions. Separate held-out evaluation data from development fixtures.
Measure missed urgent exposures, unsupported dismissals, claim/evidence correctness, priority agreement, correction rate, verified-fix accuracy, analyst time and investigation cost.
Publish sample sizes, limitations and failure cases. Do not claim state-of-the-art performance without comparative evidence.
Completion requires: all core workflows operational; advertised adapters validated; permission and adversarial suites pass; restore and crash-recovery exercises pass; operational documentation and deployment paths verified; evaluation results reviewed against agreed thresholds.
Numerical quality thresholds must be set using the labelled dataset and risk tolerance before release; this document does not invent validated values.

## 17. Remaining design decisions
- Product name, distribution licence and commercial packaging.
- Single-tenant-only first deployment versus shared multi-tenant operation; tenant boundaries remain mandatory.
- Supported vendor editions and accessible test accounts.
- Workflow engine, approved model providers and offline/local model requirements.
- Expected asset/finding volume, concurrency, retention and deployment resource budget.
- Exact prioritisation policy, approval thresholds and evaluation release thresholds.
These decisions refine implementation; they do not reduce the agreed complete platform scope.

