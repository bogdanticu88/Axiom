# Axiom: Data and Access Design
Date: 21 October 2026
Status: proposed logical schema and permission contract; not executed SQL.
Inputs: approved behavioural specification and implementation plan, including shared and dedicated installations.
Purpose: define database boundaries before migrations and API implementation.

## 1. Scope and naming
A customer tenant is the isolation boundary. Projects, cloud accounts, subscriptions and environments are scopes within a tenant.
An installation hosts one or many tenants. Dedicated mode follows identical domain rules.
Use UUID identifiers; tenant IDs accompany all tenant-owned primary and foreign keys.
Suggested conventions: timestamptz for instants, UTC storage, bigint record_version for concurrency, explicit text enums/checks for states, JSONB only for source extensions and versioned structured payloads.
Core searchable relationships and authorisation fields must be relational columns, not buried in JSON.
UUIDs are identifiers, not secrets or access controls.

## 2. Installation and identity tables
| Table | Key and critical columns | Contract |
|---|---|---|
| installations | id, deployment_profile, region, configuration_version | Operational configuration, no implicit customer access |
| tenants | id, installation_id, status, residency_policy_id | Customer boundary; suspended/deleting state enforced |
| identity_providers | id, tenant_id or installation scope, issuer, audience, config_reference | Explicit authentication trust |
| principals | id, kind, status | Human or workload identity; minimal global identity data |
| federated_identities | provider_id, issuer, subject, principal_id | Unique issuer/subject in trusted provider scope; no email-based account merging |
| memberships | tenant_id, principal_id, status, valid_from, valid_until | Explicit entry into a tenant |
| role_bindings | tenant_id, principal_id, role_id, scope_id, expiry | Permissions bounded by delegated scope |
| role_permissions | role_id, permission | Versioned role definitions; tenant custom roles cannot invent privileged permissions |
| scopes | tenant_id, id, kind, parent_id, resource_reference | Authorised hierarchy; no cross-tenant parent |
| delegation_limits | tenant_id, principal_id, action_class, scope_id, limit_policy_id | Financial/business risk acceptance or action bounds |
| service_grants | tenant_id, id, principal_id, job_id, tools, subjects, expires_at, revoked_at | Narrow workload authority |
| access_events | tenant_id where applicable, actor, purpose, decision, resource | Administrative and evidence access history |

Global identity tables are accessible only through narrow authentication services. Tenant memberships and role bindings are never exposed through unrestricted global searches.
Proposed baseline: membership in a tenant plus explicit scoped permission is required. Tenant selection is validated server-side, never trusted from a client header alone.
Authentication proves identity; it does not grant membership.

## 3. Integration and ingestion tables
| Table | Critical columns | Contract |
|---|---|---|
| connections | tenant_id, id, provider, scope_id, capability_version, credential_ref, status | Secrets are external references |
| connection_checkpoints | tenant_id, connection_id, stream, cursor, last_durable_run | Advance only after committed ingestion |
| ingestion_runs | tenant_id, id, connection_id, scope_snapshot, start/end, completeness, error_summary | Coverage explicit |
| ingestion_pages | tenant_id, run_id, page_identity, digest, status | Replay and pagination reconciliation |
| quarantined_records | tenant_id, run_id, raw_evidence_id, reason_code | No silent discard |
| source_objects | tenant_id, connection_id, external_id, source_version, digest | Stable source identity with version history |

Unique key for source versions includes connection, external ID and normalised source-version key. If vendor versions are absent, use a documented digest/version strategy. Never assume a CVE uniquely identifies an occurrence.
Provider webhooks need signature verification, replay protection and tenant-bound connection resolution.

## 4. Evidence tables
| Table | Critical columns | Contract |
|---|---|---|
| evidence_objects | tenant_id, id, object_key, hash_algorithm, digest, size, media_type, status, classification, retention_policy_id | pending/uploaded/verified/deleting/deleted; only verified objects support decisions |
| observations | tenant_id, id, source_object_id, evidence_id, subject_version_id, source_time, collected_at, expires_at, observation_type | Recorded source observation, not an automatic fact |
| observation_relations | tenant_id, from_id, to_id, relation | Supersedes, contradicts or corroborates |
| evidence_snapshots | tenant_id, id, created_at, manifest_digest | Frozen membership of an assessment's evidence |
| snapshot_members | tenant_id, snapshot_id, observation_id | Composite uniqueness |
| legal_holds | tenant_id, id, authorised_by, reason, scope, expires_at | Explicit hold lifecycle |
| deletion_jobs | tenant_id, id, policy_version, affected_manifest, status | Tracks originals, derivatives and backup lifecycle |

Observations are append-only during retention. Corrections create new records with supersession links. Deletion policy is explicit rather than an unrestricted SQL cascade.
Hashes provide integrity checks against trusted metadata; they do not authenticate source truth.
Evidence access uses short-lived scoped delivery or authenticated streaming. Download issuance is audited. A pre-signed URL, if used, is a short-lived bearer capability with documented revocation limitations.
A successful object deletion must not leave a report falsely implying its evidence is still available.

## 5. Asset and relationship tables
| Table | Critical columns | Contract |
|---|---|---|
| assets | tenant_id, id, asset_kind, lifecycle_status, scope_id | Stable internal entity |
| asset_identifiers | tenant_id, asset_id, namespace, external_value, valid interval | Cloud ID, image digest, scanner ID; identity rules vary by namespace |
| asset_versions | tenant_id, id, asset_id, observed_at, effective interval, deployment_digest, source_evidence_id | Immutable observed configuration/version |
| asset_relationships | tenant_id, id, from_version, to_version, kind, evidence_id, valid interval | Supports deployment/exposure paths; unknown is allowed |
| identity_candidates | tenant_id, id, left_subject, right_subject, method, evidence_snapshot, status | Ambiguous matches require review |
| identity_decisions | tenant_id, candidate_id, actor, outcome, rationale, recorded_at | Merge/split/link changes retain history |
| business_context_versions | tenant_id, asset_id, owner_principal/team, criticality, data_classification, effective interval, evidence_id | Distinguish asserted and independently observed context |
| teams / team_memberships | tenant_id and stable IDs | Ownership does not automatically grant approval authority |

Do not enforce global uniqueness on IP addresses, resource names or tags.
Asset links across tenant boundaries are prohibited. Cross-client intelligence must be a separate explicitly authorised transformation, not an asset foreign key.
A merge must preserve old identifiers and references. Findings are not silently moved to a different deployment version.

## 6. Finding and decision tables
| Table | Critical columns | Contract |
|---|---|---|
| finding_occurrences | tenant_id, id, connection_id, source_finding_id, asset_version_id, component_locator | Scanner-specific identity retained |
| occurrence_observations | tenant_id, occurrence_id, observation_id, observed_status | Finding history across scans |
| finding_cases | tenant_id, id, scope_id, assessment, priority, workflow, disposition, owner_id, record_version | Current materialised business state |
| case_occurrence_links | tenant_id, case_id, occurrence_id, linked_by_decision | Correlation reversible through history |
| investigations | tenant_id, id, case_id, snapshot_id, policy_version_id, status, deadline, budget | Runs versioned independently |
| tool_executions | tenant_id, investigation_id, tool_version, grant_id, canonical_args_digest, actual_subject, result_evidence_id, status | No plaintext secrets |
| model_executions | tenant_id, investigation_id, provider/model/prompt versions, sanitised_input_ref, output_ref, usage, status | Preserve results and concise rationale; no private reasoning requirement |
| claims | tenant_id, id, investigation_id, proposition, assessment, limitations | Structured supported/contradicted/unknown conclusion |
| claim_evidence | tenant_id, claim_id, observation_id, relation | Supporting or contradicting references |
| policy_versions | tenant_id, id, policy_family, version, definition_digest, publication_status | Immutable once published |
| decisions | tenant_id, id, case_id, policy_version_id, snapshot_id, actor_id, kind, outcome, rationale, recorded_at | Authoritative append-only history |
| case_events | tenant_id, case_id, sequence, event_type, actor, decision_id, previous/new version | Transition history |
| priority_overrides | tenant_id, case_id, decision_id, expiry/review_date, authoriser | Distinct from computed priority |

Priority requires policy provenance. Human overrides are explicit records, never an overwrite disguised as model output.
Inconclusive cases cannot acquire a verified-remediation closure reason.
Database checks validate row-local states; domain transactions validate cross-record transition guards. Avoid claiming a CHECK constraint can enforce arbitrary cross-table logic.

## 7. Actions, risk and verification tables
| Table | Critical columns | Contract |
|---|---|---|
| action_proposals | tenant_id, id, case_id, effect_class, canonical_payload, payload_digest, preconditions, expires_at, version | Immutable approved version |
| approvals | tenant_id, id, proposal_id/version, payload_digest, approver_id, authority_snapshot, valid_until, max_uses, revoked_at | Bound to exact scope and use count |
| approval_reservations | tenant_id, approval_id, execution_id, status | Concurrent reservation controlled transactionally |
| action_executions | tenant_id, id, proposal_version, idempotency_key, external_operation_id, state, grant_id | prepared/executing/reconciling/succeeded/failed/cancelled |
| external_references | tenant_id, execution_id, provider, connection_id, external_id | Maps tickets/PRs/changes without losing provider scope |
| risk_acceptances | tenant_id, id, case/scope, owner, decision_id, starts_at, expires_at, status | Authority and expiry required |
| deferrals | tenant_id, case_id, decision_id, review_at | Remains open |
| verification_runs | tenant_id, id, case_id, asset_version_id, criteria_version, snapshot_id, outcome | passed/failed/inconclusive |
| closure_records | tenant_id, case_id, decision_id, reason, verification_id or acceptance_id or duplicate_target | Reason-specific prerequisites |

Approval reservation is not proof of effect. Once execution begins, timeout cannot automatically restore a single-use approval for blind reuse. Reconciliation resolves uncertain state.
Recheck authority at execution, including revoked membership/grants and proposal expiry.
A transaction locks the proposal and approval accounting rows consistently; conflicting transitions use expected versions.
Risk expiry scheduling is durable, with a periodic reconciliation sweep to catch missed timers.
Retired-asset closure requires lifecycle evidence and is reported separately from remediation.

## 8. Reporting and operations tables
Report snapshots retain query definition/version, as-of time, evidence coverage, metric denominators, case membership and result digest.
Exports have tenant, requesting actor, authorised scope, classification, expiry and download history.
Jobs have tenant, workflow/run identity, requested scope, initiating actor, deadline, resource budget and current status.
Outbox/inbox tables use tenant and message identities with durable deduplication.
Audit events include actor, delegated identity if applicable, request correlation, action, resource, decision and time. Security-sensitive tokens are excluded.
Audit write and consequential state change commit atomically. Independent checkpoints improve tamper evidence but do not create immunity to an all-powerful operator.
Tenant quotas cover concurrent investigations, sync tasks, model spend and export size.
Installation metrics may expose aggregate health without customer payloads.

## 9. Required relational constraints and indices
- Tenant-owned referenced rows use composite foreign keys (tenant_id, id).
- Tenant-owned tables use UNIQUE(tenant_id, id) or composite primary keys.
- Scoped idempotency uniqueness includes tenant, endpoint/action class, principal as appropriate and key; same key with different payload is a conflict.
- Case event sequence unique per tenant/case.
- Published policy version unique per tenant/family/version.
- Source finding keys scoped to connection and occurrence identity, not CVE.
- Index case queues by tenant, scope, workflow, priority and due date.
- Index observations by tenant/subject/time and source identity.
- Index source sync status and durable outbox readiness.
- No unrestricted cascading delete from asset or case to evidence/audit history.
- All required domain links are constrained; polymorphic resource references require explicit validation or concrete linking tables.

## 10. PostgreSQL isolation proposal
Enable and force row-level security on tenant-owned tables; runtime roles must not own tables, be superusers or have BYPASSRLS.
Use transaction-local tenant context set only after authorisation. Missing context denies access. Test pool reuse, rollback and error paths.
Apply both row visibility and write checks. Tenant ID is mandatory, immutable through ordinary commands and included in joins.
RLS is defence in depth: an application role able to set arbitrary tenant context is not protection against total application compromise. Use narrow service credentials, authenticated workload grants and dedicated deployments for stronger isolation requirements.
Views, functions, exports and maintenance code require explicit review. Avoid broad SECURITY DEFINER helpers; validate any necessary one with fixed search path and minimal privileges.
Separate authentication lookup, runtime, migration, backup and operational roles. Worker credentials do not bypass RLS.
Background jobs resolve tenant from trusted persisted run identity, never arbitrary untrusted payloads alone.
Dedicated mode still exercises tenant checks.

## 11. Permission catalogue and defaults
Permissions are verbs on scoped resources.
| Role | Default permissions |
|---|---|
| Viewer | case.read, asset.read, report.read within assigned scope |
| Analyst | Viewer plus investigation.request, claim.review, remediation.propose, closure.propose, override.propose |
| Remediation owner | Assigned case.read, remediation.update, verification.request |
| Approver | proposal.read, action.approve for delegated effect classes/scopes |
| Risk owner | risk.accept within delegated bounds; read required case/evidence scope |
| Policy administrator | policy.draft/simulate/publish under approval policy; connection.configure with separate secret handling |
| Auditor | audit.read, report.read and evidence.read explicitly granted; no mutations |
| Tenant administrator | membership.manage and role assignment within delegation rules; no automatic evidence/risk authority |
| Installation operator | deployment/health/recovery operations; no routine client evidence permission |
| Workload principal | Explicit grant only, bounded by tenant, run, tool, subject, expiry and budget |

Evidence read is classification-sensitive, separate from viewing a case summary. Role assignment cannot grant permissions the assigning principal is prohibited from delegating.
Publishing a sensitive policy change, approving production mutation and accepting high-impact risk require independent approval according to tenant policy. Defaults prohibit self-approval in those classes.
A requester, owner or administrator is not implicitly an approver.
Emergency access uses a distinct time-bound grant with reason, audit, notification and subsequent review.

## 12. Authorisation algorithm
1. Validate identity, issuer, audience and token validity.
2. Resolve active principal and explicit tenant selection.
3. Check tenant state and active membership or workload grant.
4. Resolve resource in tenant scope without leaking other tenants' existence.
5. Evaluate permission, scope, evidence classification, delegated limits and separation of duties.
6. Recheck expiry/revocation and target version at the commit/effect boundary.
7. Commit command, decision, audit and outbox atomically where applicable.
8. Return a safe result and correlation ID.
Cache only with bounded TTL and an explicit revocation strategy. High-impact actions consult current authoritative grants; token validity alone is insufficient.
List/search/count/export paths enforce the same rules as direct reads.

## 13. Required isolation and concurrency tests
- Cross-tenant foreign key creation rejected.
- Missing context denies reads/writes; tenant switch and pool reuse do not leak context.
- Multi-membership users cannot reuse one tenant's resource, approval or evidence identifier in another.
- Object links and exports cannot bypass classification or tenant checks.
- Service identity/job payload mismatch denied.
- Tenant suspension/revocation blocks new actions and appropriately cancels waiting work.
- Concurrent approval consumption permits only authorised use; unknown effect requires reconciliation.
- Concurrent case decisions conflict rather than overwrite.
- Evidence deletion/hold races preserve documented policy.
- Installation and tenant administration cannot obtain routine evidence access without explicit grant.
- Backup restore does not silently reactivate expired grants or replay external effects.
- Portfolio aggregation excludes unauthorised tenants and classifies resulting exports.

## 14. Next implementation deliverables
1. Translate this logical design into SQL migrations and typed domain records.
2. Implement authentication context, transaction-scoped tenant handling and permission evaluation.
3. Implement evidence upload finalisation, case transitions and atomic audit/outbox.
4. Prove tenant isolation, approval concurrency and crash recovery with database-backed tests.
5. Then connect ingestion and user journeys to this foundation.
Before selecting concrete dependency versions, verify current official documentation. This design intentionally makes no unverified claims about current library APIs.

