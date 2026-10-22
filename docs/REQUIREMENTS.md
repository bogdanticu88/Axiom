# Requirements register

Stable identifiers for the complete platform scope. Sources:
**S** = Axiom-Specification.md, **P** = Axiom-Implementation-Plan.md,
**D** = Axiom-Data-and-Access-Design.md, **B** = project brief of 22 October 2026,
**R** = docs/REVIEW-2026-10-22.md (review finding). Section numbers follow each document.

Statuses: `planned`, `implementing` (some parts built or verified, others not), `implemented_unverified`
(built, no test exercises it yet), `verified` (a test that was actually run exercises the behaviour; see
docs/VERIFICATION.md), `blocked`.

A requirement is not marked verified because a table, class, endpoint or placeholder exists. Where only part of a
requirement is verified, the status is `implementing` and the note says which part.

Test references are abbreviated: `cases::name` = tests/integration/test_cases.py, `iso::` = test_isolation.py,
`evo::` = test_evidence_outbox.py, `api::` = test_api.py, `s3::` = test_s3_store.py, `unit::` = tests/unit/test_rules.py,
`spike::` = experiments/workflow-spike/tests/test_scenarios.py. `job::` = tests/integration/test_jobs.py.
`act::` = tests/integration/test_actions.py. `act_api::` = tests/integration/test_actions_api.py.
`risk2::` = tests/integration/test_risk_two_step.py. `rw::` = tests/integration/test_restore_witness.py.
`r7::` = tests/integration/test_r7_return_to_review.py. `track::` = tests/integration/test_tracking_reports.py.
`wf::` = tests/integration/test_workflow_adapters.py. `s3w::` = tests/integration/test_s3_witness.py.
`ingjob::` = tests/integration/test_ingestion_jobs.py.

Last updated: 2026-10-22 (Phase B checkpoint).


## Known gaps at this checkpoint (explicit)

| Gap | Requirement IDs | State |
|---|---|---|
| Authentication is **development token authentication** (generated key, inline JWKS). No production enterprise OIDC/SSO login, IdP integration test, revocation strategy or workload identity yet | AUTHZ-14, ADR 0008 | planned |
| Job runner: no operations UI, no multi-step workflows; CI pipeline executed locally only (hosted workflow never run) | ARC-02, DEP-08, ADR 0006 | implementing |
| Action protocol is fixture-tested only: Jira-style, ServiceNow and GitHub Issues integrations have only met local fakes | INT-15..17, ADR 0010 | fixture-tested |
| Restore detection cannot see a rollback of the database **and** the witness together; the S3 witness is tested against SeaweedFS only, and its guarantees depend on production storage properties not yet validated | ADR 0010 | documented limitation |
| Not built: webhooks, merge/split execution, Defender/AWS context (Phase B remainder), investigation and AI, prioritisation (C), pull-request actions, webhooks for inbound ticket events, reporting beyond the exposure snapshot (coverage, freshness, framework mappings, evidence packages) and GRC (D), UI, Helm/AKS, observability, backup/restore, retention and deletion (F), evaluation dataset | sections 8 to 17 | planned |
| **No connector is sandbox-validated or production-supported.** Four are fixture-tested (Trivy and SARIF with real tool output; Tenable and Azure Resource Graph with synthetic data and local fakes); the other 16 are planned; commercial ones need licensed accounts | INT-01..INT-20 | fixture-tested / planned / blocked for sandbox validation |

---

## 1. Invariants (S 2)

| ID | Requirement | Implementation | Verification | Status | Notes / blockers |
|---|---|---|---|---|---|
| B01 | Original observations remain distinguishable from conclusions and human decisions | `evidence_objects`, `decisions`, `verification_runs` are separate append-only records | iso::test_append_only_tables_reject_mutation_even_for_owner | implementing | `observations` table and model-analysis records arrive in Phases B/C |
| B02 | Consequential decisions reference evidence snapshot, policy version and actor authority | `decisions.authority` JSON (bindings, roles, evaluated_at); `decision_evidence` | api::test_analyst_journey_to_verified_closure (evidence link), cases::test_decisions_record_authority | implementing | Authority and evidence verified; snapshot and policy columns null until Phase C |
| B03 | Missing, stale or contradictory evidence cannot justify dismissal, priority reduction or verified closure | `record_assessment`, `dismiss`, `verification_outcome`, `validate_closure` trigger | cases::test_definite_assessment_requires_verified_evidence, ::test_inconclusive_assessment_cannot_be_dismissed, ::test_wrong_deployment_digest_is_inconclusive, ::test_partial_coverage_... | implementing | Verified for dismissal and verified closure; priority-reduction path is Phase C; staleness needs observation freshness (Phase B) |
| B04 | Failed or partial synchronisation never implies remediation | coverage rules; absence and source fixes never touch cases | ing::test_partial_scan..., ::test_tenable_identity..., sync::test_interrupted_sync_keeps_committed_pages_as_partial | verified | |
| B05 | Untrusted content cannot grant authority, change policy or choose tool destinations | Authority only from tokens and bindings | none | planned | Investigation tools and gateway (Phase C) |
| B06 | Records, jobs, objects, credentials, caches and model requests enforce tenant boundaries | RLS, composite FKs, `TenantObjectStore`, tx-bound context | iso::*, evo::test_cross_tenant_evidence_is_not_found, api::test_cross_tenant_access_through_api_is_denied, job::test_jobs_are_tenant_isolated | implementing | Verified for database, API, object storage and jobs; credentials (secret refs only so far), caches and model requests do not exist yet |
| B07 | Approvals bind to exact action, arguments, resources, tenant, validity and use count | `approvals` FK on (version, digest); DB-computed digest; expiry, max_uses, counters guarded | act::test_approval_cannot_point_at_a_different_digest, ::test_revision_after_approval_requires_new_approval, ::test_concurrent_reservations_never_exceed_max_uses, ::test_approval_limits | verified | Tenant binding via RLS and composite FKs |
| B08 | Unknown external outcomes reconcile before retry; no exactly-once claim | EffectGate capability rules (ADR 0010), `axiom.effect_intents`, `action_executions` | act::test_lost_ack_with_lagging_search_parks..., ::test_lost_ack_adopted..., ::test_lost_ack_with_provider_idempotency..., ::test_stale_worker_already_past_the_boundary[*], job::test_sigkill_after_effect... | verified | Against local fakes only; real providers must be shown to have the declared capabilities |
| B09 | Previous decisions remain retrievable after reassessment | Append-only decisions, events, closure records | cases::test_full_lifecycle_to_verified_closure_and_reopen_preserves_history | verified | |
| B10 | Report figures derive from reproducible queries over an identified snapshot | none | none | planned | Phase D reporting |
| B11 | Model output is analysis, supported by independent observations | none | none | planned | Phase C |
| B12 | Audit and event delivery are transactional; failed audit prevents the change | Audit, case update, event and outbox in one transaction; `case_events.audit_event_id` NOT NULL FK; deferred commit guard | cases::test_audit_failure_prevents_transition, ::test_audit_failure_in_application_prevents_transition, iso::test_direct_sql_cannot_bypass_case_commands | verified | |

## 2. Acceptance scenarios (S 15) and additional scenarios

| ID | Scenario | Verification | Status | Notes |
|---|---|---|---|---|
| A01 | Reimport and replay: no duplicate occurrences, decisions or external actions | ing::test_replayed_import_creates_no_duplicates, ::test_resume_after_in_process_crash_skips_committed_pages, ::test_real_process_kill_then_resume | implementing | Occurrences, cases, events and decisions verified; external actions do not exist yet |
| A02 | Lost acknowledgement after ticket creation reconciles or pauses | act::test_lost_ack_with_lagging_search_parks_instead_of_creating_again, ::test_lost_ack_adopted_when_the_index_has_caught_up, ::test_lost_ack_with_provider_idempotency_retries_safely | verified | Jira-style fake (fixture-tested); no live tracker |
| A03 | Half a scan: keep cases, show partial coverage, close none | ing::test_partial_scan_closes_nothing_and_complete_rescan_records_absence | verified | |
| A04 | Conflicting asset identifiers require review; no cross-tenant/deployment merge | ing::test_tenable_identity..., sync::test_tenable_host_and_azure_vm..., iso::test_cross_tenant_foreign_key_rejected | implementing | Weak overlaps and strong conflicts verified; merge execution not built |
| A05 | Malicious instructions in scanner text change nothing | none | planned | Phase C adversarial suite |
| A06 | Model conclusion citing nonexistent observation is rejected | none | planned | Phase C |
| A07 | Revoked evidence access or approval before execution denies and records why | cases::test_permission_scope_and_revocation, act::test_revocation_before_execution_denies_and_returns_the_unused_use, ::test_approver_losing_membership_before_execution_denies | verified | Denial reason recorded on the execution and in job events |
| A08 | Changed arguments after approval require new approval | act::test_revision_after_approval_requires_new_approval, act_api::test_action_journey_with_idempotent_execution | verified | |
| A09 | External ticket closure without deployment proof keeps the case open | cases::test_no_closure_path_from_remediating, track::test_external_ticket_closure_is_recorded_but_never_closes_the_case, wf::test_externally_closed_ticket_never_moves_the_case[3 adapters] | verified | Polling only; webhooks (ING-08) not built; adapters fixture-tested |
| A10 | Losing a connector or model preserves work and resumes with bounded retry | sync::test_interrupted_sync..., adp::test_tenable_client_bounded_retries... | implementing | Connector part verified against fakes; model part is Phase C |
| A11 | Risk acceptance expiry reopens review and notifies the owner | cases::test_risk_acceptance_limits_owner_and_expiry_reopens, ingjob::test_risk_expiry_sweep_is_scheduled_once_per_interval_per_tenant | implementing | Reopen, notification event and hourly scheduled sweep verified; notification delivery not built |
| A12 | Worker restarts at each durable boundary: no lost decisions or repeated effects | job::test_sigkill_after_effect_before_outcome_recorded (both variants), ::test_hung_step_loses_lease..., ing::test_real_process_kill_then_resume, job::test_restore_is_detected... | implementing | Verified for single-effect jobs and ingestion; database-server crash not re-run in product code (experiment only); multi-step workflows not built |
| A13 | Cross-tenant access via API, jobs, object paths, exports, caches is denied and audited | api::test_cross_tenant_access_through_api_is_denied, evo::test_tenant_object_store_refuses_foreign_keys, iso::test_tenant_selection_and_security_events | implementing | Jobs, exports and caches not built; 404s inside a tenant are not yet audited as denials |
| A14 | Policy change after assessment keeps old decision and versions reassessment | none | planned | Phase C |
| A15 | Restore backup within RPO/RTO and reconcile pending effects first | none | planned | Phase F; needs WAL archiving profile |
| A16 | Report reproduces quantities from frozen snapshot and discloses coverage gaps | none | planned | Phase D |
| A17 | Concurrent contradictory decisions: one commits, the other conflicts | cases::test_concurrent_contradictory_decisions_one_commits | verified | |
| A18 | Fix reported against the wrong image digest stays inconclusive or failed | cases::test_wrong_deployment_digest_is_inconclusive; unit::test_verification_outcome | verified | The DB trigger also rejects a forced "passed" (observed during mutation check) |
| A19 | Failed audit persistence prevents the transition | cases::test_audit_failure_prevents_transition (DB fault), ::test_audit_failure_in_application_prevents_transition | verified | |
| A20 | Tenant deletion applies retention, legal hold, access termination, backup expiry | none | planned | Phase F |
| X01 | Identical lifecycle tests in shared and dedicated profiles (P 14) | none | planned | Dedicated single-tenant trigger exists, untested |
| X02 | Multi-membership user cannot reuse one tenant's identifiers in another (D 13) | cases::test_cross_tenant_resource_references_are_invisible, api::test_cross_tenant_access_through_api_is_denied | verified | |
| X03 | Stale or session-level tenant context does not leak (D 13) | iso::test_session_level_context_does_not_leak_into_next_transaction | verified | |
| X04 | Background job payload tenant tampering is denied (P 14, D 13) | none | planned | Outbox carries persisted tenant; worker framework pending |
| X05 | Export paths enforce tenant and classification (P 14) | none | planned | |
| X06 | Shared caches cannot leak across tenants (P 14) | none | planned | No cache exists |
| X07 | Object access is tenant-scoped (P 14) | evo::test_tenant_object_store_refuses_foreign_keys, evo::test_cross_tenant_evidence_is_not_found | verified | |
| X08 | Installation and tenant administration gain no routine evidence access (D 13) | iso::test_tenant_selection_and_security_events, evo::test_classification_permissions_and_denial_audit, cases::test_tenant_admin_delegation_rules | verified | |
| X09 | Per-tenant quotas for connectors, investigations, model budgets (P 14) | none | planned | |
| X10 | Per-tenant model and data policies (P 14) | none | planned | |
| X11 | Pool reuse, rollback and tenant switching keep isolation (B) | iso::test_pool_reuse_rollback_and_tenant_switching | verified | Test found and drove a fix to a pool reset bug |
| X12 | Direct SQL cannot bypass domain commands | iso::test_direct_sql_cannot_bypass_case_commands, ::test_closure_without_valid_record_fails_at_commit | verified | |
| X13 | Runtime role cannot be owner, superuser or BYPASSRLS; service refuses to start otherwise (B) | iso::test_runtime_role_self_check; manual uvicorn check in VERIFICATION.md | verified | |
| X14 | Applied migrations cannot be silently edited | iso::test_migration_ledger_is_idempotent_and_detects_edits | verified | |
| X15 | Storage tampering after verification is detected on read | evo::test_storage_tampering_after_verification_is_detected, s3::test_s3_evidence_finalise_and_tamper_detection | verified | Detection, not prevention |
| X16 | Suspended tenant is inaccessible | iso::test_suspended_tenant_is_inaccessible | verified | Cancelling waiting work is planned |
| X17 | Tenant selection gives no existence oracle | iso::test_tenant_selection_and_security_events | verified | |
| X18 | Emergency access is time-bound and raises a review event | cases::test_tenant_admin_delegation_rules | verified | Review workflow itself planned |
| X19 | Concurrent outbox relays never double-claim | evo::test_concurrent_relays_do_not_double_claim | verified | |
| X20 | Approval waits survive worker restart without duplicate effects | job::test_wait_then_done, job::test_sigkill_after_effect..., act::test_stale_worker_already_past_the_boundary[*] | implementing | Approvals are records, so waiting is not held in a worker; an automatic "wait for approval then execute" job is not built (execution is requested explicitly after approval) |
| X21 | Restored backups do not reactivate expired grants or replay effects (D 13) | none | planned | |
| X22 | Evidence deletion and legal-hold races follow policy (D 13) | none | planned | |

## 3. Case lifecycle (S 4, D 6-7)

| ID | Requirement | Implementation | Verification | Status | Notes |
|---|---|---|---|---|---|
| CASE-01 | Workflow, assessment, priority and disposition enumerations and the allowed transition table | `domains/cases/model.py`; `axiom.case_transition_allowed` (replaced in 0008 for R7), row guard trigger | unit::test_transition_table_matches_specification (includes the two R7 transitions), iso::test_direct_sql_cannot_bypass_case_commands | verified | Specification S 4 amended for R7 (approved 2026-10-22) |
| CASE-02 | Optimistic concurrency with expected versions | `_apply` versioned UPDATE; DB increments-by-one guard | cases::test_stale_version_..., ::test_concurrent_... | verified | |
| CASE-03 | Unsupported transitions return a structured conflict and commit nothing | `Conflict` errors, transaction rollback | cases::test_stale_version_rejected_without_partial_state, api::test_conflicts_and_structured_errors, r7::* | verified | |
| CASE-04 | received -> investigating needs valid scope and scheduled investigation | `start_investigation` (decision + permission) | cases lifecycle tests | implementing | Investigation runs are scheduled in Phase C |
| CASE-05 | investigating -> review needs assessment with limitations and policy decision, or explicit escalation | `record_assessment`, `escalate` | cases::test_definite_assessment_requires_verified_evidence | implementing | Policy decision is Phase C |
| CASE-06 | review -> remediation_planned needs authorised decision and eligible assigned owner | `plan_remediation` | cases::test_plan_requires_eligible_owner | verified | |
| CASE-07 | remediation_planned -> remediating needs approved action or recorded external work | `record_external_work` | lifecycle tests | implementing | Moving the case on an executed approved action is not automatic (ACT-09 keeps tickets from moving cases); record_external_work remains the route |
| CASE-08 | remediating -> awaiting_verification needs a reported change with identified deployment of an affected asset | `report_change`, `remediation_report_target` trigger | lifecycle tests; cases::test_remediation_target_must_be_affected_asset | verified | Negative path currently enforced by the DB trigger (service returns a 409 guard_violation via the API mapping) |
| CASE-09 | Verification passed/failed/inconclusive drive closed / remediating / review | `record_verification`, `close_verified` | cases::test_partial_coverage_..., ::test_wrong_deployment_..., lifecycle | verified | |
| CASE-10 | Distinct closure reasons with reason-specific prerequisites (verified, accepted risk, dismissed, duplicate, retired) | `_close`, `closure_records` CHECKs, `validate_closure` | cases::test_full_lifecycle..., ::test_risk_acceptance..., ::test_dismissal..., ::test_duplicate..., ::test_asset_retirement... | verified | Asset retirement route per R2 |
| CASE-11 | Reopen appends an event, preserves earlier closure and requires a reason | `reopen` | cases::test_full_lifecycle... | verified | |
| CASE-12 | Deferral stays open with a review date | `defer`, CHECK constraint | cases::test_deferral_stays_open_with_review_date | verified | |
| CASE-13 | No generic state change bypassing commands | No PATCH route; column grants; triggers | api::test_client_cannot_assert_authority_or_tenant, iso::test_direct_sql_... | verified | |
| CASE-14 | Operational job failure does not erase the last valid business state | none | none | planned | Workers |
| CASE-15 | Separation of duties: reporter cannot verify or close; assessor cannot dismiss; case owner cannot accept risk | service guards; dismissal SoD also in DB | cases::test_reporter_cannot_verify_own_change, ::test_dismissal..., ::test_case_owner_cannot_accept_own_risk | verified | |
| CASE-16 | Case correlation keeps per-scanner identities | `finding_occurrences` unique per source identity; links | cases::test_duplicate_requires_shared_vulnerability_on_same_asset | implementing | Full correlation engine is Phase B |
| CASE-17 | Asset-retirement closure: from review only, verified lifecycle evidence readable by the closer, every linked affected asset retired with its own verified evidence, recorded separately from remediation | `close_asset_retired`, `AssetService.retire`, `validate_closure` | cases::test_asset_retirement_closure_requires_retired_assets | implementing | Closure route verified (refused while active, accepted after retirement); separate reporting is planned (VER-05). See ADR 0004 |
| CASE-18 | R7 (approved 2026-10-22): remediation_planned -> review via authorised recorded decision; remediating -> review only with verified evidence of no deployment; deployed/partial/unknown goes through verification (may return to review); never bypasses unresolved external effects; keeps tickets, approvals, consumed uses, history and evidence; obsolete proposals cannot execute | `withdraw_remediation`, migration 0008 (`r7_return_guard`, abandoned remediation reports, plan epoch) | r7::* (10 tests incl. two database-backstop tests with the service check bypassed), mutation checks 2026-10-22 | verified | ADR 0004; Specification S 4 amendment |

## 4. Evidence (S 3, P 3, D 4)

| ID | Requirement | Implementation | Verification | Status | Notes |
|---|---|---|---|---|---|
| EVD-01 | Upload: pending record, bytes, size and hash verified by reading back storage, then finalise | `EvidenceService.initiate/upload/finalise` | evo::test_upload_finalise..., ::test_digest_mismatch..., ::test_oversize..., ::test_finalise_before_upload_rejected, s3:: | verified | |
| EVD-02 | Only verified evidence supports consequential decisions | service check + `decision_evidence_verified` trigger + verification trigger | cases::test_definite_assessment_requires_verified_evidence | verified | DB trigger path not tested in isolation |
| EVD-03 | Server-generated, tenant-namespaced object keys; no arbitrary paths | `evidence_key`, DB CHECK, `TenantObjectStore` | evo::test_upload_finalise..., ::test_tenant_object_store_refuses_foreign_keys | verified | |
| EVD-04 | Classification-sensitive reads, audited before bytes are served; denials audited | `open_for_read` | evo::test_classification_permissions_and_denial_audit, ::test_upload_finalise_and_audited_download | verified | |
| EVD-05 | Integrity re-checked when served; hashes are not proof of truth | `_verified_stream` | evo::test_storage_tampering..., s3:: | verified | |
| EVD-06 | Retention policies for originals, derivatives and backups | `retention_policy` column only | none | planned | |
| EVD-07 | Legal holds with explicit lifecycle | none | none | planned | |
| EVD-08 | Immutable retention or independently stored signed checkpoints where stronger integrity is needed | none | none | planned | |
| EVD-09 | Observations, observation relations, evidence snapshots and members | none | none | planned | Phases B/C |
| EVD-10 | Evidence delivery by authenticated streaming; any pre-signed URL is short-lived with documented limits | API streaming download; no pre-signed URLs issued | api::test_analyst_journey... | verified | |
| EVD-11 | Corrections append superseding records, never silent overwrite | Append-only triggers on decisions/events/verification | iso::test_append_only_... | implementing | Observation supersession is Phase B |

## 5. Authentication and authorisation (S 8, D 2, 11, 12)

| ID | Requirement | Implementation | Verification | Status | Notes |
|---|---|---|---|---|---|
| AUTHZ-01 | Validate OIDC tokens: trusted issuer, audience, expiry, asymmetric algorithms only | `auth/tokens.py` | unit::test_token_verification | verified | |
| AUTHZ-02 | Resolve principals from (issuer, subject); no email-based merging; authentication is not membership | `axiom_auth.resolve_principal` | iso::test_tenant_selection_and_security_events | verified | |
| AUTHZ-03 | Explicit tenant selection validated server-side on every request | `Authenticator.select_tenant` | api::test_authentication_and_tenant_selection | verified | |
| AUTHZ-04 | Scoped role bindings covering descendants, with expiry and revocation | `access.evaluate`, `Authorizer` | unit::test_binding_covers..., ::test_expired..., cases::test_permission_scope_and_revocation, ::test_expired_binding_denied | verified | |
| AUTHZ-05 | Built-in roles and permissions per D 11 | migration 0001 catalogue | role behaviour across cases/evo tests | verified | |
| AUTHZ-06 | Tenant custom roles cannot contain privileged permissions | `custom_roles_unprivileged` trigger | none | implemented_unverified | No custom role API yet |
| AUTHZ-07 | No self-grant; assigning requires role.assign covering the scope | `TenancyService.assign_role`, DB CHECK | cases::test_tenant_admin_delegation_rules | verified | |
| AUTHZ-08 | Emergency access: time-bound, reason, notification, retrospective review | `assign_role(emergency=True)` | cases::test_tenant_admin_delegation_rules | implementing | Review workflow and notification delivery planned |
| AUTHZ-09 | Administration grants no evidence, risk or approval authority; operators get no tenant access | role catalogue; installation roles outside tenants | X08 tests | verified | |
| AUTHZ-10 | Delegation limits bound risk acceptance and action approval | `delegation_limits`, `_delegation_limit` | cases::test_risk_acceptance_limits... | implementing | Action approval limits are Phase D |
| AUTHZ-11 | High-impact decisions prohibit self-approval by default | CASE-15 guards; proposer cannot approve (service + trigger); risk independence (service + CHECK) | act::test_proposer_cannot_approve_in_service_or_database, risk2::test_high_impact_needs_someone_other_than_the_requester, ::test_database_backstop_for_independence | verified for actions and risk acceptance | Policy publishing is Phase C |
| AUTHZ-12 | Workload principals with job-scoped service grants (tools, subjects, expiry, budget) | none | none | planned | Phase C |
| AUTHZ-13 | No authority caching across requests; revocation effective on next request | per-transaction loading | cases::test_permission_scope_and_revocation | verified | |
| AUTHZ-14 | Production OIDC SSO integration (e.g. Entra ID, Keycloak) | JWKS URI support | none | planned | Development issuer only so far |
| AUTHZ-15 | Decisions record the authority relied on | `Authority.as_json` stored in decisions/audit | cases::test_decisions_record_authority | verified | |
| AUTHZ-16 | Evidence citation requires read permission at the evidence classification | `_evidence_for_citation` | cases::test_cross_tenant_resource_references_are_invisible, ::test_citing_evidence_requires_read_permission_for_its_classification | verified | |

## 6. Tenancy and isolation (S 2 B06, P 14, D 10, 13, B)

| ID | Requirement | Implementation | Verification | Status | Notes |
|---|---|---|---|---|---|
| TEN-01 | Forced RLS and composite tenant-aware FKs on all tenant-owned tables | migrations 0001-0002 | iso::test_no_context_sees_nothing, ::test_cross_tenant_foreign_key_rejected, structural audit in VERIFICATION.md | verified | |
| TEN-02 | Transaction-local, transaction-bound tenant context; no switching inside a transaction | `axiom.bind_context`, `axiom.current_tenant` | iso::test_cannot_switch..., ::test_session_level..., ::test_pool_reuse... | verified | |
| TEN-03 | Runtime roles never owners, superusers or BYPASSRLS; startup check | provisioning assertion; `verify_runtime_role` | iso::test_runtime_role_self_check | verified | |
| TEN-04 | Separate migration, runtime, authentication, relay and provisioning identities | db/provision_roles.sql | iso::test_provisioner_cannot_read..., ::test_relay_reads_only_outbox, ::test_runtime_cannot_read_identity_tables_directly | verified | Backup and operations roles planned |
| TEN-05 | Background jobs take tenant from trusted persisted identity, never payloads | outbox rows carry tenant; job worker binds tenant and system principal from `axiom_auth.active_tenant_workers` | evo::test_outbox_relay..., job::*, ingjob::* | verified | |
| TEN-06 | Object storage uses tenant namespaces and restricted identities | `TenantObjectStore`; per-tenant bucket policies not used | X07 | implementing | Storage credentials are installation-wide; tenant-scoped storage identities planned |
| TEN-07 | Cache isolation | none | none | planned | |
| TEN-08 | Search isolation | none | none | planned | |
| TEN-09 | Export isolation | none | none | planned | |
| TEN-10 | Per-tenant quotas and concurrency limits | none | none | planned | |
| TEN-11 | Integration credentials tenant-scoped, server-side, short-lived | none | none | planned | |
| TEN-12 | Model requests follow tenant provider and residency policy | none | none | planned | |
| TEN-13 | Audit access is tenant-scoped and permissioned | `/audit-events` requires audit.read | api::test_audit_read_requires_explicit_permission | verified | |
| TEN-14 | Shared and dedicated installation modes on one codebase | `installations.deployment_profile`, dedicated single-tenant trigger | none | implemented_unverified | |
| TEN-15 | Cross-client portfolio via separate authorised aggregation path | none | none | planned | |
| TEN-16 | Suspension and revocation block new actions and cancel waiting work | tenant status in policies | iso::test_suspended_tenant_is_inaccessible | implementing | Waiting work cancellation pending |
| TEN-17 | Document that a compromised application choosing tenant context exceeds context-based RLS | ADR 0002, README | review | verified | Documentation requirement |
| TEN-18 | Provider webhooks resolve tenant from authenticated connection | none | none | planned | |
| TEN-19 | Workers take tenant and principal from trusted persisted records (`axiom_auth.active_tenant_workers`), never from payloads | jobs/worker.py, workers/jobs.py | sync::test_tenable_sync_end_to_end_and_checkpoint (dispatch path), test_jobs (all) | verified | |

## 7. Audit, outbox and API conventions (S 2 B12, P 3-4, D 8)

| ID | Requirement | Implementation | Verification | Status | Notes |
|---|---|---|---|---|---|
| AUD-01 | Audit write atomic with the change | see B12 | B12 tests | verified | |
| AUD-02 | Audit history append-only, including against the owner | triggers | iso::test_append_only... | verified | A superuser can still drop triggers; independent checkpoints are EVD-08 |
| AUD-03 | Audit excludes tokens and secrets | `_sanitise` | cases::test_audit_detail_redacts_secret_like_keys | verified | Key-name based; values in free text are not scanned |
| AUD-04 | Transactional outbox with at-least-once leased relay and backoff | `outbox.py` | evo::test_outbox_relay..., ::test_concurrent_relays... | verified | |
| AUD-05 | Consumer inbox deduplication | `Inbox.first_delivery` | evo::test_outbox_relay... | verified | |
| AUD-06 | Relay has least privilege | axiom_relay grants | iso::test_relay_reads_only_outbox | verified | |
| AUD-07 | Unattributable denials recorded as installation security events | `security_events` | iso::test_tenant_selection_and_security_events | verified | |
| API-01 | Versioned under /api/v1 | `api/app.py` | api:: tests | verified | |
| API-02 | Tenant and actor from authentication, never body fields; unknown fields rejected | `extra='forbid'` bodies | api::test_client_cannot_assert_authority_or_tenant | verified | |
| API-03 | Mutating commands take expected version; 409 on conflicts | command schemas | api::test_conflicts_and_structured_errors | verified | |
| API-04 | Structured errors: code, safe message, correlation ID, retryability | exception handlers | api::test_conflicts_and_structured_errors | verified | |
| API-05 | Cursor pagination | `/cases` cursor | api::test_pagination | verified | Other list endpoints pending |
| API-06 | Long-running work returns 202 and a job reference | none | none | planned | |
| API-07 | External-effect commands need idempotency keys with stored request digest and outcome | `axiom/idempotency.py`, `axiom.idempotency_keys`; required on execution requests | act::test_idempotency_key_replays_and_rejects_reuse_with_different_arguments, ::test_idempotency_keys_are_scoped_per_principal, act_api::test_action_journey_with_idempotent_execution | verified | Expired-key cleanup not built |
| API-08 | Versioned contracts and generated OpenAPI under contracts/ | OpenAPI served at /api/v1/openapi.json | manual check (200) | implementing | Not exported or diff-checked yet |
| API-09 | Permission denial distinct from dependency failure; hidden records return 404 | error mapping | api::test_cross_tenant_access_through_api_is_denied | verified | |

## 8. Ingestion and assets (S 5, P 5, D 3-5) - Phase B (ADR 0009)

`ing::` = tests/integration/test_ingestion.py, `sync::` = test_sync.py, `adp::` = tests/unit/test_adapters.py.

| ID | Requirement | Implementation | Verification | Status | Notes |
|---|---|---|---|---|---|
| ING-01 | Import pipeline retaining original files, provenance, timestamps, scope and source-specific fields | `ingestion/pipeline.py`, migration 0003 | ing::test_trivy_import_preserves_original_and_correlates, ::test_tampered_original_fails_the_run | verified | |
| ING-02 | Adapters declare formats, operations, versions and support level | `adapters/base.py`, `catalogue.py`, `/api/v1/adapters` | adp::test_identifier_strength_and_catalogue_honesty, api::test_ingestion_journey_through_api | verified | Limits and permissions documentation per adapter still to write |
| ING-03 | Pagination, provider rate limits, bounded retry classification | Tenable and Resource Graph clients | adp::test_tenable_export_client_flow..., ::test_tenable_client_bounded_retries..., ::test_resource_graph_pages_and_parser | verified (against fakes) | Not validated against live services |
| ING-04 | Resumable checkpoints advanced only after durable writes | page commits, fenced; checkpoints in finalisation | ing::test_resume_after_in_process_crash..., ::test_real_process_kill_then_resume, sync::test_tenable_sync_complete_advances_checkpoint... | verified | |
| ING-05 | Replay deduplication by tenant/source identity and observation version, not CVE | source_records, occurrence uniqueness | ing::test_replayed_import_creates_no_duplicates, adp::test_trivy_real_report | verified | |
| ING-06 | Run coverage complete/partial/failed/unknown | `_finalise` | ing::test_partial_scan..., ::test_tenable_identity..., sync:: tests | verified | |
| ING-07 | Provider deletions/tombstones are observations, not closure | `tombstone` observation type and absence rules | ing::test_partial_scan_closes_nothing_and_complete_rescan_records_absence (absence part) | implementing | No source in scope emits tombstones yet |
| ING-08 | Webhooks: signature verification, replay protection, tenant-bound connection | none | none | planned | |
| ING-09 | Visible quarantine of invalid records | `quarantined_records`, run API | ing::test_tenable_identity..., api::test_identity_candidate_review_through_api | verified | |
| ING-10 | Connector health, freshness and operations UI | run listing API only | api::test_ingestion_journey_through_api | implementing | Health/freshness metrics and UI planned |
| ING-11 | Stale ingestion workers cannot commit (fencing) | lease token + `ingestion_page_fence` trigger | ing::test_stale_worker_is_fenced (also passes with the service check removed) | verified | |
| ING-12 | Source-reported fixes never close cases | `_correlate` | ing::test_tenable_identity_uncertainty_quarantine_and_source_fix | verified | |
| ING-13 | Imported text is untrusted data | stored in `source_fields` only | ing::test_sarif_import_with_untrusted_text_changes_no_authority | verified (ingestion part) | A05 also needs Phase C model-path tests |
| AST-01 | Identity prefers immutable provider identifiers and deployment digests | `ingestion/identity.py` | ing::, sync:: tests | verified | |
| AST-02 | Conflicting identifiers require review; no automatic merge | candidates; `conflict` status | ing::test_tenable_identity..., sync::test_tenable_host_and_azure_vm_with_same_hostname_stay_separate | verified | ing::test_strong_identifier_conflict_creates_conflict_asset_and_review (found and fixed a bug: each record created a new conflict asset) |
| AST-03 | Reversible merges and splits through recorded links | review decisions recorded only | api::test_identity_candidate_review_through_api | implementing | Merge/split execution not built |
| AST-04 | No global uniqueness on IP, name or tag | weak identifiers never unique | sync::test_tenable_host_and_azure_vm... (3 assets share a hostname) | verified | |
| AST-05 | Immutable asset versions with deployment digests | `asset_versions` | ing:: tests | implementing | Effective intervals pending |
| AST-06 | Business context versions with effective dates and basis | `business_context_versions` | sync::test_azure_resource_graph_sync_context_and_identity | implementing | Source-tag assertions done; user assertions (journey J03) pending |
| AST-07 | Asset relationships (deployment and exposure paths) | none | none | planned | |
| AST-08 | No cross-tenant asset links | composite FKs; RLS | iso::test_cross_tenant_foreign_key_rejected, api::test_identity_candidate_review_through_api | verified | |
| AST-09 | Declared subjects recorded as importer assertions | `declared_by_importer` origin | ing::test_sarif_without_subject_fails_until_declared | verified | |
| CORR-01 | Correlate occurrences into cases per asset and vulnerability without discarding scanner identities | `_correlate` | ing::test_trivy_import_preserves_original_and_correlates | verified | Cross-scanner correlation not attempted |
| CORR-02 | Recurrence reopens cases (new occurrence after closure; old deployment seen after verified closure) | `_correlate` | ing::test_recurrence_after_verified_closure_reopens | verified | |

## 9. Investigation and AI (S 6, P 6) - Phase C

| ID | Requirement | Status |
|---|---|---|
| INVS-01 | Freeze evidence and policy snapshot before investigation | planned |
| INVS-02 | Typed, allowlisted tools with registered destinations, scoped credentials, bounded calls/bytes/time/spend/recursion | planned |
| INVS-03 | Record unsuccessful checks and tool records (principal, subject, destination, time, result digest) | planned |
| INVS-04 | Claims with supporting and contradicting observations, limitations | planned |
| INVS-05 | Schema-validated model output; references must exist in tenant and scope (A06) | planned |
| INVS-06 | Timeout, invalid output or budget exhaustion yields explicit incomplete result | planned |
| INVS-07 | Provider routing and fallback only as tenant data policy permits; redaction before submission | planned |
| INVS-08 | Imported content treated as untrusted; cannot expand tools or authority (A05) | planned |
| INVS-09 | Confidence expressed as evidence completeness categories, no invented probabilities | planned |
| INVS-10 | New evidence supersedes runs without rewriting them | planned |
| INVS-11 | Model gateway: approved providers, schemas, budgets, usage and cost observability | planned |
| INVS-12 | No retention of private chain-of-thought; concise rationale and decision inputs kept | planned |

## 10. Prioritisation (S 7) - Phase C

| ID | Requirement | Status |
|---|---|---|
| PRI-01 | Versioned, testable deterministic policies set authoritative priority | planned |
| PRI-02 | AI cannot set authoritative priority | planned |
| PRI-03 | Unknown context triggers conservative rules; unsupported reachability is not unreachability | planned (unknown priority already treated as urgent for delegation checks) |
| PRI-04 | Record inputs, freshness and rule outcomes | planned |
| PRI-05 | Overrides with scope, reason, actor, expiry/review; second approver by policy | planned |
| PRI-06 | Impact preview before policy activation | planned |
| PRI-07 | Historical decisions retain their policy version (A14) | planned |

## 11. Actions and remediation (S 9, P 7, D 7) - Phase D

| ID | Requirement | Status | Notes |
|---|---|---|---|
| ACT-01 | Canonical proposals with payload digest, effect class, preconditions, owner, rollback, verification criteria | verified | act::test_digest_is_computed_by_the_database..., ::test_payload_validation_and_disabled_effect_classes |
| ACT-02 | Approvals bound to proposal version, digest, tenant, resources, expiry, max uses | verified | See B07 |
| ACT-03 | Recheck authority, revocation, approval validity and resource version before the effect | verified | act::test_revocation..., ::test_approver_losing_membership..., ::test_material_change_after_approval_denies; mutation checks 2026-10-22 |
| ACT-04 | Durable intent with stable external operation identity before the effect | verified | `external_operation_id` per execution; intent marked executing before the call; act::test_two_jobs_racing... |
| ACT-05 | Provider idempotency keys where available | verified (fake provider) | The gate uses them when declared (act::test_lost_ack_with_provider_idempotency..., stale-worker variants). Jira is not known to offer them, so jira_style declares none |
| ACT-06 | Reconcile unknown outcomes; operator intervention when unidentifiable | verified | act::test_lost_ack_with_lagging_search..., ::test_unprocessed_and_connect_failures..., ::test_operator_actions_are_audited... |
| ACT-07 | Transactional approval reservation; timeout never restores single-use approval blindly | verified | act::test_concurrent_reservations..., ::test_reservation_accounting_is_guarded..., ::test_a_use_is_never_returned_once_the_effect_may_have_been_attempted |
| ACT-08 | Ticket, pull request and production mutation permissions are distinct; production mutation disabled by default | verified | Per-class propose/approve/execute permissions, exact match, no hierarchy (migration 0009); act::test_weaker_class_permissions_never_authorise_a_stronger_effect (production.change enabled in-process only for the test); production.change and pull_request.create stay disabled in the product |
| ACT-09 | External ticket closure does not close the case | verified | Inbound polling records state changes append-only and never moves the case (track::*, wf::test_externally_closed_ticket_never_moves_the_case for Jira-style, ServiceNow and GitHub fakes) |
| ACT-11 | SLA timers per priority start, supersede on priority change, breach once, end on closure | verified | track::test_sla_lifecycle (fault injection for priority and time); thresholds are defaults D-SLA-1 |
| ACT-10 | Material changes invalidate approval | verified | Payload change needs a new version and approval (A08); priority or scope change or closure denies at execution (act::test_material_change_after_approval_denies, using fault injection because no priority command exists yet) |

## 12. Verification, risk and reassessment (S 10) 

| ID | Requirement | Status | Verification / notes |
|---|---|---|---|
| VER-01 | Verification identifies the deployed asset version and explicit acceptance criteria | verified | A18 tests; criteria digest stored |
| VER-02 | Unavailable systems or incomplete scans give inconclusive, never passed | verified | unit::test_verification_outcome, cases::test_partial_coverage... |
| VER-03 | Reassessment triggers (deployment, exposure, intelligence, ownership, exception validity) with storm deduplication | planned | |
| VER-04 | Verification worker collecting outcome evidence with scoped credentials | planned | Currently recorded by a human verifier |
| VER-05 | Retired asset closure distinct and not counted as a fix | verified | Closure route (cases::test_asset_retirement...); report snapshots count closures by reason separately (track::test_snapshot_is_immutable_digest_checked_and_separates_outcomes) |
| RISK-01 | Acceptance with owner, scope, rationale, compensating controls, expiry, delegation limits | verified | cases::test_risk_acceptance... |
| RISK-02 | Request/authorise/renew flow | verified | risk2::* (independence, stale requests, renewal chain, reassessment notices, lapse), act_api::test_risk_request_and_authorise_over_http. Thresholds are defaults (D-RISK-1) |
| RISK-03 | Durable expiry scheduling plus reconciliation sweep | verified | Hourly per-tenant sweep job (ingjob::test_risk_expiry_sweep...); expiry, reassessment and lapse (risk2::*) |
| RISK-04 | Accepted exposure remains in reports | verified | Snapshot section `accepted_exposure` (active acceptances, expiring within 14 days) and `closed_by_reason` keeps accepted_risk separate |

## 13. Reporting and GRC (S 11) - Phase D

| ID | Requirement | Status |
|---|---|---|
| RPT-01 | Immutable report snapshots: query definition/version, as-of, coverage, denominators, membership, result digest | implementing | Immutable, digest-checked snapshots computed by one SQL statement (track::test_snapshot...). Query version, coverage and denominators are not recorded yet |
| RPT-02 | Reports show freshness, missing coverage, unresolved ownership, inconclusive cases, accepted exposure | implementing | Accepted exposure, SLA state, open work by state; freshness, coverage and ownership not yet |
| RPT-03 | AI summaries cite case/query identifiers; figures must match snapshot calculations | planned |
| RPT-04 | Framework mappings are versioned references, not compliance verdicts | planned |
| RPT-05 | Auditor can reconstruct a decision and export an evidence package (journey J08) | planned |
| RPT-06 | Exports record tenant, actor, scope, classification, expiry and downloads | implementing | Export records tenant, actor, snapshot, format, digest; reads are audited and digest-verified (track::test_exports...); classification and expiry not recorded |
| RPT-07 | Cross-client portfolio metrics keep source tenant and coverage | planned |
| RPT-08 | Owner attestations and exception expiry captured for GRC | planned |

## 14. Integration catalogue (S 12, B)

Support levels: planned, fixture-tested, sandbox-validated, production-supported. Nothing below is beyond planned.
Commercial connectors are blocked for sandbox validation until licensed test accounts are provided.

| ID | Integration | Adapter type | Support level | Validation dependency |
|---|---|---|---|---|
| INT-01 | Tenable (Vulnerability Management): export chunk parser and export API client | scanner | **fixture-tested** (synthetic chunks, local fake API) | Tenable account and API keys for sandbox validation |
| INT-02 | Qualys VMDR | scanner | planned | Qualys subscription |
| INT-03 | Rapid7 InsightVM | scanner | planned | InsightVM console or cloud API access |
| INT-04 | CodeQL (via SARIF / GitHub code scanning API) | scanner | planned | Public SARIF samples; GitHub token for API |
| INT-05 | Semgrep | scanner | planned | OSS CLI output fixtures; Semgrep AppSec Platform account for API |
| INT-06 | Snyk | scanner | planned | Snyk org and token |
| INT-07 | Trivy JSON (SchemaVersion 2, container images) | scanner | **fixture-tested** (real Trivy 0.76.1 output) | Other report types (fs, sbom, k8s) not tested |
| INT-08 | Generic SARIF 2.1.0 | scanner | **fixture-tested** (real Trivy SARIF, synthetic code-scanning) | Real CodeQL/Semgrep output not yet tested |
| INT-09 | OWASP ZAP | scanner (DAST) | planned | Open source; local target |
| INT-10 | Burp Suite DAST | scanner (DAST) | planned | PortSwigger licence |
| INT-11 | Microsoft Defender for Cloud | scanner/context | planned | Azure subscription |
| INT-12 | Azure Resource Graph | context | **fixture-tested** (synthetic pages, local fake API) | Azure subscription and workload identity for sandbox validation |
| INT-13 | AWS Security Hub | scanner/context | planned | AWS account |
| INT-14 | AWS resource inventory (e.g. AWS Config) | context | planned | AWS account |
| INT-15 | Jira | workflow | fixture-tested (Jira-style fake only) | Shapes from Atlassian REST v3 docs; never run against a Jira site; sandbox validation needs a Jira Cloud site |
| INT-16 | ServiceNow | workflow | fixture-tested (local fake only) | Table API shapes from ServiceNow docs; table, correlation field and state mapping are per-instance assumptions; needs a developer instance for sandbox validation |
| INT-17 | GitHub (issues, pull requests) | workflow | fixture-tested for issues (local fake only); pull requests planned | REST 2022-11-28 shapes; needs an org or app for sandbox validation |
| INT-18 | Structured business inventory import | context | planned | Schema to be defined |
| INT-19 | Threat intelligence feeds (candidates: CISA KEV, FIRST EPSS, OSV/NVD) with provenance, freshness and licence | intelligence | planned | Licence terms to record per feed |
| INT-20 | Witness (optional evidence provider; platform runs without it) | evidence provider | planned | |

## 15. Architecture, operations and deployment (S 13-14, P 1, 11)

| ID | Requirement | Status | Notes |
|---|---|---|---|
| ARC-01 | Modular application with separately deployable workers and identities | implementing | API module and relay done; workers pending |
| ARC-02 | Durable workflow engine selected through an experiment and ADR | implementing | ADR 0006 accepted; runner with metrics, operations API and CI script; hosted CI never run; no operations UI; multi-step workflows not built |
| ARC-03 | Domain logic independent of scanner, cloud and model vendors | implementing | Holds for current code |
| ARC-04 | Pinned dependencies and reproducible builds | verified | uv.lock with cooldown; images pinned by digest; Docker build succeeded |
| ARC-05 | React and TypeScript frontend supporting real journeys | planned | |
| ARC-06 | PostgreSQL relational edges first; graph DB only with measured need | implementing | |
| ARC-07 | PostgreSQL search first; vector search optional and non-authoritative | planned | |
| OPS-01 | Metrics and traces | implementing | Job runner metrics (API + worker Prometheus endpoint); no traces, no API metrics |
| OPS-02 | Connector freshness alerts | planned | |
| OPS-03 | Worker health | implementing | Worker counters and job metrics; no liveness endpoint or alerting |
| OPS-04 | Model cost monitoring | planned | |
| OPS-05 | Operator access to security events and audit without tenant evidence | planned | |
| OPS-06 | Backup and restore procedures with drills (A15) | implementing | Restore detection drills (logical same-OID restore, physical snapshot rollback, pg_dump/pg_restore) and operator acknowledgement; no backup procedure or RPO/RTO drill |
| OPS-07 | Disaster recovery exercises | planned | |
| OPS-08 | Secret rotation | planned | |
| OPS-09 | Encryption in transit and at rest | planned | Compose profile has no TLS |
| OPS-10 | Retention, export, tenant deletion and auditable legal holds (A20) | planned | |
| OPS-11 | Data classification and residency defined before sending code or evidence to models | planned | |
| OPS-12 | Upgrade compatibility across schema, API, workflow histories, connectors | implementing | Migration ledger in place |
| DEP-01 | Docker images package components | verified | `docker build` succeeded; non-root user |
| DEP-02 | Compose starts the complete functional platform | implementing | API, PostgreSQL, S3 storage, init and job worker (with restore witness volume) verified; UI pending |
| DEP-03 | Insecure development defaults refused in production | verified | unit::test_production_refuses_development_shortcuts |
| DEP-04 | Helm with external PostgreSQL, object storage, IdP, workflow services; restricted workloads; backups | planned | |
| DEP-05 | AKS reference deployment with portable interfaces | planned | |
| DEP-06 | Workload identity, network policies, restricted service accounts, limits, health checks | implementing | Compose hardening (read-only, cap_drop, internal network); Kubernetes pending |
| DEP-07 | Signed and pinned images | implementing | Pinned; signing planned |
| DEP-08 | Continuous integration running unit, DB, isolation and lint gates | implementing | `scripts/ci/run.sh` executed locally (CI PASS, run 14); `.github/workflows/ci.yml` with actions pinned to verified commit hashes (docs/ci-action-pins.md, scripts/ci/check-action-pins.sh). Never run on a hosted service (no remote authorised). No linter; byte-compilation and secret scan instead |
| DEP-09 | Disposable execution with explicit egress and no ambient credentials before any untrusted code capability | planned | Capability stays disabled |

## 16. User journeys (P 9)

| ID | Journey | Status |
|---|---|---|
| J01 | Operator installs, configures SSO and integrations, checks ingestion health | implementing (Compose install verified; SSO and ingestion pending) |
| J02 | Analyst reviews a correlated case and follows every material conclusion to evidence | implementing (API path verified in api::test_analyst_journey...; UI pending) |
| J03 | Asset owner corrects ownership/importance with effective date | planned |
| J04 | Approver reviews exact remediation scope and authorises or rejects | planned |
| J05 | Risk owner accepts scoped exposure with reason and expiry | implementing (service and API verified; UI pending) |
| J06 | Remediation owner supplies deployment evidence and requests verification | implementing (API verified; UI pending) |
| J07 | Verifier confirms or rejects resolution against the correct deployment | implementing (API verified; UI pending) |
| J08 | Auditor reconstructs a decision and exports an evidence package | planned |
| J09 | Manager inspects verified risk reduction, accepted exposure, missing coverage | planned |
| J10 | Operator restores backup and reconciles uncertain external actions first | planned |

## 17. Evaluation (S 16, P 10, B)

| ID | Requirement | Status | Notes |
|---|---|---|---|
| EVAL-01 | Labelled cases: true, unsupported, ambiguous, stale, contradictory, malicious | planned | |
| EVAL-02 | Held-out evaluation data separate from development fixtures, blinded reference review | planned | |
| EVAL-03 | Baselines: scanner severity alone, deterministic policy alone, human reference | planned | |
| EVAL-04 | Metrics: missed urgent exposures, unsupported dismissals, claim/evidence correctness, priority agreement, correction rate, verified-fix accuracy, analyst time, cost | planned | |
| EVAL-05 | Publish sample sizes, limitations and failure cases; no state-of-the-art claim without comparison | planned | |
| EVAL-06 | Release thresholds set from the dataset and risk tolerance before use | blocked | Needs business decision on thresholds |
