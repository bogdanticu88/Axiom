# ADR 0012: Evidence-backed investigation (Phase C)

Status: accepted (2026-10-22). Budgets, retry limits and the claim rules are initial values (D-INV-1).
The real-provider path is implemented but **unverified**: no credentials or external access were authorised.

## Context
Analysts recorded assessments by hand. Phase C adds AI-assisted investigation, under these constraints:
* AI output is analysis, never authority;
* every conclusion must be traceable to frozen evidence;
* contradictions and missing information must survive;
* data must not leave for unapproved destinations;
* a model or imported content must not be able to widen tools, network access or permissions.

## Decision

### 1. Frozen evidence snapshots (`investigation/snapshots.py`, migration 0013)
A snapshot of one case at one instant has append-only members. Each member has a stable key (`M001`...), a kind, the
record ID, a version identity (observation digest, deployment digest or evidence digest), a classification, a
collection time, a freshness value and availability. It also holds a frozen copy of the attributes used.

Members cover:
* active linked occurrences and their asset versions and assets;
* every observation of each occurrence by every run (present, absent in a complete scan, fixed or suppressed by the
  source);
* the runs themselves (adapter, declared scope or subject, coverage), with freshness under the freshness policy in
  force at that time;
* business-context versions;
* raw reports, and evidence cited by earlier decisions.

**Contradictions** are recorded, not resolved: present in one run and absent or fixed in another (with the latest
status), severity disagreement, user and source context disagreement, and several deployment versions.

**Gaps** are recorded: no complete scan, stale complete scan, no business context, no criticality, no severity,
unverified evidence, and no occurrences.

The digest is computed over a canonical form with times in UTC; `verify_snapshot` recomputes it. Later evidence
produces a new snapshot. An assessment that cites a snapshot keeps it, and a reassessment is a new decision.

### 2. Model routes and the gateway (`investigation/gateway.py`, `providers.py`)
A route records the provider, model, endpoint origin, region, maximum data classification, credential reference,
prices, timeout, retries and output limit. One administrator proposes it, another approves it (service plus a
database CHECK), and the definition is immutable.

The endpoint origin must be in the installation's `AXIOM_MODEL_DESTINATIONS`. The deterministic fake is refused in
production.

A run is bound to one route at creation. The gateway calls only that binding. If the route is disabled, the
destination is unregistered or the provider fails, the run ends; there is **no fallback** to another provider,
model or region.

Every prompt is redacted (credential patterns) and the number of redactions is counted. Members above the route's
classification are withheld, **content and metadata alike** (digest, filename, size, raw locator, normalised fields).
The withholding of metadata was added after a test found digests leaking.

Usage is recorded per call: tokens as reported, or estimated and labelled for the fake, with cost from the route's
prices and the latency.

Providers:
* `DeterministicFakeProvider` is a rule-based stand-in for CI, plus `fake-adversarial:<behaviour>` for tests. It is
  not a language model.
* `AnthropicMessagesProvider` follows the documented Messages API shape. It has been tested against a local transport
  only.

### 3. Durable runs (`investigation/runner.py`, `service.py`)
A run has explicit questions (1 to 10), frozen tool grants, a budget (rounds, model calls, tool calls, input tokens,
output tokens, cost) and a deadline. It executes as a job, one round per fenced job step, and waits between rounds.

At the start of each round the runner checks, in this order:
1. cancellation requested: `cancelled`;
2. the requester no longer holds `investigation.run`: `cancelled` (authority_revoked);
3. route not approved, or gateway refused: `failed`;
4. deadline passed or budget exhausted: `incomplete`.

The model step is recorded as `started` and counted **before** the call. A worker crash leaves it to be marked
`lost` (still counted), and the run resumes.

Failure handling:
* Retryable provider errors are retried up to the route's `max_retries`; then the run is `incomplete`.
* Non-retryable provider errors make the run `failed`.
* Malformed output gets one corrective retry; then the run is `incomplete`.

A run is `completed` only when the model reports done and at least one claim survived validation.

### 4. Claims (`investigation/claims.py`, `schema.py`)
The output schema has no action fields, and unknown fields make the output malformed. `model_stated_confidence` is
an uncalibrated label and is never used as a probability.

Each claim states a subject (vulnerability, asset, attribute) and a conclusion (supported, contradicted, unknown),
citing supporting and contradicting member keys.

**Rejected** when:
* a reference is fabricated, or comes from another snapshot, case or tenant;
* a reference is unavailable (unverified, above the route's classification, or unreadable by the requester);
* the subject is not in the snapshot;
* a reference is valid but concerns another vulnerability or asset;
* a reference's recorded status contradicts what it is cited for;
* a definite conclusion has no record on the cited side.

**Downgraded to unknown** when:
* it ignores a recorded contradiction;
* only stale evidence is decisive;
* the attribute cannot be established from snapshot contents (exposure);
* the latest observation of the subject points the other way. The evaluation harness found that a claim citing both
  sides could otherwise draw the outdated conclusion.

**Every** claim is stored with `entailment = not_verified`. The platform checks references, subjects and recorded
statuses, not reasoning.

### 5. Tools (`investigation/tools.py`)
All tools are read-only:
* `snapshot_member` and `asset_history` take member keys of the run's own snapshot;
* `evidence_excerpt` returns at most 4096 bytes per call, checks integrity, requires the requester's current
  classification permission and the route's classification limit, and audits each read;
* `advisory_lookup` reads OSV `GET /v1/vulns/{id}`. Its fixed template accepts an identifier pattern only. It must be
  enabled in `AXIOM_TOOL_DESTINATIONS` and granted on the run. Reference URLs in its response are returned as text and
  never fetched.

Arguments are typed with unknown fields refused. Output is bounded. Every call, refused ones included, is a recorded
step. Grants are frozen at creation, so content cannot add tools or change permissions or policies.

### 6. Decisions
`record_assessment` may cite `investigation_run_id` and/or `evidence_snapshot_id`. Citing a run requires it to be
completed or incomplete, and requires that **every claim it did not reject has a human review** (confirmed,
rejected, or corrected with a corrected conclusion). The run's limitations and the snapshot's contradiction and gap
counts are appended to the decision's limitations.

Priority stays with the deterministic policy, and the AI has no command path. Database backstops (trigger, using
`axiom_auth.principal_kind`):
* workload principals may insert only `reopen` and `prioritisation` decisions;
* approvals and claim reviews must come from humans.

## Consequences
* Investigations are slower and more constrained than a free-form chat. Many outputs end `incomplete` or carry
  downgraded claims; that is intended.
* The guards depend on structured statuses (presence, absence, freshness). Claims about exploitability or
  reachability cannot be established from scanner data and are downgraded until such evidence types exist.
* The fake provider makes CI deterministic, but it measures nothing about model quality.

## Not done or not verified
* Any real model call. `tests/integration/test_real_provider_optin.py` is opt-in and has never been run.
* Calibration, which is not attempted.
* An investigation UI.
* Per-tenant budgets and quotas (X09).
* Model data-residency policy beyond the route's region label.
* Retention rules for step records.
* Additional evidence types (reachability, runtime, threat intelligence).
* Human-reviewed evaluation references (the current labels are author-drafted).

## Amendment (2026-10-22, checkpoint 5): what the claim checks are, and system authority

### What the claim checks are, and what they are not
The checks in `investigation/claims.py` are **deterministic record checks**. They are not semantic relevance or
entailment validation, and no check reads the claim's statement text. They are:

1. **Existence and membership**: every cited key is a member of the run's own snapshot (same case, same tenant).
2. **Availability**: the member is verified, within the route's classification limit and readable by the requester.
3. **Subject matching by identifier equality**: the cited member's vulnerability, asset and (when the claim names
   one) asset version equal the claim's subject. Two records about the same identifiers can still be irrelevant to
   what the statement says; this check cannot tell.
4. **Recorded-status consistency**: a member cited as supporting presence must record presence; one cited as
   contradicting must record absence in a complete scan or a source fix.
5. **Freshness**: if only stale members decide the conclusion, it is downgraded to unknown.
6. **Structured contradiction rules**: the snapshot records presence disagreements per deployment with an
   ordering result. Ordering is by the **source's reported scan time**, never import time. It is `by_scan_time`
   only when every observation has a scan time and the latest time is held by one observation; otherwise it is
   `undetermined` with a reason (missing time, tie, different sources). A definite conclusion over an
   `undetermined` contradiction is downgraded to unknown (`unresolved_contradiction`) and the contradiction stays
   open for a person. A conclusion against the `by_scan_time` result is downgraded (`latest_observation_disagrees`).
7. **Deployment scoping**: when the vulnerability affects several deployments, a presence claim must name one
   (`deployment_unspecified`); evidence about one deployment never decides another.
8. **Attributes that cannot be established** from snapshot data (exposure, exploitability) are downgraded.

Every claim is stored with `entailment = not_verified`, and the UI labels claims "references checked, reasoning not
verified". A claim that passes every check is `references_checked`, which means only that.

Tests for the five required cases:
* a valid reference that does not support the claim: `adv::test_valid_but_irrelevant_citations_are_rejected` and
  `invu::` cases (subject_mismatch, status_conflicts_with_citation). A reference with matching identifiers and a
  consistent status whose content still does not support the statement's wording is **not detected**; that is what
  human review is for;
* newer evidence about a different deployment: `inv::test_newer_scan_of_a_different_deployment_does_not_change_this_one`;
* newer but incomplete evidence: partial scans never count as absence (H3 and H10 in the evaluation set, ingestion
  coverage tests) and stale evidence is downgraded (`adv::test_stale_evidence_alone_cannot_support_a_conclusion`);
* conflicting observations without a defensible order:
  `inv::test_same_reported_scan_time_leaves_the_contradiction_open_for_a_person`;
* several claims, some supported and some unresolved: `inv::test_one_run_with_supported_and_unresolved_claims`.

### Discretionary decisions versus policy-authorised system results (migration 0014)
The first version of the database backstop ("workload principals may insert only reopen and prioritisation
decisions") was replaced. The rule is now:
* **Humans** make discretionary decisions: assessments, dismissals, claim reviews, approvals, risk acceptance,
  overrides and every consequential action authorisation. Approvals and claim reviews must have a human actor.
* **System identities** (workload principals, such as each tenant's system principal) may record a decision only
  when it is a deterministic, policy-authorised result within the permission recorded in its authority:
  `prioritisation` under `priority.apply` (including reassessment after an override expires),
  `verification_review` under `verification.record` (a verification observation; none is produced yet), and
  `reopen` on recurrence or acceptance expiry (or with `case.reopen`). Everything else is refused with SQLSTATE 42501.
* The principal type is read by `axiom_auth.principal_kind`, a security-definer function owned by `axiom_authn` that reads
  the identity tables. It never comes from the transaction context or request data
  (`ovr::test_principal_kind_comes_from_identity_records_not_the_context`, `::test_api_cannot_assert_principal_kind`).
* Limitation: the trigger checks the permission name in the recorded authority; the permission itself is evaluated
  by the service layer (`Authorizer`). The trigger does not re-evaluate role bindings.

Requirements changed by the earlier human-only trigger: it would have blocked a verification worker (VER-04) and
override-expiry reassessment (PRI-05). Both are now possible within explicit authority; VER-04 remains unbuilt.

## Amendment 2 (2026-10-22, checkpoint 6): review of the human and system authority boundary

### How the server decides who is acting
* **Principal type** comes only from `axiom.principals.kind`, the identity record created at provisioning. Requests,
  tokens and sessions cannot set it: API bodies reject unknown fields; token claims are not read for kind or roles;
  the session stores only the principal ID. The API resolves the principal from (issuer, audience or client ID,
  subject) and takes `kind` from that record. Database guards read it through `axiom_auth.principal_kind` (security
  definer, owned by `axiom_authn`). Since checkpoint 6 the audit trail also records the kind from the identity record,
  not from the in-process context.
* **Permission**: every command calls `Authorizer.require(permission, scope)`, which loads the actor's active role
  bindings (not revoked, inside their validity window, in an active and unexpired membership) at the target scope or
  an ancestor, on every request. Nothing is cached across requests.
* **Policy authorisation** for system results: the database decision guard (migration 0016) derives the permission a
  system result needs from the decision kind and checks it against the actor's real bindings with
  `axiom.holds_permission`, which mirrors `Authorizer`. The authority JSON on the row is no longer trusted (the 0014
  guard trusted it; see below).

### Every action a system principal can perform
The tenant system principal holds one role, `ingestion_worker` (case.read, case.create, case.reopen, asset.read,
asset.manage, ingestion.read, evidence.upload, job.read, priority.apply, ownership.route), bound at the tenant root.
Migration 0016 makes that role the only kind of role a workload principal can hold.

| Job | What it writes | Permission checked (service) | Decision recorded | Conditions |
|---|---|---|---|---|
| Ingestion run (`ingestion.run`) | assets, versions, occurrences, observations, cases, links | ingestion.read on the run scope; asset.manage, case.create | `reopen` with reason `recurrence` | Run requested by a person with ingestion.import; reopening needs case.reopen (service and database) |
| Risk expiry sweep | lapses undecided requests; marks acceptances expired | none (time-bound records reaching their recorded end) | `reopen` with reason `acceptance_expiry` | Only when the closure points at the expired acceptance chain; reopen needs case.reopen |
| Override expiry | ends expired overrides | priority.apply | `prioritisation` (current policy, provenance recorded) | Only overrides past `expires_at`; never restores the earlier priority |
| Ownership sweep | ownership records from published rules | ownership.route | none | Rule-based; ownership confers no authority |
| SLA sweep | timer state (breach, end) | none | none | Deterministic from recorded events and policy |
| Ticket sync | external ticket states (append-only) | none | none | Never changes the case |
| Action execution | the approved external effect; execution state | re-checks the **approver's** approve permission and the **requester's** execute permission at execution time | none | Needs an active, unexpired human approval of the exact payload digest; production change is not enabled |
| Investigation run | steps, claims (append-only) | reads use the **requester's** current permissions | none | Cannot record reviews or decisions |

A system principal cannot: assess, dismiss or close a case; plan, defer or withdraw remediation; accept risk or
authorise a risk request; override priority; approve or reject an action; review a claim; reopen on a person's
judgement (relevant_change, authorised_reassessment); assign roles. Each is refused by the service (no permission)
and, for decisions, approvals and claim reviews, by the database guard.

### Gaps found by this review and fixed
1. **The 0014 guard trusted the decision's authority JSON.** A workload insert naming `priority.apply` was accepted
   without the database checking that the actor held it. Migration 0016 checks real bindings; a test shows a
   project-scoped workload refused on another project's case even with a forged authority.
2. **Workload reopening for any reason** was accepted when the JSON named `case.reopen`, including
   `authorised_reassessment`. Now only recurrence and acceptance expiry.
3. **System reopening skipped the permission check in the service** (`reopen(system=True)`). It now requires
   case.reopen like any reopening, and refuses other reasons before loading the case.
4. **Nothing stopped binding a human role to a workload principal**, which would have given the system principal
   discretionary authority (the database guard would still have refused its decisions, approvals and reviews).
   Workload principals can now hold only workload roles, and humans only human roles.
5. **The audit trail recorded the in-process context's kind.** It now reads the identity record.

System authority was not broadened: no permission was added to `ingestion_worker`, and `verification.record` is
still held by no workload, so no system verification result can be recorded until a verification worker is designed
and authorised.

### Tests
`tests/integration/test_system_authority_boundary.py` (discretionary approval, risk acceptance and override by the
system; forged authority; human roles on workloads; principal type in requests and tokens; other tenant and other
project; revoked system binding; role and membership revocation with the same bearer token); the session variant in
`test_oidc_sso.py`; override expiry under a newly published policy in `test_authority_and_overrides.py`.
Limitation: `axiom.holds_permission` duplicates `access.evaluate` in SQL; both must change together.

## Amendment 3 (2026-10-22, checkpoint 7): adversarial review of the authority fixes

The checkpoint-6 fixes (migration 0016, service checks, the audit kind) were reviewed as one boundary. Each finding
below was reproduced on the checkpoint-6 revision (1eed24c) before the fix; the test body is the reproducer.

### Entry points reviewed
| What | Where | Identity and kind from | Permission checked against |
|---|---|---|---|
| Case decisions (assess, plan, defer, report, verify, close, dismiss, accept risk, override, prioritise) | `CaseService._apply` | the transaction's bound principal; kind from `axiom.principals` | `Authorizer.require` at the case scope; database guard on `axiom.decisions` |
| Risk request decisions | `domains/cases/risk.py` | same | same |
| Approvals | `ActionService` | same | per-class `action.approve:<class>` at the proposal scope; guard on `axiom.approvals` |
| Claim reviews | `InvestigationService` | same | `claim.review`; guard on `axiom.claim_reviews` |
| Reopen by a person | `CaseService.reopen` | same | `case.reopen`; human reasons only for people |
| Reopen by the system | ingestion recurrence, risk expiry sweep (`reopen(system=True)`) | tenant system principal | `case.reopen`; guard allows workload reopen only for `recurrence` and `acceptance_expiry` |
| Verification by the worker (new, ADR 0014) | `verification/worker.py` | tenant verification principal | `verification.record`; guard checks it at the case scope |
| Role assignment and revocation | `TenancyService` (API), `Provisioner.bootstrap_role` (CLI) | bound principal / provisioning identity | `role.assign`; `role_binding_kind_guard` (kind compatibility) |
| Membership suspension | `TenancyService` | bound principal | `membership.manage` |
| Principal records | `Provisioner.create_principal`, `create_tenant`, `create_verification_identity` | provisioning identity (`axiom_admin_cli`) | database grants; no application role can update `kind` |

Principal type is never taken from a request, token claim or session (unchanged from amendment 2, retested over the
API with a workload bearer token: workload results accepted, discretionary commands refused, audit kind `workload`).

### Demonstrated defects (fixed in migration 0017)
| | Preconditions | Reproducer | Observed on checkpoint 6 | Regression test |
|---|---|---|---|---|
| D1 | Code holding the runtime role in a transaction bound to principal X | insert into `axiom.decisions` (or `axiom.approvals`) naming principal Y as actor | the row committed: an assessment attributed to a person, written by the system context; an approval attributed to a risk owner, written by an approver | `test_d1_bound_transaction_cannot_record_a_decision_as_someone_else`, `test_d1_approvals_must_be_recorded_by_the_bound_principal` |
| D2 | Same | `SELECT axiom.bind_context(tenant, other_principal)` inside a bound transaction | re-binding succeeded | `test_d2_a_bound_transaction_cannot_switch_principal` |
| D3 | A command that has passed its permission check, and a concurrent revocation of that role binding or membership | revoke in another transaction while the command's transaction is open | the revocation committed first; the command then committed a decision whose authority was already revoked | `test_d3_revocation_waits_for_a_command_that_already_checked_the_permission[role, membership]` |

D1 and D2 need code running with the runtime database role; no API request reproduced them (the API binds the
authenticated principal). They mattered because the database guards were documented as enforcing who decides, and
did not when the row named another actor. The guards now require the recorded actor to be the bound principal, and a
transaction can bind only one principal.

### Hardening without an application-level exploit
* **H1 bindings created before 0016.** 0016 checked kind compatibility only on new bindings; an incompatible binding
  that already existed stayed live. `axiom_auth.revoke_incompatible_bindings()` (run once by 0017, re-runnable by the
  provisioning identity, idempotent) revokes them and records a security event for each
  (`role_binding.incompatible_revoked`, reason `<role>:<holder kind>`). Test injects one with triggers disabled.
* **H2 principal kind changes.** No application or provisioning role can update `axiom.principals.kind`; only the owner
  could. A trigger now refuses any change of kind, so a kind change can never leave incompatible bindings behind.

### The revocation guarantee, stated at a transaction boundary
`Authorizer.bindings_for` reads the actor's bindings and membership `FOR SHARE`. Therefore:
* a revocation or suspension that **commits before** a command's permission check is seen by that check, and the
  command is refused;
* a revocation that **starts after** the check waits until the command's transaction commits or rolls back; the
  command's decision is therefore one its authority covered at commit time;
* nothing stronger is claimed. A command already committed stays committed (decisions are append-only), a browser
  showing a stale page learns of the revocation on its next request, and a job's earlier transactions are not
  re-evaluated (ADR 0014 describes the worker's boundary). The share lock adds blocking: a revocation can wait for
  the longest open command of that principal.

### Trust boundary that remains
The runtime database role is trusted to bind the principal the API authenticated. A compromised runtime credential
can bind any principal of its tenant and act as it; the database guards do not defend against that.
`axiom.holds_permission` still duplicates `access.evaluate` in SQL.

### Tests
`tests/integration/test_authority_review_cp7.py` (9 tests). Reproducer output against checkpoint 6 is in
`docs/verification/2026-10-22-checkpoint7/reproducers-on-cp6.txt`.
