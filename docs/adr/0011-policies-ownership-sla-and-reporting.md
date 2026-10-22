# ADR 0011: Versioned policies, ownership routing, SLA clocks and report semantics

Status: accepted (2026-10-22). All thresholds and targets are **provisional** until the business confirms them
(Specification S 17; DECISIONS D-SLA-2, D-PRIO-1).

## Context
Prioritisation was previously set by test code writing the `priority` column directly. Ownership, SLA behaviour and
report coverage semantics were thin (migration 0011 had one SLA row per case and a report with one denominator). The
11:33 instruction asked for versioned rules, an unresolved-owner queue, documented clock behaviour, explicit unknowns
and coverage, reproducible snapshots and classification-aware auditor packages.

## Decision

### Policies (migration 0012, `domains/policies`)
* `axiom.policy_versions` holds versions of four kinds: `priority`, `ownership`, `sla`, `freshness`.
* A version is drafted with a rationale and validated by kind; the database computes the definition digest.
* Publishing needs `policy.publish` and a principal other than the author (service check plus a database CHECK).
  Publishing supersedes the previous published version of that kind; at most one is published per kind (unique index).
* Definitions are immutable (trigger); versions are never deleted.
* When nothing is published, a **built-in provisional default** applies, and every decision or timer that uses it says
  so (`policy_version_id` NULL, "built-in provisional default" in limitations or `provisional: true` in the snapshot).
* Decisions record `policy_version_id` (foreign key), so a later policy never rewrites earlier decisions (A14).

### Prioritisation (`domains/cases/priority.py`)
* `apply-priority-policy` takes the maximum source severity over active linked occurrences and the maximum asserted
  asset criticality from the latest business-context version, and maps them through the published matrix.
* Missing inputs are substituted with the policy's `unknown_severity` / `unknown_criticality` (conservative: high) and
  listed as limitations in the decision; they are never silently dropped.
* `override-priority` is a separate, recorded decision (`priority_override`) needing `override.propose`.
* Both write case events (`case.prioritised`, `case.priority_overridden`) carrying `priority_from` and `priority_to`;
  reports reconstruct priority from these events.

### Ownership (`domains/cases/ownership.py`)
* Rules match only explicit context: `scope_id`, `asset_kind`, `owner_ref`, `environment`, `criticality`. Context
  comes from asserted business context (`POST /assets/{id}/business-context`, basis `user_assertion`, permission
  `context.assert`), never from free text such as titles.
* Rules are evaluated in order; the first match names a principal. If that principal has no active membership, or no
  rule matches, or no context exists, or no policy is published, the case is **unresolved** with the reason recorded.
* `axiom.case_ownership` is append-only: rule assignments, manual overrides (reason required, permission
  `ownership.override`) and unresolved results, with the context used. The latest row is the current owner.
* `GET /ownership/unresolved` lists readable cases whose latest row is unresolved or that have none.
* **Ownership confers no authority.** Routing writes no role binding, delegation limit or permission; approval and
  risk acceptance are still checked against role bindings and delegation limits (tested).
* A sweep job (`cases.ownership_sweep`, every 15 minutes) routes cases that have never been routed.

### SLA clocks (`domains/cases/sla.py`, `axiom.sla_timers`)
* **Two clocks per cycle.** A cycle starts when the case is created and again at each reopening.
  * *Triage* starts at the cycle start and ends at the first prioritisation in the cycle. It is a deadline to decide
    priority, not to remediate: `met` if prioritised by the due time, otherwise `missed`.
  * *Remediation* starts at the first prioritisation in the cycle; due = start + target for the current priority +
    paused time.
* **Priority change.** The running remediation timer ends as `revised` and a new timer starts with the **same start**
  and the accumulated pause, with the new target. Elapsed time is never reset. If the new due time has already
  passed, the new timer is breached at that due time.
* **Pause and resume.** With `pause_on_deferral`, the clock stops from a `case.deferred` event until the next case
  event. Pauses are derived from event timestamps, so the result does not depend on when the sweep runs.
* **Breach.** Breach time is the due time itself (deterministic). It is recorded once, with one audit event and one
  outbox event. A recorded breach cannot be cleared (trigger), and a breached timer cannot become `met`.
* **End.** On closure:
  * `verified_remediated` ends the remediation timer as `met` (closed by the due time) or `missed`;
  * `accepted_risk` ends it as `risk_accepted`, never `met`, because accepted risk is not remediation;
  * dismissed, duplicate and retired-asset closures end it as `closed_without_fix`.
* Every timer records the policy version (or none, for the default) and a snapshot of the targets it used.
* Not modelled yet:
  * business-hours calendars;
  * pausing for reasons other than deferral (for example waiting on a vendor without a deferral);
  * reconstructing `paused` status in as-of reports, where a paused timer at time *t* is reported as running.

### Reports (`domains/reports/service.py`, `exposure_summary@2`)
* **Reconstructed as of a time** from append-only history only. Regenerating for the same `as_of` gives the same
  digest after later priority changes, timer revisions, workflow moves and imports (tested; a revised-timer bug was
  found and fixed by this test). Times in content are serialised in UTC.
* **Separate denominators** for cases (total, open, closed), occurrences (total, linked to open cases) and assets
  (total, retired, with occurrences).
* **Coverage by source**, per source kind, adapter and connection:
  * declared scope;
  * run count;
  * last run and its status;
  * last *successful* run and its coverage;
  * last run with *complete* coverage;
  * freshness (`fresh`, `stale` or `never_succeeded`) against the source-specific freshness policy published as of
    that time.

  `completeness` comes from the last successful run's coverage. A successful synchronisation with partial coverage is
  reported as such.
* **Unknowns, counted explicitly:**
  * unprioritised (`pending`) and unassessed open cases;
  * inconclusive assessments and verifications;
  * assets never observed by a complete scan;
  * sources that are not fresh or not complete.
* Accepted risk, dismissals, duplicates and retirements are counted apart from verified remediation.
* **Auditor evidence packages** (`POST /cases/{id}/evidence-package`) need `audit.read` at the tenant root, and
  `case.read` and `report.export` at the case scope. A package contains:
  * events and decisions, with their policy versions;
  * evidence references with digests;
  * verification runs, remediation reports and closure records;
  * risk records;
  * proposals, approvals and executions, with external references and ticket states;
  * ownership and SLA history.

  Evidence **content** is included only where the requester holds `evidence.read:<classification>`, and each such read
  is audited. Otherwise the item carries `withheld: requester lacks ...` with its digest. A package is stored as a
  snapshot (`evidence_package`) plus a JSON export, and every export read is digest-checked and audited.

## Consequences
* Priority can no longer be set by an unrecorded write in normal operation, and tests no longer inject it.
* Ownership gaps are visible as a queue instead of a silent NULL.
* SLA figures can be explained from events alone.
* Reports state what they do not know. The cost is a larger query, which is untuned and was not tested at volume.

## Not done or not tested
* No UI.
* No business-hours SLA calendar.
* No escalation notifications beyond outbox events.
* Ownership from external CMDB data, which has no connector.
* Report performance at scale.
* Freshness or ownership policies for multiple tenants with different source mixes, which is configurable but untested.

## Amendment (2026-10-22, review requested by the project owner)
**Deferral no longer pauses by default.** The remediation clock pauses only when a deferral states a `pause_reason`
listed in the SLA policy's `pause_reasons`. The default list is `vendor_fix_pending`, `change_freeze` and
`awaiting_risk_decision`; any other reason is refused with `pause_reason_not_authorised`. A deferral without a reason
keeps the case open with a review date, and time keeps counting.

Each pause interval is stored on the timer (`pauses`) with its reason and who recorded the deferral.
`GET /cases/{id}/sla` reports, for every timer:
* gross elapsed time;
* paused time;
* adjusted elapsed time;
* the target;
* whether the target is exceeded on gross time and on adjusted time.

Report snapshots (`exposure_summary@4`) add `remediation_over_target_on_gross_time`, which is reproducible as of
a time because the target is fixed per timer. Tests:
* `sla::test_deferral_without_an_authorised_reason_keeps_the_clock_running`;
* `sla::test_gross_paused_and_adjusted_time_are_reported_separately`.

**Evidence metadata needs explicit permission.** Hiding file content alone was not enough. In evidence packages and
snapshot reads, metadata (digest, size, media type, filename) is disclosed only with `evidence.read:<classification>`
or the new `evidence.metadata:<classification>` (role `evidence_metadata_reader` for internal and confidential;
restricted metadata is a privileged permission). Without either, only the reference and its classification appear,
with `metadata_withheld`. The auditor role has no metadata permission by default. Tests:
* `rpt::test_evidence_package_withholds_content_the_requester_cannot_read`;
* `inv::test_snapshot_reads_disclose_content_and_metadata_only_with_permission`.

## Amendment (2026-10-22, checkpoint 5): override expiry and impact preview
**Every priority override expires.** `override-priority` takes `expires_at` (default 90 days, at most 365; D-PRIO-2,
provisional). Overrides are rows in `axiom.priority_overrides` (migration 0014) with the priority before the override,
the deciding decision and an end reason (`expired`, `superseded`, `case_closed`); at most one is active per case.
While one is active, `apply-priority-policy` refuses with `override_active`, so policy runs cannot silently undo a
human decision.

**Expiry reassesses; it never restores.** The `cases.priority_override_expiry` job (every 15 minutes per tenant, same
interval as the SLA sweep) ends each expired override by re-applying the **current published policy to current
inputs** as the tenant's system principal. The resulting `prioritisation` decision records provenance: the override
ID, its priority, when it expired, and the priority before the override, with the limitation "not restored to the
earlier X". The earlier priority is never reinstated just because it was there before
(`ovr::test_override_holds_until_expiry_then_policy_reassesses_with_provenance`,
`::test_expired_override_does_not_restore_a_stale_priority`). Overrides on closed cases end with `case_closed` and no
decision.

**Impact preview does not mutate.** `POST /policies/{id}/preview` (a draft or published priority version) and
`POST /policies/preview` (an unsaved definition) evaluate the policy against every open case the requester can read
(`policy.preview`, held by policy administrators and analysts) and return, per case: current and preview priority,
whether it changes, effective inputs, missing inputs, the case's current policy version, and any active override
that would hold the case. Totals count cases that would change, held by override, and with missing inputs. The only
write is an audit record `policy.previewed`. A test compares events, decisions, case priorities and versions, and
overrides before and after (`ovr::test_preview_shows_effects_without_changing_anything`,
`ui::test_policy_preview_is_read_only_in_the_ui`). Preview is limited to 2000 cases per call and says when it is
truncated.

Not done: a second approver for overrides by policy; override review reminders before expiry; preview of ownership,
SLA or freshness policies.
