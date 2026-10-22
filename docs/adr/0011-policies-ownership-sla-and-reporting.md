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
