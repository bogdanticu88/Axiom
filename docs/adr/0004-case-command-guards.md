# ADR 0004: Case command guards, closure routes and interpretations

Status: accepted (2026-10-22)

## Context
The specification defines the case state machine and guard conditions (S 4). The supplied code checked only closure
guards using caller-supplied booleans. Several points were ambiguous (review findings R2 to R5, R7, R9, R10).

## Decision
### Two layers
1. **Service commands** (`domains/cases/service.py`) are the only write path. Each loads authoritative rows, checks
   expected version, permission at the case scope, separation of duties, and guard inputs, then writes decision,
   dependent rows, audit event, versioned case update, case event and outbox message in one transaction.
2. **Database guards** (migration 0002) reject anything that bypasses the service:
   * immediate row trigger: allowed transitions only, version increments by exactly one, identity and scope immutable,
     closed cases immutable until reopened, creation only as received/unassessed/pending/unset;
   * deferred constraint trigger at COMMIT: a case event exists at the new version describing the exact transition and
     referencing an audit event (NOT NULL FK), and any closure has a valid reason-specific closure record.

Database checks validate what the database can see. They do not replace authorisation and cannot judge whether a
rationale is sound.

### Closure routes
| Reason | From | Prerequisites (service and DB) |
|---|---|---|
| verified_remediated | awaiting_verification | assessment `supported`; a passed verification with complete coverage of the **latest** remediation report; observed deployment equals the reported target version; verified evidence; closer is not the change reporter |
| accepted_risk | review_required | active risk acceptance for this case, within the accepting principal's delegation limit (priority and duration; unknown priority treated as urgent); acceptor is not the case owner |
| dismissed | review_required | assessment `not_supported` from an assessment decision citing verified supporting evidence; dismisser holds `case.dismiss` and is not the assessor |
| duplicate | review_required | target case in the same tenant, readable by the caller, not itself closed as a duplicate, sharing at least one vulnerability reference on the same asset; links are retained |
| asset_retired | review_required | see below |

### Asset-retirement route (review finding R2)
The specification's transition table omits retirement, while S 10 and D 7 require it as a distinct outcome with
independent lifecycle evidence that does not count as a fix. Decision:
* `closed` from `review_required` with reason `asset_retired`;
* the cited retirement evidence must be `verified` (hash- and size-checked) and readable by the closer at its
  classification;
* the case must have at least one active occurrence link, and **every** linked affected asset must already be
  `lifecycle_status='retired'` with its own verified retirement evidence (recorded via the asset retirement command,
  which needs `asset.manage`);
* closure records keep `retirement_evidence_id`; reporting must count these separately from remediation (VER-05,
  reporting not yet built).
Verified by `test_asset_retirement_closure_requires_retired_assets` (refused while the asset is active; accepted after
retirement).

### Other interpretations
* **Deferral** keeps `review_required` with `disposition='defer'` and a mandatory review date within 365 days.
* **Disposition vs closure reason**: closure reason is authoritative; disposition records intended treatment.
* **Inconclusive**: both an inconclusive assessment and an inconclusive verification block verified closure.
* **Verification outcomes are computed, not asserted**: a claimed pass is downgraded to inconclusive when the observed
  deployment is unknown or different, coverage is incomplete, or evidence is not verified. Failure observed on a
  different deployment is also inconclusive.
* **Reopen** (`closed -> investigating`) needs a reason (`relevant_change`, `recurrence`, `authorised_reassessment`,
  or `acceptance_expiry` from the system sweep only) and resets assessment and disposition; earlier closure records
  remain.
* **Verifier role**: `verification.record` is held by analysts; the change reporter cannot verify or close.

### Open items (not silently changed)
* **No route back** from `remediation_planned` or `remediating` to review when a plan is abandoned (R7). Proposed
  specification change: allow `remediation_planned -> review_required` and `remediating -> review_required` with an
  authorised decision. Awaiting approval; not implemented.
* **Risk acceptance is single-step** (R9): a risk owner authorises directly within limits. The specified
  request / authorise / renew flow (RISK-02) is not built. This is an acknowledged gap, not a scope change.
