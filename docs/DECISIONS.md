# Decisions index

Architecture decision records live in `docs/adr/`. Decisions taken in the design documents themselves are listed for
completeness.

| ID | Title | Status | Summary |
|---|---|---|---|
| P-14 | Shared and dedicated installations | approved by the project owner, 21 Oct 2026 (Plan 14) | One codebase; tenant is the data and authority boundary in both modes |
| [0001](adr/0001-repository-layout-and-package-name.md) | Repository layout and package name | accepted | `axiom` instead of `platform` (stdlib clash) |
| [0002](adr/0002-tenant-isolation.md) | Tenant isolation | accepted for Phase A | Forced RLS, composite FKs, transaction-bound context; RLS does not contain a compromised app |
| [0003](adr/0003-database-roles-and-migrations.md) | Database roles and migrations | accepted | Cluster roles provisioned separately; checksummed ledgered migrations |
| [0004](adr/0004-case-command-guards.md) | Case command guards and closure routes | accepted | Service plus DB guards; asset-retirement route; deferral; open items R7 and RISK-02 |
| [0005](adr/0005-evidence-storage.md) | Evidence storage and finalisation | accepted | API-streamed uploads, read-back hash verification, SeaweedFS for Compose |
| [0006](adr/0006-workflow-engine.md) | Durable workflow engine | **accepted** (2026-10-22) | PostgreSQL-backed job runner for Phases B-D; Temporal as named alternative with explicit revisit triggers |
| [0007](adr/0007-dependency-pinning.md) | Dependency pinning | accepted | uv lock with cooldown; digest-pinned images |
| [0008](adr/0008-authentication.md) | Authentication | accepted for development | Dev token auth only; production SSO is a tracked gap |
| [0009](adr/0009-ingestion-pipeline.md) | Ingestion pipeline, source identity, asset correlation | accepted for Phase B | Fenced page commits, coverage rules, strong/weak identifiers, no automatic merges |
| [0010](adr/0010-action-protocol-and-duplicate-prevention.md) | Action protocol, duplicate prevention, restore detection | accepted | DB-computed proposal digests; approvals bound to version and digest; locked reservations; capability-based effect gate (no repeat without provider dedupe or fencing); external restore witness |

## Proposed specification changes awaiting approval
| Ref | Proposal | Why | Status |
|---|---|---|---|
| R7 | Allow `remediation_planned -> review_required` and `remediating -> review_required` with an authorised decision | No way to abandon a plan today without a fake verification | awaiting decision; not implemented |

## Interim defaults pending business decisions
| Ref | Default in force | Where | Decision needed |
|---|---|---|---|
| D-RISK-1 | Independent risk authorisation for pending/urgent/high priority or more than 90 days; maximum 365 days; requests lapse after 14 days; reassessment notice 14 days before expiry | `RiskPolicy` (stored with each request) | Approval thresholds (Specification S 17) |
| D-ACT-1 | `ticket.create` approvals: at most 3 uses; proposals expire within 30 days | `domains/actions/model.py` | Approval thresholds (Specification S 17) |

## Business decisions still open (from the specification, section 17)
Product name and licence; supported vendor editions and test accounts; approved model providers and offline-model
needs; volumes, retention and cost envelope; exact prioritisation policy, approval thresholds and evaluation release
thresholds. These do not reduce scope; they block only the specific items noted in REQUIREMENTS.md.
