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
| [0006](adr/0006-workflow-engine.md) | Durable workflow engine | **pending** | Temporal vs PostgreSQL-backed comparison in progress |
| [0007](adr/0007-dependency-pinning.md) | Dependency pinning | accepted | uv lock with cooldown; digest-pinned images |
| [0008](adr/0008-authentication.md) | Authentication | accepted for development | Dev token auth only; production SSO is a tracked gap |

## Proposed specification changes awaiting approval
| Ref | Proposal | Why | Status |
|---|---|---|---|
| R7 | Allow `remediation_planned -> review_required` and `remediating -> review_required` with an authorised decision | No way to abandon a plan today without a fake verification | awaiting decision; not implemented |

## Business decisions still open (from the specification, section 17)
Product name and licence; supported vendor editions and test accounts; approved model providers and offline-model
needs; volumes, retention and cost envelope; exact prioritisation policy, approval thresholds and evaluation release
thresholds. These do not reduce scope; they block only the specific items noted in REQUIREMENTS.md.
