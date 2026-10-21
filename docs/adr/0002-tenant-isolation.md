# ADR 0002: Tenant isolation mechanism

Status: accepted for Phase A (2026-10-22); revisit when workers, caches and exports are added

## Context
Shared multi-client installations are a first production requirement (Plan 14). Isolation must hold across records,
jobs, objects, credentials, caches, search, exports and model requests (S 2 B06). The data design proposes PostgreSQL
row-level security (RLS) as defence in depth.

## Decision
1. **Every tenant-owned table** carries `tenant_id`, uses `(tenant_id, id)` keys and composite tenant-aware foreign
   keys. A row in tenant A cannot reference a row in tenant B, whatever the application does.
2. **RLS is enabled and forced** on all tenant and identity tables. The single policy for the runtime role is
   `tenant_id = axiom.current_tenant() AND axiom.current_tenant_active()` for both visibility and writes. Missing context
   means zero rows.
3. **Context is bound to the transaction**, not the session. `axiom.bind_context(tenant, principal)` stores
   `tenant|principal|<transaction timestamp>:<backend pid>`, and `axiom.current_tenant()` ignores the value unless the
   marker matches the current transaction. A buggy session-level `set_config` therefore cannot leak into the next
   transaction on a pooled connection. Rebinding to another tenant inside a transaction raises an error. Pool
   check-in also runs `RESET ALL`.
4. **Context is set only after authorisation**: token validation, principal resolution and membership check happen
   through `axiom_auth` SECURITY DEFINER functions before `bind_context`.
5. **Separate identities** (ADR 0003): the runtime login never owns objects, is never superuser or BYPASSRLS, and the
   API refuses to start otherwise.
6. **Object storage** keys are server-generated as `tenants/<tenant>/evidence/<id>`; a `TenantObjectStore` wrapper
   refuses keys outside the bound tenant.
7. **Denials** inside a tenant are audited in that tenant; denials without a tenant (selection of a tenant the caller
   cannot use) go to the installation `security_events` table.

## Limits (explicit)
* **Context-based RLS does not contain a compromised application.** The runtime role can call `bind_context` for any
  tenant; an attacker controlling the application process can therefore choose any tenant context. RLS protects
  against application bugs, missing filters and confused queries, not against full application compromise. Stronger
  separation needs narrower service credentials per workload, authenticated workload grants, or a dedicated
  installation (Plan 14 allows routing such tenants to dedicated deployments).
* A PostgreSQL superuser bypasses RLS and can drop triggers; append-only triggers resist the application owner role,
  not a database superuser. Independent signed checkpoints (EVD-08) are the planned mitigation.
* Storage credentials are installation-wide today; tenant-scoped storage identities are planned (TEN-06).
* Caches, search, exports, workers and model requests do not exist yet; their isolation is planned, not claimed.

## Verification
tests/integration/test_isolation.py (no-context, cross-tenant FK, switch inside transaction, session-level leak,
pool reuse with rollback and tenant switch on one connection, suspended tenant, identity tables, provisioner and relay
privileges, append-only, direct-SQL bypass, tenant selection oracle). See docs/VERIFICATION.md.
