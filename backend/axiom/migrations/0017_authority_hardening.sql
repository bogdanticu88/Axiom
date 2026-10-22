-- 0017 Authority hardening after the checkpoint-7 adversarial review (ADR 0012 amendment 3).
--
-- Demonstrated before this migration (tests/integration/test_authority_review_cp7.py):
--   1. A transaction bound to principal X (for example the system principal) could insert a decision, approval or
--      claim review naming another principal Y as the actor; the guards read the actor from the row, so a decision
--      attributed to a human passed the human branch untouched.
--   2. axiom.bind_context allowed re-binding a different principal inside an already bound transaction.
-- Hardened here, without a demonstrated exploit through the application:
--   3. Role bindings that already existed before 0016 were not checked against the workload/human role rule.
--   4. axiom.principals.kind could be changed by the schema owner, leaving incompatible bindings behind (no application
--      or provisioning identity holds UPDATE on that column, so this needs the owner or a superuser).
--
-- What the database can and cannot establish: the runtime role is trusted to bind the principal the API
-- authenticated. These guards keep each transaction to one principal and make every recorded actor that principal;
-- they do not defend against a compromised runtime credential, which could bind any principal of its tenant.

-- ---------------------------------------------------------------------------- one principal per transaction
CREATE OR REPLACE FUNCTION axiom.bind_context(p_tenant uuid, p_principal uuid) RETURNS void
LANGUAGE plpgsql VOLATILE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  existing uuid := axiom.current_tenant();
  existing_principal uuid := axiom.current_principal();
BEGIN
  IF p_tenant IS NULL OR p_principal IS NULL THEN
    RAISE EXCEPTION 'tenant and principal context are required' USING ERRCODE = '42501';
  END IF;
  IF existing IS NOT NULL AND existing <> p_tenant THEN
    RAISE EXCEPTION 'tenant context already bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF existing_principal IS NOT NULL AND existing_principal <> p_principal THEN
    RAISE EXCEPTION 'principal context already bound in this transaction' USING ERRCODE = '42501';
  END IF;
  PERFORM set_config('axiom.ctx', p_tenant::text || '|' || p_principal::text || '|' || axiom.tx_marker(), true);
END
$$;

-- ---------------------------------------------------------------------------- the actor is the bound principal
CREATE OR REPLACE FUNCTION axiom.human_decision_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  actor uuid;
  kind text;
  what text := TG_TABLE_NAME;
  needed text;
  case_scope uuid;
  allowed boolean := false;
BEGIN
  IF TG_TABLE_NAME = 'decisions' THEN
    actor := NEW.actor_principal_id;
    what := 'decision ' || NEW.kind;
  ELSIF TG_TABLE_NAME = 'approvals' THEN
    actor := NEW.approver_principal_id;
  ELSE
    actor := NEW.reviewer;
  END IF;
  IF actor IS DISTINCT FROM axiom.current_principal() THEN
    RAISE EXCEPTION '% must be recorded by the principal bound to the transaction', what USING ERRCODE = '42501';
  END IF;
  kind := axiom_auth.principal_kind(actor);
  IF kind = 'human' THEN
    RETURN NEW;
  END IF;
  IF kind = 'workload' AND TG_TABLE_NAME = 'decisions' THEN
    needed := CASE
      WHEN NEW.kind = 'prioritisation' THEN 'priority.apply'
      WHEN NEW.kind = 'verification_review' THEN 'verification.record'
      WHEN NEW.kind = 'reopen' AND NEW.outcome IN ('recurrence', 'acceptance_expiry') THEN 'case.reopen'
      ELSE NULL END;
    IF needed IS NOT NULL THEN
      SELECT scope_id INTO case_scope FROM axiom.finding_cases WHERE id = NEW.case_id;
      allowed := COALESCE(axiom.holds_permission(actor, needed, case_scope), false);
      IF NOT allowed THEN
        RAISE EXCEPTION '% by a workload principal requires % at the case scope, which it does not hold',
          what, needed USING ERRCODE = '42501';
      END IF;
    END IF;
  END IF;
  IF NOT allowed THEN
    RAISE EXCEPTION '% by a % principal is not a policy-authorised system result', what, COALESCE(kind, 'unknown')
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;

-- ---------------------------------------------------------------------------- principal kind is immutable
CREATE FUNCTION axiom.principals_kind_immutable() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.kind IS DISTINCT FROM OLD.kind THEN
    RAISE EXCEPTION 'a principal''s kind cannot change; create a new principal' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER principals_kind_immutable BEFORE UPDATE OF kind ON axiom.principals
  FOR EACH ROW EXECUTE FUNCTION axiom.principals_kind_immutable();

-- ---------------------------------------------------------------------------- bindings that predate 0016
-- Revokes every active binding whose role is not for the holder's kind and records one installation security event
-- per binding (event_type role_binding.incompatible_revoked, reason_code role:holder_kind). Returns the number
-- revoked. Runs once below and may be re-run by the provisioning identity; idempotent. axiom_authn (owner of axiom_auth)
-- gets exactly what it needs: read bindings, set revoked_at, append security events.
CREATE POLICY authn_role_bindings_review ON axiom.role_bindings FOR SELECT TO axiom_authn USING (true);
CREATE POLICY authn_role_bindings_revoke ON axiom.role_bindings FOR UPDATE TO axiom_authn USING (true) WITH CHECK (true);
GRANT SELECT ON axiom.role_bindings TO axiom_authn;
GRANT UPDATE (revoked_at) ON axiom.role_bindings TO axiom_authn;
CREATE POLICY authn_security_events ON axiom.security_events FOR INSERT TO axiom_authn WITH CHECK (true);
GRANT INSERT ON axiom.security_events TO axiom_authn;

SET LOCAL ROLE axiom_authn;
CREATE FUNCTION axiom_auth.revoke_incompatible_bindings() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  b record;
  n integer := 0;
BEGIN
  FOR b IN
    SELECT rb.tenant_id, rb.id, rb.principal_id, rb.role_id, p.kind AS holder
      FROM axiom.role_bindings rb JOIN axiom.principals p ON p.id = rb.principal_id JOIN axiom.roles r ON r.id = rb.role_id
     WHERE rb.revoked_at IS NULL AND p.kind IS DISTINCT FROM r.principal_kind
     FOR UPDATE OF rb
  LOOP
    UPDATE axiom.role_bindings SET revoked_at = clock_timestamp() WHERE tenant_id = b.tenant_id AND id = b.id;
    INSERT INTO axiom.security_events(id, principal_id, requested_tenant, correlation_id, event_type, reason_code)
      VALUES (gen_random_uuid(), b.principal_id, b.tenant_id::text, 'incompatible-binding-review',
              'role_binding.incompatible_revoked', b.role_id || ':' || b.holder);
    n := n + 1;
  END LOOP;
  RETURN n;
END
$$;
REVOKE ALL ON FUNCTION axiom_auth.revoke_incompatible_bindings() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION axiom_auth.revoke_incompatible_bindings() TO axiom_owner, axiom_provisioner;
GRANT USAGE ON SCHEMA axiom_auth TO axiom_provisioner;
SET LOCAL ROLE axiom_owner;
SELECT axiom_auth.revoke_incompatible_bindings();
