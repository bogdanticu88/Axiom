-- 0016 System authority is checked against real role bindings, and workload principals hold only workload roles
-- (checkpoint 6 review of migration 0014; ADR 0012 amendment 2).
--
-- Review finding: the 0014 guard accepted a workload decision when the decision's recorded authority JSON *named*
-- the right permission. The JSON is written by application code, so the database never checked that the actor held
-- the permission. It also let a workload reopen a case for any reason when the JSON named 'case.reopen', including
-- discretionary reasons (relevant_change, authorised_reassessment).
--
-- From this migration:
--   * The required permission is derived from the decision kind, never from the JSON, and the guard checks that the
--     actor holds it through an active role binding, in an active membership, at the case's scope or an ancestor.
--   * Reopening by a workload is limited to recurrence and acceptance_expiry, with case.reopen.
--   * A role binding may give a workload principal only roles marked for workloads (today: ingestion_worker), and a
--     human only roles marked for humans. System authority therefore cannot be broadened by binding a human role.

-- ---------------------------------------------------------------------------- permission check usable in SQL
-- Mirrors access.evaluate: binding not revoked, valid_from <= now < valid_until, membership active and unexpired,
-- binding scope is the target scope or one of its ancestors. Runs as the invoker, so RLS keeps it inside the
-- transaction's tenant.
CREATE FUNCTION axiom.holds_permission(p_principal uuid, p_permission text, p_scope uuid) RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
  WITH RECURSIVE up(id, parent_id, depth) AS (
      SELECT id, parent_id, 0 FROM axiom.scopes WHERE id = p_scope
      UNION ALL
      SELECT s.id, s.parent_id, up.depth + 1 FROM axiom.scopes s JOIN up ON s.id = up.parent_id WHERE up.depth < 64)
  SELECT EXISTS (
      SELECT 1 FROM axiom.role_bindings b
        JOIN axiom.memberships m ON m.tenant_id = b.tenant_id AND m.principal_id = b.principal_id
        JOIN axiom.role_permissions rp ON rp.role_id = b.role_id AND rp.permission = p_permission
       WHERE b.principal_id = p_principal
         AND b.scope_id IN (SELECT id FROM up)
         AND b.revoked_at IS NULL AND b.valid_from <= clock_timestamp()
         AND (b.valid_until IS NULL OR b.valid_until > clock_timestamp())
         AND m.status = 'active' AND (m.valid_until IS NULL OR m.valid_until > clock_timestamp()))
$$;
REVOKE ALL ON FUNCTION axiom.holds_permission(uuid, text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION axiom.holds_permission(uuid, text, uuid) TO axiom_runtime;

-- ---------------------------------------------------------------------------- decision guard
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

-- ---------------------------------------------------------------------------- which principals may hold a role
ALTER TABLE axiom.roles ADD COLUMN principal_kind text NOT NULL DEFAULT 'human'
  CHECK (principal_kind IN ('human', 'workload'));
UPDATE axiom.roles SET principal_kind = 'workload' WHERE id = 'ingestion_worker';

-- SECURITY DEFINER owned by axiom_authn (like axiom_auth.principal_kind): bindings are inserted by the runtime (role
-- assignment) and by the provisioning identity (bootstrap), and the guard must read the principal's kind from the
-- trusted identity record for both. axiom.principals is readable only by axiom_authn (forced RLS).
GRANT SELECT ON axiom.roles TO axiom_authn;
SET LOCAL ROLE axiom_authn;
CREATE FUNCTION axiom_auth.role_binding_kind_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  holder text := axiom_auth.principal_kind(NEW.principal_id);
  allowed_kind text := (SELECT r.principal_kind FROM axiom.roles r WHERE r.id = NEW.role_id);
BEGIN
  IF holder IS DISTINCT FROM allowed_kind THEN
    RAISE EXCEPTION 'role % is for % principals; this principal is %', NEW.role_id, allowed_kind,
      COALESCE(holder, 'unknown') USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION axiom_auth.role_binding_kind_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION axiom_auth.role_binding_kind_guard() TO axiom_owner;
-- axiom_owner may already SET ROLE axiom_authn; usage lets it attach the trigger below.
GRANT USAGE ON SCHEMA axiom_auth TO axiom_owner;
SET LOCAL ROLE axiom_owner;
CREATE TRIGGER role_bindings_kind_guard BEFORE INSERT OR UPDATE OF principal_id, role_id ON axiom.role_bindings
  FOR EACH ROW EXECUTE FUNCTION axiom_auth.role_binding_kind_guard();
