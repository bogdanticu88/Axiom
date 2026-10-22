-- A disabled principal holds no permission (data design section 12, step 2).
--
-- People are refused at sign-in when disabled, but workload identities (the system and verification principals) never
-- sign in, and an approval is checked again at execution time against the approver's current authority. Both paths
-- go through the authority check, which did not read the principal's status. The application check now does; this is
-- the database copy used by the decision guard and the execution recheck.
--
-- The status is read, not locked. Disabling a principal is still outside the revocation boundary: it applies to the
-- next check, and a command that already passed its check may commit (ADR 0012 amendment 5).

CREATE OR REPLACE FUNCTION axiom.holds_permission(p_principal uuid, p_permission text, p_scope uuid) RETURNS boolean
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
        JOIN axiom.principals p ON p.id = b.principal_id AND p.status = 'active'
        JOIN axiom.role_permissions rp ON rp.role_id = b.role_id AND rp.permission = p_permission
       WHERE b.principal_id = p_principal
         AND b.scope_id IN (SELECT id FROM up)
         AND b.revoked_at IS NULL AND b.valid_from <= clock_timestamp()
         AND (b.valid_until IS NULL OR b.valid_until > clock_timestamp())
         AND m.status = 'active' AND (m.valid_until IS NULL OR m.valid_until > clock_timestamp()))
$$;
REVOKE ALL ON FUNCTION axiom.holds_permission(uuid, text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION axiom.holds_permission(uuid, text, uuid) TO axiom_runtime;
