-- 0015 OIDC login state and browser sessions for the analyst UI (ADR 0013).
--
-- Installation-level records (no tenant): a login attempt (state, nonce, PKCE verifier, browser binding) and a
-- session (who signed in, through which issuer and subject, with absolute and idle expiry). Only hashes of the
-- browser-held secrets (state, binding, session token, CSRF token) are stored. The runtime role cannot read these
-- tables; it calls the narrow SECURITY DEFINER functions below, owned by axiom_authn like the other axiom_auth lookups.
-- Tenant membership and permissions are NOT part of a session: every request re-checks them (Design S 12).

CREATE TABLE axiom.ui_login_states (
  state_hash text PRIMARY KEY CHECK (state_hash ~ '^[0-9a-f]{64}$'),
  binding_hash text NOT NULL CHECK (binding_hash ~ '^[0-9a-f]{64}$'),
  issuer text NOT NULL,
  nonce text NOT NULL,
  code_verifier text,                 -- cleared when the state is consumed
  return_to text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CHECK (consumed_at IS NULL OR code_verifier IS NULL)
);

CREATE TABLE axiom.ui_sessions (
  id uuid PRIMARY KEY,
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  csrf_hash text NOT NULL CHECK (csrf_hash ~ '^[0-9a-f]{64}$'),
  principal_id uuid NOT NULL REFERENCES axiom.principals(id),
  issuer text NOT NULL,
  subject text NOT NULL,
  idp_session_id text,                -- 'sid' claim when the IdP provides one
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  idle_seconds int NOT NULL CHECK (idle_seconds BETWEEN 60 AND 86400),
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  revoke_reason text
);
CREATE INDEX ui_sessions_principal ON axiom.ui_sessions(principal_id) WHERE revoked_at IS NULL;

ALTER TABLE axiom.ui_login_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE axiom.ui_login_states FORCE ROW LEVEL SECURITY;
ALTER TABLE axiom.ui_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE axiom.ui_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY ui_login_states_authn ON axiom.ui_login_states TO axiom_authn USING (true) WITH CHECK (true);
CREATE POLICY ui_sessions_authn ON axiom.ui_sessions TO axiom_authn USING (true) WITH CHECK (true);
GRANT SELECT, INSERT ON axiom.ui_login_states, axiom.ui_sessions TO axiom_authn;
GRANT UPDATE (consumed_at, code_verifier) ON axiom.ui_login_states TO axiom_authn;
GRANT UPDATE (last_seen_at, revoked_at, revoke_reason) ON axiom.ui_sessions TO axiom_authn;

SET LOCAL ROLE axiom_authn;

CREATE FUNCTION axiom_auth.login_state_create(p_state_hash text, p_binding_hash text, p_issuer text, p_nonce text,
                                           p_verifier text, p_return_to text, p_ttl_seconds int)
RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO axiom.ui_login_states(state_hash, binding_hash, issuer, nonce, code_verifier, return_to, expires_at)
  VALUES (p_state_hash, p_binding_hash, p_issuer, p_nonce, p_verifier, p_return_to,
          clock_timestamp() + make_interval(secs => LEAST(GREATEST(p_ttl_seconds, 30), 900)))
$$;

-- Single use: the first caller with the matching browser binding gets the verifier; replays get nothing.
CREATE FUNCTION axiom_auth.login_state_consume(p_state_hash text, p_binding_hash text)
RETURNS TABLE (issuer text, nonce text, code_verifier text, return_to text)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH s AS (SELECT state_hash, issuer, nonce, code_verifier, return_to FROM axiom.ui_login_states
              WHERE state_hash = p_state_hash AND binding_hash = p_binding_hash AND consumed_at IS NULL
                AND expires_at > clock_timestamp() FOR UPDATE),
       u AS (UPDATE axiom.ui_login_states l SET consumed_at = clock_timestamp(), code_verifier = NULL
               FROM s WHERE l.state_hash = s.state_hash RETURNING l.state_hash)
  SELECT s.issuer, s.nonce, s.code_verifier, s.return_to FROM s JOIN u USING (state_hash)
$$;

CREATE FUNCTION axiom_auth.session_create(p_id uuid, p_token_hash text, p_csrf_hash text, p_principal uuid, p_issuer text,
                                       p_subject text, p_sid text, p_ttl_seconds int, p_idle_seconds int)
RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  INSERT INTO axiom.ui_sessions(id, token_hash, csrf_hash, principal_id, issuer, subject, idp_session_id, expires_at,
                             idle_seconds)
  VALUES (p_id, p_token_hash, p_csrf_hash, p_principal, p_issuer, p_subject, p_sid,
          clock_timestamp() + make_interval(secs => LEAST(GREATEST(p_ttl_seconds, 60), 86400)), p_idle_seconds)
$$;

-- A session is usable while: not revoked, before absolute expiry, within the idle window, and its principal is
-- still active. Use refreshes last_seen_at. Membership is checked separately on every request.
CREATE FUNCTION axiom_auth.session_use(p_token_hash text)
RETURNS TABLE (session_id uuid, principal_id uuid, principal_kind text, csrf_hash text, issuer text, subject text)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE axiom.ui_sessions s SET last_seen_at = clock_timestamp()
    FROM axiom.principals p
   WHERE s.token_hash = p_token_hash AND p.id = s.principal_id AND p.status = 'active'
     AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp()
     AND s.last_seen_at + make_interval(secs => s.idle_seconds) > clock_timestamp()
  RETURNING s.id, s.principal_id, p.kind, s.csrf_hash, s.issuer, s.subject
$$;

CREATE FUNCTION axiom_auth.session_revoke(p_token_hash text, p_reason text)
RETURNS int LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH r AS (UPDATE axiom.ui_sessions SET revoked_at = clock_timestamp(), revoke_reason = left(p_reason, 200)
              WHERE token_hash = p_token_hash AND revoked_at IS NULL RETURNING 1)
  SELECT count(*)::int FROM r
$$;

REVOKE ALL ON FUNCTION axiom_auth.login_state_create(text, text, text, text, text, text, int),
  axiom_auth.login_state_consume(text, text),
  axiom_auth.session_create(uuid, text, text, uuid, text, text, text, int, int),
  axiom_auth.session_use(text), axiom_auth.session_revoke(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION axiom_auth.login_state_create(text, text, text, text, text, text, int),
  axiom_auth.login_state_consume(text, text),
  axiom_auth.session_create(uuid, text, text, uuid, text, text, text, int, int),
  axiom_auth.session_use(text), axiom_auth.session_revoke(text, text) TO axiom_runtime;

SET LOCAL ROLE axiom_owner;
