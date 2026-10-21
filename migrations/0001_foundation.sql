-- Apply as a provisioning/migration identity in a fresh PostgreSQL database.
BEGIN;
CREATE ROLE axiom_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE SCHEMA axiom;
REVOKE ALL ON SCHEMA axiom FROM PUBLIC;
GRANT USAGE ON SCHEMA axiom TO axiom_runtime;

CREATE FUNCTION axiom.current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
 SELECT nullif(current_setting('axiom.tenant_id', true), '')::uuid
$$;
REVOKE ALL ON FUNCTION axiom.current_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION axiom.current_tenant() TO axiom_runtime;

CREATE TABLE axiom.tenants (
 id uuid PRIMARY KEY,
 name text NOT NULL,
 status text NOT NULL CHECK (status IN ('active','suspended','deleting'))
);
CREATE TABLE axiom.scopes (
 tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
 id uuid NOT NULL,
 parent_id uuid,
 name text NOT NULL,
 PRIMARY KEY (tenant_id,id),
 FOREIGN KEY (tenant_id,parent_id) REFERENCES axiom.scopes(tenant_id,id),
 CHECK (parent_id IS DISTINCT FROM id)
);
CREATE TABLE axiom.evidence_objects (
 tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
 id uuid NOT NULL,
 scope_id uuid NOT NULL,
 object_key text NOT NULL,
 sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
 size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
 status text NOT NULL CHECK(status IN ('pending','verified','deleting','deleted')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),
 UNIQUE(tenant_id,object_key),
 FOREIGN KEY(tenant_id,scope_id) REFERENCES axiom.scopes(tenant_id,id)
);
CREATE TABLE axiom.finding_cases (
 tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
 id uuid NOT NULL,
 scope_id uuid NOT NULL,
 workflow text NOT NULL DEFAULT 'received' CHECK(workflow IN
 ('received','investigating','review_required','remediation_planned','remediating','awaiting_verification','closed')),
 assessment text NOT NULL DEFAULT 'unassessed' CHECK(assessment IN
 ('unassessed','supported','not_supported','inconclusive')),
 priority text NOT NULL DEFAULT 'pending' CHECK(priority IN ('pending','urgent','high','medium','low')),
 record_version bigint NOT NULL DEFAULT 0 CHECK(record_version >= 0),
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,scope_id) REFERENCES axiom.scopes(tenant_id,id)
);
CREATE TABLE axiom.case_events (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 case_id uuid NOT NULL,
 sequence bigint NOT NULL,
 actor_id uuid NOT NULL,
 event_type text NOT NULL,
 payload jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),
 UNIQUE(tenant_id,case_id,sequence),
 FOREIGN KEY(tenant_id,case_id) REFERENCES axiom.finding_cases(tenant_id,id)
);
CREATE TABLE axiom.outbox (
 tenant_id uuid NOT NULL REFERENCES axiom.tenants(id),
 id uuid NOT NULL,
 event_id uuid NOT NULL,
 payload jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 delivered_at timestamptz,
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,event_id) REFERENCES axiom.case_events(tenant_id,id)
);

-- Runtime can read its tenant, but cannot provision or change tenant status.
ALTER TABLE axiom.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE axiom.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON axiom.tenants FOR SELECT TO axiom_runtime USING(id=axiom.current_tenant());
GRANT SELECT ON axiom.tenants TO axiom_runtime;

DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['scopes','evidence_objects','finding_cases','case_events','outbox'] LOOP
  EXECUTE format('ALTER TABLE axiom.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE axiom.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_boundary ON axiom.%I TO axiom_runtime USING
   (tenant_id=axiom.current_tenant() AND EXISTS(SELECT 1 FROM axiom.tenants WHERE id=tenant_id AND status=''active''))
   WITH CHECK (tenant_id=axiom.current_tenant() AND EXISTS(SELECT 1 FROM axiom.tenants WHERE id=tenant_id AND status=''active''))',t);
 END LOOP;
END $$;
GRANT SELECT,INSERT ON axiom.scopes,axiom.evidence_objects,axiom.finding_cases,axiom.case_events,axiom.outbox TO axiom_runtime;
-- Domain mutation functions/transactions are implemented in subsequent migrations.
-- No generic runtime UPDATE, DELETE or TRUNCATE privilege is granted.
CREATE INDEX case_queue ON axiom.finding_cases(tenant_id,scope_id,workflow,priority);
CREATE INDEX outbox_pending ON axiom.outbox(tenant_id,created_at) WHERE delivered_at IS NULL;
COMMIT;
