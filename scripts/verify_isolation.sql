-- Execute as provisioning identity after migration, in a disposable database.
-- Entire test transaction rolls back.
\set ON_ERROR_STOP on
BEGIN;
INSERT INTO axiom.tenants VALUES
 ('00000000-0000-0000-0000-000000000001','A','active'),
 ('00000000-0000-0000-0000-000000000002','B','active');
INSERT INTO axiom.scopes(tenant_id,id,name) VALUES
 ('00000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','A scope'),
 ('00000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000002','B scope');
SET LOCAL ROLE axiom_runtime;
DO $$ BEGIN
 IF (SELECT count(*) FROM axiom.scopes) <> 0 THEN RAISE EXCEPTION 'missing context leaked rows'; END IF;
END $$;
SELECT set_config('axiom.tenant_id','00000000-0000-0000-0000-000000000001',true);
DO $$ BEGIN
 IF (SELECT count(*) FROM axiom.scopes) <> 1 THEN RAISE EXCEPTION 'tenant isolation failed'; END IF;
 BEGIN
  INSERT INTO axiom.finding_cases(tenant_id,id,scope_id) VALUES
   ('00000000-0000-0000-0000-000000000001',gen_random_uuid(),'10000000-0000-0000-0000-000000000002');
  RAISE EXCEPTION 'cross tenant FK accepted';
 EXCEPTION WHEN foreign_key_violation THEN NULL; END;
 BEGIN
  INSERT INTO axiom.scopes(tenant_id,id,name) VALUES
   ('00000000-0000-0000-0000-000000000002',gen_random_uuid(),'forbidden');
  RAISE EXCEPTION 'cross tenant insert accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
SELECT set_config('axiom.tenant_id','',true);
DO $$ BEGIN
 IF (SELECT count(*) FROM axiom.scopes) <> 0 THEN RAISE EXCEPTION 'cleared context leaked rows'; END IF;
END $$;
ROLLBACK;
\echo 'Isolation checks passed; fixture changes rolled back.'
