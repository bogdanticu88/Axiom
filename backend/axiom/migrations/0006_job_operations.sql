-- 0006 Job operations (ADR 0006 conditions): operator retry of dead-lettered and failed jobs.
--
-- A finished job stays immutable except for one explicit operator move: dead_lettered or failed -> queued, which
-- must increment operator_retries and may only raise the attempt and claim budgets. Retrying never touches
-- approvals or reservations; an action job that is retried re-runs the full pre-execution re-check.

ALTER TABLE axiom.jobs ADD COLUMN operator_retries int NOT NULL DEFAULT 0;
GRANT UPDATE (operator_retries, max_attempts, max_claims) ON axiom.jobs TO axiom_runtime;

CREATE OR REPLACE FUNCTION axiom.jobs_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'queued' OR NEW.lease_token <> 0 OR NEW.claims <> 0 OR NEW.attempts <> 0
       OR NEW.operator_retries <> 0 THEN
      RAISE EXCEPTION 'jobs are created queued and unclaimed' USING ERRCODE = '23514';
    END IF;
    IF NEW.db_fingerprint <> axiom.db_fingerprint() THEN
      RAISE EXCEPTION 'job fingerprint must be the current database fingerprint' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.db_fingerprint IS DISTINCT FROM OLD.db_fingerprint AND NEW.db_fingerprint <> axiom.db_fingerprint() THEN
    RAISE EXCEPTION 'job fingerprint can only be set to the current database fingerprint' USING ERRCODE = '23514';
  END IF;
  IF (NEW.tenant_id, NEW.id, NEW.kind, NEW.payload, NEW.created_by, NEW.created_at, NEW.dedupe_key,
      NEW.aggregate_type, NEW.aggregate_id)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.id, OLD.kind, OLD.payload, OLD.created_by, OLD.created_at, OLD.dedupe_key,
      OLD.aggregate_type, OLD.aggregate_id) THEN
    RAISE EXCEPTION 'job definition is immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.operator_retries <> OLD.operator_retries THEN
    IF NOT (OLD.state IN ('dead_lettered', 'failed') AND NEW.state = 'queued'
            AND NEW.operator_retries = OLD.operator_retries + 1) THEN
      RAISE EXCEPTION 'operator retry moves a dead-lettered or failed job back to queued, one at a time'
        USING ERRCODE = '23514';
    END IF;
  ELSIF OLD.state IN ('succeeded', 'failed', 'dead_lettered', 'cancelled') THEN
    RAISE EXCEPTION 'finished job is immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.max_attempts < OLD.max_attempts OR NEW.max_claims < OLD.max_claims THEN
    RAISE EXCEPTION 'retry budgets can only grow' USING ERRCODE = '23514';
  END IF;
  IF NEW.lease_token < OLD.lease_token OR NEW.claims < OLD.claims OR NEW.attempts < OLD.attempts THEN
    RAISE EXCEPTION 'lease token, claim and attempt counters cannot decrease' USING ERRCODE = '23514';
  END IF;
  IF NEW.record_version <> OLD.record_version + 1 THEN
    RAISE EXCEPTION 'job record_version must increment by one' USING ERRCODE = '40001';
  END IF;
  IF NEW.handler_version <> OLD.handler_version AND OLD.state = 'running' THEN
    RAISE EXCEPTION 'cannot migrate a running job' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE INDEX jobs_state_kind ON axiom.jobs(tenant_id, state, kind);
CREATE INDEX job_events_event ON axiom.job_events(tenant_id, event, created_at);
