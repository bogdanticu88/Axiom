-- PostgreSQL-only workflow runner for single approved remediation actions (spike).
-- Applied by the test harness as the database owner into a throwaway database.
-- Worker processes connect as a non-superuser role with DML only (see grant_worker()).

CREATE SCHEMA wf;

-- Per-tenant concurrency limit, enforced inside the claim transaction.
CREATE TABLE wf.tenant_limits (
    tenant_id      text PRIMARY KEY,
    max_concurrent int  NOT NULL DEFAULT 1000 CHECK (max_concurrent > 0)
);

-- Who may approve. Re-checked at the fencing gate, immediately before the effect.
CREATE TABLE wf.grants (
    tenant_id  text NOT NULL,
    principal  text NOT NULL,
    permission text NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (tenant_id, principal, permission)
);

CREATE TABLE wf.workflow_runs (
    tenant_id          text        NOT NULL,
    id                 uuid        PRIMARY KEY,
    kind               text        NOT NULL,
    state              text        NOT NULL CHECK (state IN (
                           'awaiting_approval', 'ready', 'executing', 'retry_wait',
                           'needs_operator_reconciliation',
                           'completed', 'approval_expired', 'approval_mismatch', 'denied',
                           'cancelled', 'dead_lettered', 'abandoned')),
    version            int         NOT NULL DEFAULT 1,      -- bumped on every state change
    step               text        NOT NULL,
    proposal           jsonb       NOT NULL,
    proposal_digest    text        NOT NULL,
    approval_deadline  timestamptz,
    due_at             timestamptz,                         -- timer: claimable when due_at <= now(); NULL = not schedulable
    attempts           int         NOT NULL DEFAULT 0,      -- effect attempts (incremented at the gate)
    max_attempts       int         NOT NULL DEFAULT 5,
    cancel_requested   boolean     NOT NULL DEFAULT false,
    reconcile_required boolean     NOT NULL DEFAULT false,  -- set by the post-restore runbook step
    handler_version    int         NOT NULL,                -- pinned at creation
    detail             text,
    created_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at        timestamptz
);
CREATE INDEX workflow_runs_due ON wf.workflow_runs (due_at, created_at) WHERE due_at IS NOT NULL;
CREATE INDEX workflow_runs_tenant ON wf.workflow_runs (tenant_id);

CREATE TABLE wf.job_leases (
    run_id           uuid   PRIMARY KEY REFERENCES wf.workflow_runs (id),
    lease_owner      text,
    lease_expires_at timestamptz,
    fencing_token    bigint NOT NULL DEFAULT 0              -- +1 on every claim, never reused
);
CREATE INDEX job_leases_live ON wf.job_leases (lease_expires_at) WHERE lease_expires_at IS NOT NULL;

CREATE TABLE wf.approvals (
    id              bigserial PRIMARY KEY,
    run_id          uuid        NOT NULL REFERENCES wf.workflow_runs (id),
    tenant_id       text        NOT NULL,
    approver        text        NOT NULL,
    proposal_digest text        NOT NULL,
    expires_at      timestamptz NOT NULL,
    max_uses        int         NOT NULL DEFAULT 1,
    uses            int         NOT NULL DEFAULT 0,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- One row per external operation. operation_key = sha256(run_id || ':' || proposal_digest).
CREATE TABLE wf.execution_intents (
    operation_key text        PRIMARY KEY,
    run_id        uuid        NOT NULL REFERENCES wf.workflow_runs (id),
    tenant_id     text        NOT NULL,
    fencing_token bigint      NOT NULL,
    state         text        NOT NULL CHECK (state IN (
                      'prepared',    -- gate passed, external call NOT started (safe to redo without lookup)
                      'executing',   -- external call may have started
                      'succeeded', 'unknown', 'reconciled', 'failed')),
    attempt       int         NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at    timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE wf.execution_results (
    id              bigserial PRIMARY KEY,
    operation_key   text        NOT NULL,
    run_id          uuid        NOT NULL REFERENCES wf.workflow_runs (id),
    outcome         text        NOT NULL,   -- created | adopted | deduplicated_by_external | operator_adopted
    ticket_id       text,
    fencing_token   bigint,
    handler_version int,
    recorded_at     timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX execution_results_one_per_op ON wf.execution_results (operation_key);

CREATE TABLE wf.run_events (
    id            bigserial PRIMARY KEY,
    run_id        uuid        NOT NULL,
    event         text        NOT NULL,
    detail        text,
    worker        text,
    fencing_token bigint,
    at            timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX run_events_run ON wf.run_events (run_id, id);
