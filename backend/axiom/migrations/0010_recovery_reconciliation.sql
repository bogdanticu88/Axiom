-- 0010 Acknowledging a restore does not authorise replay (ADR 0010).
--
-- Acknowledgements become an append-only log (a rollback that keeps the fingerprint is acknowledged again under the
-- same fingerprint). Any job created before the latest acknowledgement is treated by the effect gate as carried
-- across a restore: integrations that cannot deduplicate park until an operator reconciles that job, which sets
-- recovery_cleared_at. Acknowledgement itself never clears a job.

ALTER TABLE axiom.recovery_acknowledgements DROP CONSTRAINT recovery_acknowledgements_pkey;
ALTER TABLE axiom.recovery_acknowledgements ADD COLUMN id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY;
CREATE INDEX recovery_acknowledgements_fingerprint ON axiom.recovery_acknowledgements(fingerprint);

ALTER TABLE axiom.jobs ADD COLUMN recovery_cleared_at timestamptz;
GRANT UPDATE (recovery_cleared_at) ON axiom.jobs TO axiom_runtime;
