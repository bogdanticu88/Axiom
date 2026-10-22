-- 0019 Verification worker destination policy (ADR 0014 amendment 1).
-- Records the address the worker actually connected to (after the destination policy checked it) and whether the
-- stored response had the request's credential redacted from it.
ALTER TABLE axiom.verification_observations
  ADD COLUMN connected_address inet,
  ADD COLUMN response_redacted boolean NOT NULL DEFAULT false;
