"""Ids-only remediation workflow.

Inputs, signals, activity arguments and results carry only identifiers, digests and verdict codes:
  input   SecureInput(tenant_id, run_id, proposal_digest, approval_window_seconds)
  signal  approval_ready(approval_id)          -- a wake-up, NOT an authorisation
  results "ok" | verdict code | ticket id
Everything sensitive (proposal text, approver identity, evidence) stays in the platform DB and is
loaded inside activities.

The approval signal is non-authoritative: any client with namespace access can send it, so the
workflow verifies the referenced approval row through an activity, and a bad reference does not
end the workflow (that would let any client cancel actions by sending garbage). The effect activity
re-checks the approval immediately before acting (revocation).

Activities run on `<workflow task queue>-act`, so workflow workers and activity workers can be
separate processes (used by the stale-worker and backup tests).
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError, CancelledError
from temporalio.workflow import ActivityCancellationType

with workflow.unsafe.imports_passed_through():
    from spike.secure_activities import SecureActivities
    from spike.secure_models import SecureInput, SecureOutcome

SHORT = timedelta(seconds=10)
EFFECT_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    maximum_interval=timedelta(seconds=2),
    maximum_attempts=10,
    non_retryable_error_types=["ApprovalRevoked", "StaleAttempt", "ProposalMismatch", "UncertainEffect"],
)


@workflow.defn
class SecureRemediationWorkflow:
    def __init__(self) -> None:
        self._pending: list[str] = []
        self._status = "starting"

    @workflow.signal
    def approval_ready(self, approval_id: str) -> None:
        self._pending.append(approval_id)

    @workflow.query
    def status(self) -> str:
        return self._status

    async def _event(self, inp: SecureInput, event: str, detail: str) -> None:
        await workflow.execute_activity_method(
            SecureActivities.record_event, args=[inp.tenant_id, inp.run_id, event, detail],
            task_queue=workflow.info().task_queue + "-act", start_to_close_timeout=SHORT)

    async def _stop(self, inp: SecureInput, status: str, code: str = "") -> SecureOutcome:
        self._status = status
        await self._event(inp, status, code)
        return SecureOutcome(status=status, reason_code=code)

    @workflow.run
    async def run(self, inp: SecureInput) -> SecureOutcome:
        act_q = workflow.info().task_queue + "-act"
        t, r, d = inp.tenant_id, inp.run_id, inp.proposal_digest
        try:
            await workflow.execute_activity_method(
                SecureActivities.check_proposal, args=[t, r, d], task_queue=act_q, start_to_close_timeout=SHORT,
                retry_policy=RetryPolicy(maximum_attempts=3))

            self._status = "awaiting_approval"
            deadline = workflow.now() + timedelta(seconds=inp.approval_window_seconds)
            approval_id: str | None = None
            while approval_id is None:
                remaining = (deadline - workflow.now()).total_seconds()
                try:
                    if remaining <= 0:
                        raise asyncio.TimeoutError
                    await workflow.wait_condition(lambda: bool(self._pending), timeout=remaining)
                except asyncio.TimeoutError:
                    return await self._stop(inp, "approval_deadline_exceeded")
                candidate = self._pending.pop(0)
                verdict = await workflow.execute_activity_method(
                    SecureActivities.verify_approval, args=[t, r, d, candidate], task_queue=act_q,
                    start_to_close_timeout=SHORT)
                if verdict == "valid":
                    approval_id = candidate
                else:
                    await self._event(inp, "approval_signal_rejected", verdict)

            self._status = "executing"
            try:
                ticket = await workflow.execute_activity_method(
                    SecureActivities.execute_effect, args=[t, r, d, approval_id], task_queue=act_q,
                    start_to_close_timeout=timedelta(seconds=120), heartbeat_timeout=timedelta(seconds=2),
                    retry_policy=EFFECT_RETRY,
                    cancellation_type=ActivityCancellationType.WAIT_CANCELLATION_COMPLETED)
            except ActivityError as err:
                cause = err.cause
                if isinstance(cause, CancelledError):
                    raise  # handled below as workflow cancellation
                if isinstance(cause, ApplicationError) and cause.type in ("ApprovalRevoked", "StaleAttempt"):
                    return await self._stop(inp, "approval_revoked" if cause.type == "ApprovalRevoked"
                                            else "stale_attempt", cause.type)
                raise
            self._status = "completed"
            await self._event(inp, "completed", ticket)
            return SecureOutcome(status="completed", ticket_id=ticket)
        except (asyncio.CancelledError, ActivityError) as err:
            if isinstance(err, ActivityError) and not isinstance(err.cause, CancelledError):
                raise
            was = self._status
            self._status = "cancelled"
            # Cleanup after cancellation still runs activities; shield them from the cancellation.
            await asyncio.shield(asyncio.ensure_future(self._event(inp, "cancelled", f"while {was}")))
            raise
