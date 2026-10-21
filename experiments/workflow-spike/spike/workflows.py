"""Remediation-action workflow: proposal -> durable approval wait -> guarded, reconciled effect."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

with workflow.unsafe.imports_passed_through():
    from spike import activities as acts
    from spike.models import (
        Approval,
        EffectRequest,
        OperatorResolution,
        RemediationInput,
        WorkflowOutcome,
    )

SHORT = timedelta(seconds=10)


@workflow.defn
class RemediationWorkflow:
    def __init__(self) -> None:
        self._approval: Approval | None = None
        self._resolution: OperatorResolution | None = None
        self._status = "starting"
        self._history: list[str] = []
        self._input: RemediationInput | None = None

    # ---- signals / queries -------------------------------------------------
    @workflow.signal
    def approve(self, approval: Approval) -> None:
        if self._approval is None:  # first approval wins; later ones are ignored
            self._approval = approval
            self._history.append(f"approval_received:{approval.approver}")

    @workflow.signal
    def operator_resolve(self, resolution: OperatorResolution) -> None:
        if self._resolution is None and self._status == "needs_operator_reconciliation":
            self._resolution = resolution

    @workflow.query
    def status(self) -> str:
        return self._status

    @workflow.query
    def history(self) -> list[str]:
        return list(self._history)

    # ---- helpers -----------------------------------------------------------
    def _set(self, status: str) -> None:
        self._status = status
        self._history.append(status)

    async def _event(self, event: str, detail: str) -> None:
        assert self._input is not None
        await workflow.execute_activity(
            acts.record_workflow_event,
            args=[workflow.info().workflow_id, self._input.platform_db, event, detail],
            start_to_close_timeout=SHORT,
        )

    async def _stop(self, status: str, detail: str, digest: str = "", key: str = "") -> WorkflowOutcome:
        self._set(status)
        await self._event(status, detail)
        return WorkflowOutcome(status=status, payload_digest=digest, operation_key=key,
                               detail=detail, history=list(self._history))

    # ---- main --------------------------------------------------------------
    @workflow.run
    async def run(self, inp: RemediationInput) -> WorkflowOutcome:
        self._input = inp
        wf_id = workflow.info().workflow_id

        # 1. Persist the canonical proposal and its digest (digest computed in the activity,
        #    then recorded in workflow history as the activity result).
        digest = await workflow.execute_activity(
            acts.persist_proposal, args=[wf_id, inp.proposal, inp.platform_db], start_to_close_timeout=SHORT
        )

        # 2. Durable wait for approval, bounded by a server-side timer.
        self._set("awaiting_approval")
        try:
            await workflow.wait_condition(
                lambda: self._approval is not None,
                timeout=timedelta(seconds=inp.approval_window_seconds),
            )
        except asyncio.TimeoutError:
            return await self._stop("approval_deadline_exceeded", "no approval before deadline", digest)

        approval = self._approval
        assert approval is not None
        if approval.payload_digest != digest:
            return await self._stop(
                "approval_mismatch",
                f"approved digest {approval.payload_digest[:16]} != proposal digest {digest[:16]}",
                digest,
            )
        if datetime.fromisoformat(approval.expires_at) <= workflow.now():
            return await self._stop("approval_expired", f"approval expired at {approval.expires_at}", digest)

        # 3. Stable operation key: same across activity retries, worker restarts and replays.
        op_key = hashlib.sha256(f"{wf_id}:{digest}".encode()).hexdigest()
        self._set("executing")
        req = EffectRequest(workflow_id=wf_id, operation_key=op_key, payload_digest=digest,
                            proposal=inp.proposal, platform_db=inp.platform_db, ticket_url=inp.ticket_url)
        try:
            res = await workflow.execute_activity(
                acts.execute_ticket_effect,
                req,
                start_to_close_timeout=timedelta(seconds=5),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=5),
                    maximum_attempts=10,
                    non_retryable_error_types=["UncertainEffect"],
                ),
            )
        except ActivityError as err:
            cause = err.cause
            if not (isinstance(cause, ApplicationError) and cause.type == "UncertainEffect"):
                raise
            # 4. Unknown outcome and no way to look it up: park for a human.
            self._set("needs_operator_reconciliation")
            await self._event("needs_operator_reconciliation", cause.message)
            await workflow.wait_condition(lambda: self._resolution is not None)
            r = self._resolution
            assert r is not None
            if r.decision == "adopt" and r.ticket_id:
                await workflow.execute_activity(
                    acts.record_operator_resolution,
                    args=[inp.platform_db, op_key, r.ticket_id, "operator_adopted"],
                    start_to_close_timeout=SHORT,
                )
                self._set("completed")
                await self._event("completed", f"operator {r.operator} adopted {r.ticket_id}")
                return WorkflowOutcome(status="completed", payload_digest=digest, operation_key=op_key,
                                       ticket_id=r.ticket_id, detail="operator_adopted", history=list(self._history))
            return await self._stop("abandoned_by_operator", r.note, digest, op_key)

        self._set("completed")
        await self._event("completed", f"{res.outcome} {res.ticket_id}")
        return WorkflowOutcome(status="completed", payload_digest=digest, operation_key=op_key,
                               ticket_id=res.ticket_id, detail=res.outcome, history=list(self._history))
