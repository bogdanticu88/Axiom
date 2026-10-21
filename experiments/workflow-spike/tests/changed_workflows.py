"""Two 'new deployments' of RemediationWorkflow, used only for replay (determinism) tests."""

from __future__ import annotations

from datetime import timedelta

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from spike.models import RemediationInput, WorkflowOutcome
    from spike.workflows import RemediationWorkflow


@workflow.defn(name="RemediationWorkflow")
class UnpatchedChange(RemediationWorkflow):
    """Adds a step before the existing ones without a patch marker: incompatible with old histories."""

    @workflow.run
    async def run(self, inp: RemediationInput) -> WorkflowOutcome:
        await workflow.sleep(timedelta(seconds=1))  # new 'cool-down' step
        return await super().run(inp)


@workflow.defn(name="RemediationWorkflow")
class PatchedChange(RemediationWorkflow):
    """Same change guarded by workflow.patched(): old histories take the old path."""

    @workflow.run
    async def run(self, inp: RemediationInput) -> WorkflowOutcome:
        if workflow.patched("cool-down-step"):
            await workflow.sleep(timedelta(seconds=1))
        return await super().run(inp)
