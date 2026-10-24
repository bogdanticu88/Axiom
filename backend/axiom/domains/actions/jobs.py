"""Job handler that executes one reserved approval use through the effect gate.

Two responsibilities are kept apart after the effect step:

* **Observations** about the provider (an effect was created, adopted, rejected or is of unknown outcome) are
  recorded by the effect gate in ``effect_intents`` and job events, even after the lease is lost: the effect may
  already exist, and that fact must not be lost (``EffectGate._record``).
* **Transitions of the execution record** (succeeded, reconciling, failed, cancelled, and the approval use that
  finishing consumes or returns) are decisions taken on the job's behalf. Each one commits only in a transaction that
  first passes the lease check (``JobContext.fenced``), so it is made by the worker holding the job's current lease
  token. The execution belongs to exactly one job (``job_id`` is immutable), so that token identifies the attempt.
  A worker that has lost the lease records what it observed as ``execution_transition_discarded`` and stops; the
  current lease holder reruns the step, and the gate reconciles from the recorded intent (a recorded success is
  adopted, never created again).
"""
from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from ...ingestion.sync import EnvSecretResolver, SecretResolver
from ...integrations.jira_style import JiraStyleClient, JiraStyleTicketAdapter
from ...jobs import Done, EffectGate, Fail, JobContext, NeedsOperator, Retry, StaleLease
from ...jobs.core import event
from .service import EXECUTE_KIND, TERMINAL_EXECUTION, check_execution, finish_execution, set_execution_state

AdapterFactory = Callable[[dict, SecretResolver], object]


def default_adapter_factory(connection: dict, secrets: SecretResolver):
    """Real adapters for workflow connections. All are fixture-tested only (see each module)."""
    ref, cfg = connection["credential_ref"], connection.get("config") or {}
    if connection["adapter"] == "jira_style":
        client = JiraStyleClient(connection["base_url"], lambda: tuple(secrets.resolve(ref).split(":", 1)))
        return JiraStyleTicketAdapter(client)
    if connection["adapter"] == "servicenow":
        from ...integrations.servicenow import ServiceNowTicketAdapter
        return ServiceNowTicketAdapter(connection["base_url"], lambda: tuple(secrets.resolve(ref).split(":", 1)),
                                       table=cfg.get("table", "incident"),
                                       correlation_field=cfg.get("correlation_field", "correlation_id"),
                                       states=cfg.get("states"))
    if connection["adapter"] == "github_issues":
        from ...integrations.github_issues import GitHubIssueAdapter
        return GitHubIssueAdapter(cfg["repo"], lambda: secrets.resolve(ref),
                                  api=connection["base_url"] or "https://api.github.com")
    raise ValueError(f"no executor for adapter {connection['adapter']}")


def _how(intent: dict | None, gate_how: str | None) -> str:
    if gate_how in ("created", "adopted_by_lookup"):
        return gate_how
    resolution = (intent or {}).get("resolution") or ""
    if resolution.startswith("adopt:"):
        return "adopted_by_operator"
    if resolution in ("adopted by lookup", "provider reported the existing object"):
        return "adopted_by_lookup"
    return "created"


def _holds_lease(conn, jc: JobContext, observed: dict) -> bool:
    """The authorization for one execution transition, inside its transaction. Without the lease the transition is
    not applied; what this worker observed is recorded instead, and the caller stops the step."""
    try:
        jc.fenced(conn)
        return True
    except StaleLease:
        event(conn, jc.ctx, jc.job["id"], "execution_transition_discarded", lease_token=jc.lease_token,
              detail={"lease_token": jc.lease_token, **observed})
        return False


class ActionExecuteHandler:
    kind = EXECUTE_KIND
    versions = frozenset({1})
    current_version = 1

    def __init__(self, adapter_factory: AdapterFactory = default_adapter_factory,
                 secrets: SecretResolver | None = None):
        self.adapter_factory = adapter_factory
        self.secrets = secrets or EnvSecretResolver()

    def step(self, jc: JobContext):
        execution_id = UUID(jc.job["payload"]["execution_id"])
        with jc.db.tenant_tx(jc.ctx) as conn:
            jc.fenced(conn)
            e = conn.execute("SELECT * FROM axiom.action_executions WHERE id = %s", (execution_id,)).fetchone()
            if e is None:
                return Fail("execution not found")
            if e["state"] in TERMINAL_EXECUTION:
                return Done({"execution_id": str(execution_id), "state": e["state"], "already_finished": True})
            v = conn.execute("SELECT * FROM axiom.action_proposal_versions WHERE id = %s",
                             (e["proposal_version_id"],)).fetchone()
            connection = conn.execute("SELECT * FROM axiom.connections WHERE id = %s", (e["connection_id"],)).fetchone()
            if e["state"] == "prepared":
                set_execution_state(conn, execution_id, "executing")
        adapter = self.adapter_factory(connection, self.secrets)
        payload = v["canonical_payload"]
        request = {k: payload[k] for k in ("project_key", "summary", "description", "labels", "issue_type")
                   if k in payload}
        key = e["external_operation_id"]
        outcome = EffectGate(jc).run(adapter, request, lambda c: check_execution(c, jc.ctx, execution_id), key=key)
        step = outcome.step
        if isinstance(step, Done):
            ref = outcome.external_ref
            verified = adapter.verify(ref, key) if hasattr(adapter, "verify") else True
            if verified is None:
                return Retry(f"could not verify external reference {ref} yet")
            with jc.db.tenant_tx(jc.ctx) as conn:
                if verified is False:
                    problem = f"{ref} does not carry the operation label"
                    held = _holds_lease(conn, jc, {"intended": "reconciling", "external_ref": ref, "verified": False,
                                                   "problem": problem})
                    if held:
                        set_execution_state(conn, execution_id, "reconciling", {"problem": problem})
                else:
                    intent = conn.execute("SELECT resolution FROM axiom.effect_intents WHERE operation_key = %s",
                                          (key,)).fetchone()
                    how = _how(intent, outcome.how)
                    held = _holds_lease(conn, jc, {"intended": "succeeded", "external_ref": ref, "verified": True,
                                                   "how": how})
                    if held:
                        finish_execution(conn, jc.ctx, execution_id, "succeeded", external_ref=ref, how=how,
                                         verified=True)
            if not held:
                raise StaleLease(f"lease {jc.lease_token} lost before recording the execution outcome")
            if verified is False:
                return NeedsOperator(f"external object {ref} does not carry operation label for {key}")
            return Done({"execution_id": str(execution_id), "external_ref": ref, "how": how})
        held = True
        with jc.db.tenant_tx(jc.ctx) as conn:
            if isinstance(step, Fail):
                state = "cancelled" if "cancelled" in step.error else "failed"
                held = _holds_lease(conn, jc, {"intended": state, "error": step.error})
                if held:
                    finish_execution(conn, jc.ctx, execution_id, state, detail={"error": step.error})
            elif isinstance(step, NeedsOperator):
                held = _holds_lease(conn, jc, {"intended": "reconciling", "reason": step.reason})
                if held:
                    set_execution_state(conn, execution_id, "reconciling", {"reason": step.reason})
        if not held:
            raise StaleLease(f"lease {jc.lease_token} lost before recording the execution outcome")
        return step
