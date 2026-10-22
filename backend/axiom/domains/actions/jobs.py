"""Job handler that executes one reserved approval use through the effect gate."""
from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from ...ingestion.sync import EnvSecretResolver, SecretResolver
from ...integrations.jira_style import JiraStyleClient, JiraStyleTicketAdapter
from ...jobs import Done, EffectGate, Fail, JobContext, NeedsOperator, Retry
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
                    set_execution_state(conn, execution_id, "reconciling",
                                        {"problem": f"{ref} does not carry the operation label"})
                    return NeedsOperator(f"external object {ref} does not carry operation label for {key}")
                intent = conn.execute("SELECT resolution FROM axiom.effect_intents WHERE operation_key = %s",
                                      (key,)).fetchone()
                how = _how(intent, outcome.how)
                finish_execution(conn, jc.ctx, execution_id, "succeeded", external_ref=ref, how=how, verified=True)
            return Done({"execution_id": str(execution_id), "external_ref": ref, "how": how})
        with jc.db.tenant_tx(jc.ctx) as conn:
            if isinstance(step, Fail):
                state = "cancelled" if "cancelled" in step.error else "failed"
                finish_execution(conn, jc.ctx, execution_id, state, detail={"error": step.error})
            elif isinstance(step, NeedsOperator):
                set_execution_state(conn, execution_id, "reconciling", {"reason": step.reason})
        return step
