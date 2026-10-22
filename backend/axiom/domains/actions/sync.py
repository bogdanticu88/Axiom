"""Inbound ticket synchronisation (ACT-09): poll the state of verified external references.

State changes are recorded append-only in ``axiom.external_ticket_states`` and announced on the outbox. They never move
the platform case: a ticket closed externally does not close, verify or otherwise change the case (Specification
S 9). Webhook delivery (``handle_authenticated_event``) is not built (ING-08); polling is the only source.
"""
from __future__ import annotations

import uuid

from ... import audit, outbox
from ...ingestion.sync import EnvSecretResolver, SecretResolver
from ...jobs import Done, JobContext
from .jobs import AdapterFactory, default_adapter_factory

KIND = "actions.ticket_sync"


class TicketSyncHandler:
    kind = KIND
    versions = frozenset({1})
    current_version = 1

    def __init__(self, adapter_factory: AdapterFactory = default_adapter_factory,
                 secrets: SecretResolver | None = None):
        self.adapter_factory, self.secrets = adapter_factory, secrets or EnvSecretResolver()

    def step(self, jc: JobContext):
        with jc.db.tenant_tx(jc.ctx) as conn:
            jc.fenced(conn)
            refs = conn.execute(
                """SELECT r.*, c.status AS connection_status, c.adapter, c.base_url, c.credential_ref, c.config,
                          c.id AS conn_id,
                          (SELECT s.status_category FROM axiom.external_ticket_states s WHERE s.reference_id = r.id
                            ORDER BY s.observed_at DESC, s.id DESC LIMIT 1) AS last_category,
                          (SELECT s.status FROM axiom.external_ticket_states s WHERE s.reference_id = r.id
                            ORDER BY s.observed_at DESC, s.id DESC LIMIT 1) AS last_status
                     FROM axiom.external_references r JOIN axiom.connections c ON c.id = r.connection_id
                    WHERE r.verified AND c.status = 'active'""").fetchall()
        adapters, checked, changed, errors = {}, 0, 0, []
        for r in refs:
            if r["last_category"] == "missing":
                continue
            connection = {"id": r["conn_id"], "adapter": r["adapter"], "base_url": r["base_url"],
                          "credential_ref": r["credential_ref"], "config": r["config"]}
            try:
                adapter = adapters.setdefault(r["conn_id"], self.adapter_factory(connection, self.secrets))
                status, category = adapter.fetch_state(r["external_id"])
            except Exception as exc:  # noqa: BLE001 - one unreachable ticket must not stop the others
                errors.append({"reference_id": str(r["id"]), "error": f"{type(exc).__name__}: {exc}"[:200]})
                continue
            checked += 1
            if (status, category) == (r["last_status"], r["last_category"]):
                continue
            with jc.db.tenant_tx(jc.ctx) as conn:
                jc.fenced(conn)
                conn.execute(
                    """INSERT INTO axiom.external_ticket_states(tenant_id, id, reference_id, status, status_category, source)
                       VALUES (%s, %s, %s, %s, %s, 'poll')""",
                    (jc.ctx.tenant_id, uuid.uuid4(), r["id"], status, category))
                audit.record(conn, jc.ctx, action="external_ticket.state_observed", resource_type="external_reference",
                             resource_id=r["id"], detail={"status": status, "category": category,
                                                          "previous": r["last_category"]})
                outbox.enqueue(conn, jc.ctx, topic=f"external_ticket.{category}", aggregate_type="finding_case",
                               aggregate_id=r["case_id"], payload={"reference_id": str(r["id"]),
                                                                   "external_id": r["external_id"], "status": status,
                                                                   "case_unchanged": True})
            changed += 1
        return Done({"checked": checked, "changed": changed, "errors": errors})
