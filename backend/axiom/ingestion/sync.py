"""Connections and API synchronisation (Tenable export, Azure Resource Graph).

* Connections hold configuration and a *reference* to a secret (``secretref:...``), never the secret.
* Every API page is stored as verified evidence (classification 'confidential') before it is parsed,
  so observations always point at preserved raw data.
* Pages are keyed by content digest: a resumed sync that re-fetches identical pages skips them.
* Checkpoints advance only when the run completes with complete coverage, in the finalisation
  transaction (S 5: advance checkpoints only after durable writes).
* Source completeness: Tenable export FINISHED with no failed/cancelled chunks; Resource Graph all pages
  fetched without truncation. Neither supports absence inference (an export window or a query result is not
  proof that something no longer exists).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from collections.abc import Callable
from typing import Any, Protocol
from uuid import UUID

from psycopg.types.json import Jsonb

from .. import audit, outbox
from ..access import Authorizer
from ..adapters.azure_resource_graph import ResourceGraphClient
from ..adapters.base import ParseError, ScanSummary
from ..adapters.catalogue import parser as get_parser
from ..adapters.tenable import TenableApiError, TenableExportClient
from ..db import Database, TenantContext
from ..domains.evidence.service import EvidenceService
from ..errors import ConfigurationError, NotFound, ValidationFailed
from .pipeline import IngestionService, RunState

API_ADAPTERS = {"tenable_vm": "scanner", "azure_resource_graph": "context"}


class SecretResolver(Protocol):
    def resolve(self, ref: str) -> str: ...


class EnvSecretResolver:
    """Development resolver: ``secretref:env/NAME`` reads environment variable NAME.

    Production should resolve references from a secret manager with workload identity (planned: Azure Key
    Vault); this resolver refuses to run when AXIOM_ENV=production.
    """

    def resolve(self, ref: str) -> str:
        if os.environ.get("AXIOM_ENV") == "production":
            raise ConfigurationError("environment secret resolver is not permitted in production")
        if not ref.startswith("secretref:env/"):
            raise ConfigurationError("unsupported secret reference")
        value = os.environ.get(ref.removeprefix("secretref:env/"))
        if not value:
            raise ConfigurationError("secret reference did not resolve")
        return value


ClientFactory = Callable[[dict, SecretResolver], Any]


def default_client_factory(connection: dict, secrets: SecretResolver) -> Any:
    if connection["adapter"] == "tenable_vm":
        ref = connection["credential_ref"]
        return TenableExportClient(connection["base_url"] or "https://cloud.tenable.com",
                                   lambda: tuple(secrets.resolve(ref).split(":", 1)))
    if connection["adapter"] == "azure_resource_graph":
        ref = connection["credential_ref"]
        return ResourceGraphClient(lambda: secrets.resolve(ref),
                                   base_url=connection["base_url"] or "https://management.azure.com")
    raise ValidationFailed(f"no API client for adapter {connection['adapter']}")


class SyncService:
    def __init__(self, db: Database, ingestion: IngestionService, evidence: EvidenceService,
                 secrets: SecretResolver | None = None, client_factory: ClientFactory = default_client_factory):
        self.db = db
        self.ingestion = ingestion
        self.evidence = evidence
        self.secrets = secrets or EnvSecretResolver()
        self.client_factory = client_factory

    # ------------------------------------------------------------------ configuration
    def create_connection(self, ctx: TenantContext, *, adapter: str, scope_id: UUID, display_name: str,
                          base_url: str | None, credential_ref: str | None, config: dict) -> dict:
        if adapter not in API_ADAPTERS:
            raise ValidationFailed(f"adapter {adapter} has no API synchronisation")
        if base_url and not base_url.startswith("https://"):
            raise ValidationFailed("connections must use HTTPS")
        with self.db.tenant_tx(ctx) as conn:
            authority = Authorizer(conn, ctx).require("connection.configure", scope_id)
            row = conn.execute(
                """INSERT INTO axiom.connections(tenant_id, id, scope_id, adapter, adapter_kind, display_name, base_url,
                       credential_ref, config, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *""",
                (ctx.tenant_id, uuid.uuid4(), scope_id, adapter, API_ADAPTERS[adapter], display_name, base_url,
                 credential_ref, Jsonb(config), ctx.principal_id)).fetchone()
            audit.record(conn, ctx, action="connection.create", resource_type="connection", resource_id=row["id"],
                         detail={"adapter": adapter, "authority": authority.as_json()})
            return row

    def request_sync(self, ctx: TenantContext, connection_id: UUID) -> dict:
        with self.db.tenant_tx(ctx) as conn:
            connection = conn.execute("SELECT * FROM axiom.connections WHERE id = %s", (connection_id,)).fetchone()
            if connection is None:
                raise NotFound("connection not found", code="connection_not_found")
            authority = Authorizer(conn, ctx).require("ingestion.import", connection["scope_id"])
            if connection["status"] != "active":
                raise ValidationFailed("connection is disabled")
            run_id = uuid.uuid4()
            row = conn.execute(
                """INSERT INTO axiom.ingestion_runs(tenant_id, id, scope_id, connection_id, source_kind, adapter,
                       adapter_version, declared_scope, status, requested_by)
                   VALUES (%s, %s, %s, %s, 'api_sync', %s, %s, %s, 'queued', %s) RETURNING *""",
                (ctx.tenant_id, run_id, connection["scope_id"], connection_id, connection["adapter"],
                 get_parser(connection["adapter"]).info.version, Jsonb(connection["config"]),
                 ctx.principal_id)).fetchone()
            audit.record(conn, ctx, action="ingestion.sync_requested", resource_type="ingestion_run",
                         resource_id=run_id, detail={"connection_id": str(connection_id),
                                                     "authority": authority.as_json()})
            outbox.enqueue(conn, ctx, topic="ingestion.run_requested", aggregate_type="ingestion_run",
                           aggregate_id=run_id, payload={"run_id": str(run_id)})
            return row

    # ---------------------------------------------------------------------- execution
    def execute_sync(self, tenant_id: UUID, system_principal_id: UUID, run_id: UUID, *, worker_id: str) -> dict | None:
        ctx = TenantContext(tenant_id, system_principal_id, "workload", f"sync:{run_id}")
        state = self.ingestion._claim(ctx, run_id, worker_id)
        if state is None:
            return None
        with self.db.tenant_tx(ctx) as conn:
            connection = conn.execute("SELECT * FROM axiom.connections WHERE id = %s",
                                      (state.run["connection_id"],)).fetchone()
            checkpoint = conn.execute(
                "SELECT cursor FROM axiom.connection_checkpoints WHERE connection_id = %s AND stream = 'default'",
                (connection["id"],)).fetchone()
        client = self.client_factory(connection, self.secrets)
        parser = get_parser(connection["adapter"])
        started = int(time.time())
        try:
            if connection["adapter"] == "tenable_vm":
                complete, reason, cursor = self._tenable(ctx, state, connection, client, parser,
                                                         checkpoint["cursor"] if checkpoint else None, started)
            else:
                complete, reason, cursor = self._azure(ctx, state, connection, client, parser)
        except (TenableApiError, RuntimeError, ParseError) as exc:
            if isinstance(exc, ParseError) or state.counts["pages_committed"] == 0:
                return self.ingestion._fail(ctx, state, f"{type(exc).__name__}: {exc}")
            # Some pages are durable: finish as partial rather than discarding committed work.
            return self.ingestion._finalise(ctx, state, source_complete=False,
                                            extra_reason=f"sync interrupted: {type(exc).__name__}: {exc}")
        return self.ingestion._finalise(ctx, state, source_complete=complete, extra_reason=reason,
                                        checkpoint=(connection["id"], "default", cursor) if cursor else None)

    def _store_page(self, ctx: TenantContext, connection: dict, data: bytes) -> dict:
        rec = self.evidence.initiate(ctx, scope_id=connection["scope_id"], sha256=hashlib.sha256(data).hexdigest(),
                                     size=len(data), media_type="application/json", classification="confidential",
                                     filename=f"{connection['adapter']}-page.json")
        self.evidence.upload(ctx, rec["id"], iter([data]))
        return self.evidence.finalise(ctx, rec["id"])

    def _page(self, ctx: TenantContext, state: RunState, connection: dict, parser, data: bytes) -> None:
        digest = hashlib.sha256(data).hexdigest()
        with self.db.tenant_tx(ctx) as conn:
            if conn.execute("SELECT 1 FROM axiom.ingestion_pages WHERE run_id = %s AND page_key = %s",
                            (state.run["id"], f"sha256:{digest}")).fetchone():
                state.counts["pages_skipped"] += 1
                return
        ev = self._store_page(ctx, connection, data)
        events = list(parser.parse(data))
        state.summaries.extend(e for e in events if isinstance(e, ScanSummary))
        records = [e for e in events if not isinstance(e, ScanSummary)]
        self.ingestion._commit_page(ctx, state, f"sha256:{digest}", digest, records, raw_evidence_id=ev["id"],
                                    page_evidence_id=ev["id"])

    def _tenable(self, ctx, state, connection, client: TenableExportClient, parser, cursor, started):
        filters = {"state": ["OPEN", "REOPENED", "FIXED"]}
        since = (cursor or {}).get("since") or connection["config"].get("initial_since")
        if since:
            filters["since"] = int(since)
        export_uuid = client.request_export(filters=filters,
                                            num_assets=int(connection["config"].get("num_assets", 500)))
        result = client.wait_for_export(export_uuid)
        if result.status != "FINISHED":
            raise TenableApiError(f"export {export_uuid} ended {result.status}", retryable=False)
        for chunk_id in result.chunks:
            self._page(ctx, state, connection, parser, client.download_chunk(export_uuid, chunk_id))
        complete = not result.failed_chunks and not result.cancelled_chunks
        reason = (f"export {export_uuid}: {len(result.chunks)} chunk(s)"
                  + ("" if complete else f"; failed {result.failed_chunks} cancelled {result.cancelled_chunks}")
                  + ("" if since else "; no since filter: Tenable returns only the last 30 days"))
        return complete, reason, {"since": started}

    def _azure(self, ctx, state, connection, client: ResourceGraphClient, parser):
        subscriptions = connection["config"].get("subscriptions") or []
        if not subscriptions:
            raise ValidationFailed("Azure connection needs config.subscriptions")
        truncated = False
        pages = 0
        for data, _token in client.pages(subscriptions=subscriptions,
                                         **({"query": connection["config"]["query"]}
                                            if connection["config"].get("query") else {})):
            pages += 1
            flag = json.loads(data).get("resultTruncated")
            if flag is True or str(flag).lower() == "true":
                truncated = True
            self._page(ctx, state, connection, parser, data)
        return (not truncated), f"{pages} Resource Graph page(s)" + ("; result truncated" if truncated else ""), None
