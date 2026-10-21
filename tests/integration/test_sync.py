"""API synchronisation against local fake Tenable and Azure Resource Graph APIs (httpx MockTransport).

These prove our client and pipeline behaviour against the documented API shapes only. They are not
evidence of compatibility with the live vendor services.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from axiom.adapters.azure_resource_graph import ResourceGraphClient
from axiom.adapters.tenable import TenableExportClient
from axiom.domains.evidence.service import EvidenceService
from axiom.ingestion.pipeline import IngestionService
from axiom.ingestion.sync import SyncService
from axiom.workers.ingest import run_once

pytestmark = pytest.mark.db
FIX = Path(__file__).resolve().parent.parent / "fixtures"


class FakeSecrets:
    def resolve(self, ref):
        return {"secretref:test/tenable": "ak:sk", "secretref:test/azure": "token-123"}[ref]


class FakeTenable:
    def __init__(self, *, chunks: dict[int, bytes], failed=(), fail_download_after=None):
        self.chunks, self.failed = chunks, list(failed)
        self.requests: list[dict] = []
        self.fail_download_after = fail_download_after
        self.downloads = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["X-ApiKeys"] == "accessKey=ak;secretKey=sk"
        path = request.url.path
        if path == "/vulns/export":
            self.requests.append(json.loads(request.content))
            return httpx.Response(200, json={"export_uuid": "exp-42"})
        if path.endswith("/status"):
            return httpx.Response(200, json={"status": "FINISHED", "chunks_available": sorted(self.chunks),
                                             "chunks_failed": self.failed, "chunks_cancelled": []})
        chunk = int(path.rsplit("/", 1)[-1])
        self.downloads += 1
        if self.fail_download_after is not None and self.downloads > self.fail_download_after:
            return httpx.Response(404)
        return httpx.Response(200, content=self.chunks[chunk])


@pytest.fixture()
def services(db, object_store):
    ingestion = IngestionService(db, object_store, page_size=50)
    evidence = EvidenceService(db, object_store, max_bytes=5_000_000)

    def make(factory):
        return SyncService(db, ingestion, evidence, secrets=FakeSecrets(), client_factory=factory)
    return ingestion, make


def tenable_factory(fake):
    def factory(connection, secrets):
        return TenableExportClient(connection["base_url"], lambda: tuple(secrets.resolve(connection["credential_ref"]).split(":")),
                                   transport=httpx.MockTransport(fake.handler), sleep=lambda s: None, poll_interval=0)
    return factory


def make_connection(sync, ctx, world, dbinfo, adapter, ref, config):
    from axiom.provisioning import Provisioner
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, ctx.principal_id, "policy_admin", world.a.project,
                                                     "configure connections for test")
    base = "https://tenable.test.invalid" if adapter == "tenable_vm" else "https://arm.test.invalid"
    return sync.create_connection(ctx, adapter=adapter, scope_id=world.a.project, display_name=adapter,
                                  base_url=base, credential_ref=ref, config=config)


def test_tenable_sync_end_to_end_and_checkpoint(world, run, ctx_for, services, dbinfo, db):
    ingestion, make = services
    chunk1 = (FIX / "tenable/synthetic-vulns-chunk-1.json").read_bytes()
    chunk2 = json.dumps([json.loads(chunk1)[0] | {"plugin": {"id": 900009, "name": "Synthetic other"},
                                                   "finding_id": "x"}]).encode()
    fake = FakeTenable(chunks={1: chunk1, 2: chunk2})
    sync = make(tenable_factory(fake))
    analyst = ctx_for("analyst")
    connection = make_connection(sync, analyst, world, dbinfo, "tenable_vm", "secretref:test/tenable",
                                 {"initial_since": 1760000000})
    queued = sync.request_sync(analyst, connection["id"])
    assert queued["status"] == "queued" and queued["source_kind"] == "api_sync"
    assert run_once(db, ingestion, sync, "worker-test") >= 1      # the interim worker dispatches the run
    done = run(analyst, lambda s: s.conn.execute("SELECT * FROM axiom.ingestion_runs WHERE id = %s",
                                                 (queued["id"],)).fetchone())
    assert done["status"] == "completed"
    # One quarantined record makes the run partial, so the checkpoint must NOT advance.
    assert done["coverage"] == "partial" and done["counts"]["quarantined"] == 1
    assert fake.requests[0]["filters"]["since"] == 1760000000
    assert run(analyst, lambda s: s.conn.execute("SELECT count(*) AS n FROM axiom.connection_checkpoints").fetchone())["n"] == 0
    pages = run(analyst, lambda s: s.conn.execute(
        """SELECT p.evidence_id, e.status, e.classification FROM axiom.ingestion_pages p
             JOIN axiom.evidence_objects e ON e.id = p.evidence_id WHERE p.run_id = %s""", (queued["id"],)).fetchall())
    assert len(pages) == 2 and {(p["status"], p["classification"]) for p in pages} == {("verified", "confidential")}


def test_tenable_sync_complete_advances_checkpoint_and_failed_chunks_do_not(world, run, ctx_for, services, dbinfo):
    ingestion, make = services
    good = json.dumps(json.loads((FIX / "tenable/synthetic-vulns-chunk-1.json").read_bytes())[:3]).encode()
    analyst = ctx_for("analyst")
    fake = FakeTenable(chunks={1: good})
    sync = make(tenable_factory(fake))
    connection = make_connection(sync, analyst, world, dbinfo, "tenable_vm", "secretref:test/tenable", {})
    run1 = sync.request_sync(analyst, connection["id"])
    done = sync.execute_sync(world.a.id, world.a.system, run1["id"], worker_id="w")
    assert done["coverage"] == "complete" and "last 30 days" in done["coverage_reason"]
    cp = run(analyst, lambda s: s.conn.execute("SELECT cursor, last_durable_run_id FROM axiom.connection_checkpoints"
                                               ).fetchone())
    assert cp["last_durable_run_id"] == run1["id"] and cp["cursor"]["since"] > 0
    # Second sync: export reports a failed chunk -> partial, checkpoint unchanged, since filter used.
    fake2 = FakeTenable(chunks={1: good}, failed=[2])
    sync2 = make(tenable_factory(fake2))
    run2 = sync2.request_sync(analyst, connection["id"])
    done2 = sync2.execute_sync(world.a.id, world.a.system, run2["id"], worker_id="w")
    assert done2["coverage"] == "partial" and fake2.requests[0]["filters"]["since"] == cp["cursor"]["since"]
    cp2 = run(analyst, lambda s: s.conn.execute("SELECT last_durable_run_id FROM axiom.connection_checkpoints").fetchone())
    assert cp2["last_durable_run_id"] == run1["id"]
    # Identical page content from the second export was already parsed in run 1 but is a new run: no duplicates.
    assert run(analyst, lambda s: s.conn.execute("SELECT count(*) AS n FROM axiom.finding_occurrences").fetchone())["n"] == 3


def test_interrupted_sync_keeps_committed_pages_as_partial(world, run, ctx_for, services, dbinfo):
    ingestion, make = services
    records = json.loads((FIX / "tenable/synthetic-vulns-chunk-1.json").read_bytes())[:3]
    fake = FakeTenable(chunks={1: json.dumps(records[:1]).encode(), 2: json.dumps(records[1:]).encode()},
                       fail_download_after=1)
    sync = make(tenable_factory(fake))
    analyst = ctx_for("analyst")
    connection = make_connection(sync, analyst, world, dbinfo, "tenable_vm", "secretref:test/tenable", {})
    queued = sync.request_sync(analyst, connection["id"])
    done = sync.execute_sync(world.a.id, world.a.system, queued["id"], worker_id="w")
    assert done["status"] == "completed" and done["coverage"] == "partial"
    assert "expired" in done["coverage_reason"] and done["counts"]["pages_committed"] == 1


def test_azure_resource_graph_sync_context_and_identity(world, run, ctx_for, services, dbinfo):
    ingestion, make = services
    page1, page2 = (FIX / "azure/synthetic-arg-page-1.json").read_bytes(), (FIX / "azure/synthetic-arg-page-2.json").read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer token-123"
        body = json.loads(request.content)
        assert body["subscriptions"] == ["00000000-1111-4222-8333-444444444444"]
        return httpx.Response(200, content=page2 if body["options"].get("$skipToken") else page1)

    def factory(connection, secrets):
        return ResourceGraphClient(lambda: secrets.resolve(connection["credential_ref"]), base_url=connection["base_url"],
                                   transport=httpx.MockTransport(handler), sleep=lambda s: None)
    sync = make(factory)
    analyst = ctx_for("analyst")
    connection = make_connection(sync, analyst, world, dbinfo, "azure_resource_graph", "secretref:test/azure",
                                 {"subscriptions": ["00000000-1111-4222-8333-444444444444"]})
    queued = sync.request_sync(analyst, connection["id"])
    done = sync.execute_sync(world.a.id, world.a.system, queued["id"], worker_id="w")
    assert done["status"] == "completed" and done["coverage"] == "complete" and done["counts"]["assets"] == 3
    ctx_rows = run(analyst, lambda s: s.conn.execute(
        "SELECT owner_ref, criticality, environment, basis FROM axiom.business_context_versions ORDER BY owner_ref"
    ).fetchall())
    assert {r["basis"] for r in ctx_rows} == {"source_tag_assertion"}
    assert {"owner_ref": "payments-team", "criticality": "high", "environment": "prod",
            "basis": "source_tag_assertion"} in ctx_rows
    # Re-sync with identical data: no new assets or context versions.
    again = sync.request_sync(analyst, connection["id"])
    sync.execute_sync(world.a.id, world.a.system, again["id"], worker_id="w")
    totals = run(analyst, lambda s: s.conn.execute(
        "SELECT (SELECT count(*) FROM axiom.assets) AS assets, (SELECT count(*) FROM axiom.business_context_versions) AS ctx"
    ).fetchone())
    assert totals == {"assets": 3, "ctx": len(ctx_rows)}


def test_tenable_host_and_azure_vm_with_same_hostname_stay_separate(world, run, ctx_for, services, dbinfo, upload):
    """A04-style: a Tenable host and an Azure VM share only a hostname -> separate assets, open review candidate."""
    ingestion, make = services
    analyst = ctx_for("analyst")
    ev = upload(analyst, world.a.project, (FIX / "tenable/synthetic-vulns-chunk-1.json").read_bytes())
    imp = ingestion.request_import(analyst, evidence_id=ev["id"], adapter="tenable_vm", scope_id=world.a.project)
    ingestion.execute(world.a.id, world.a.system, imp["id"], worker_id="w")
    page1 = (FIX / "azure/synthetic-arg-page-1.json").read_bytes()

    def factory(connection, secrets):
        return ResourceGraphClient(lambda: "t", base_url=connection["base_url"], sleep=lambda s: None,
                                   transport=httpx.MockTransport(lambda r: httpx.Response(
                                       200, content=json.dumps(json.loads(page1) | {"$skipToken": None}).encode())))
    sync = make(factory)
    connection = make_connection(sync, analyst, world, dbinfo, "azure_resource_graph", "secretref:test/azure",
                                 {"subscriptions": ["00000000-1111-4222-8333-444444444444"]})
    queued = sync.request_sync(analyst, connection["id"])
    sync.execute_sync(world.a.id, world.a.system, queued["id"], worker_id="w")
    cands = run(analyst, lambda s: s.conn.execute(
        "SELECT method, cardinality(asset_ids) AS n FROM axiom.identity_candidates WHERE status = 'open'").fetchall())
    assert sum(1 for c in cands if c["method"] == "weak_identifier_overlap") >= 2   # VM overlaps both Tenable hosts
    hosts = run(analyst, lambda s: s.conn.execute(
        "SELECT count(DISTINCT asset_id) AS n FROM axiom.asset_identifiers WHERE namespace = 'hostname' AND value = 'pay-db-01'"
    ).fetchone())
    assert hosts["n"] == 3   # two Tenable assets + one Azure VM, none merged
