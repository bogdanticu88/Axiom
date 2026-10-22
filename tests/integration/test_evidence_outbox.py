"""Evidence finalisation, evidence access control, and outbox delivery tests."""
from __future__ import annotations

import hashlib
import threading
import uuid

import pytest

from axiom.access import PermissionDenied
from axiom.domains.evidence.objectstore import SizeLimitExceeded, TenantObjectStore
from axiom.domains.evidence.service import IntegrityMismatch
from axiom.errors import Conflict, Forbidden, NotFound, ValidationFailed
from axiom.outbox import Inbox, Relay

pytestmark = pytest.mark.db


def test_upload_finalise_and_audited_download(world, ctx_for, evidence, upload, admin_conn):
    analyst = ctx_for("analyst")
    content = b"nessus export\n" * 1000
    rec = upload(analyst, world.a.project, content)
    assert rec["status"] == "verified" and rec["observed_digest"] == hashlib.sha256(content).hexdigest()
    assert rec["object_key"] == f"tenants/{world.a.id}/evidence/{rec['id']}"
    opened = evidence.open_for_read(analyst, rec["id"], purpose="case review")
    assert b"".join(opened.chunks) == content
    actions = [r["action"] for r in admin_conn.execute(
        "SELECT action FROM axiom.audit_events WHERE resource_id = %s ORDER BY occurred_at", (str(rec["id"]),))]
    assert actions == ["evidence.initiate", "evidence.upload", "evidence.finalise", "evidence.download"]


def test_digest_mismatch_is_rejected_and_cannot_be_served(world, ctx_for, evidence, upload):
    analyst = ctx_for("analyst")
    rec = upload(analyst, world.a.project, b"actual bytes", declared_sha="0" * 64)
    assert rec["status"] == "rejected" and rec["rejection_reason"] == "digest_mismatch"
    with pytest.raises(Conflict):
        evidence.open_for_read(analyst, rec["id"], purpose="x")


def test_oversize_upload_aborts_and_stays_pending(world, ctx_for, evidence):
    analyst = ctx_for("analyst")
    rec = evidence.initiate(analyst, scope_id=world.a.project, sha256="1" * 64, size=4,
                            media_type="text/plain", classification="internal")
    with pytest.raises(SizeLimitExceeded):
        evidence.upload(analyst, rec["id"], iter([b"12345"]))
    assert evidence.metadata(analyst, rec["id"])["status"] == "pending"


def test_only_uploader_can_supply_and_finalise(world, ctx_for, evidence):
    rec = evidence.initiate(ctx_for("analyst"), scope_id=world.a.project, sha256="1" * 64, size=1,
                            media_type="text/plain", classification="internal")
    with pytest.raises(Forbidden):
        evidence.upload(ctx_for("analyst2"), rec["id"], iter([b"x"]))
    with pytest.raises(Forbidden):
        evidence.finalise(ctx_for("analyst2"), rec["id"])


def test_finalise_before_upload_rejected(world, ctx_for, evidence):
    analyst = ctx_for("analyst")
    rec = evidence.initiate(analyst, scope_id=world.a.project, sha256="1" * 64, size=1,
                            media_type="text/plain", classification="internal")
    with pytest.raises(Conflict):
        evidence.finalise(analyst, rec["id"])


def test_classification_permissions_and_denial_audit(world, ctx_for, evidence, upload, admin_conn):
    rec = upload(ctx_for("analyst"), world.a.project, b"secret config", classification="confidential")
    with pytest.raises(PermissionDenied):
        evidence.open_for_read(ctx_for("viewer"), rec["id"], purpose="curious")
    with pytest.raises(PermissionDenied):     # remediation owner has internal only
        evidence.open_for_read(ctx_for("owner"), rec["id"], purpose="fix")
    with pytest.raises(PermissionDenied):     # tenant admin has no evidence authority
        evidence.open_for_read(ctx_for("admin"), rec["id"], purpose="admin")
    restricted = upload(ctx_for("analyst"), world.a.project, b"keys", classification="restricted")
    with pytest.raises(PermissionDenied):     # analysts lack restricted access by default
        evidence.open_for_read(ctx_for("analyst2"), restricted["id"], purpose="x")
    denials = admin_conn.execute(
        "SELECT count(*) AS n FROM axiom.audit_events WHERE resource_id = %s AND outcome = 'denied'",
        (str(rec["id"]),)).fetchone()
    assert denials["n"] == 3


def test_cross_tenant_evidence_is_not_found(world, ctx_for, evidence, upload):
    rec = upload(ctx_for("analyst"), world.a.project, b"a data")
    with pytest.raises(NotFound):
        evidence.open_for_read(ctx_for("consultant", "b"), rec["id"], purpose="x")
    with pytest.raises(NotFound):
        evidence.metadata(ctx_for("analyst_b", "b"), rec["id"])


def test_storage_tampering_after_verification_is_detected(world, ctx_for, evidence, upload, object_store):
    analyst = ctx_for("analyst")
    rec = upload(analyst, world.a.project, b"original")
    object_store.put(rec["object_key"], iter([b"tampered"]), max_bytes=100)
    opened = evidence.open_for_read(analyst, rec["id"], purpose="review")
    with pytest.raises(IntegrityMismatch):
        b"".join(opened.chunks)


def test_tenant_object_store_refuses_foreign_keys(world, object_store):
    scoped = TenantObjectStore(object_store, world.b.id)
    with pytest.raises(ValidationFailed):
        list(scoped.get(f"tenants/{world.a.id}/evidence/{uuid.uuid4()}"))
    with pytest.raises(ValidationFailed):
        list(scoped.get(f"tenants/{world.b.id}/../{world.a.id}/evidence/x"))


def test_outbox_relay_delivers_at_least_once_and_inbox_dedupes(world, run, ctx_for, relay_db, db):
    analyst = ctx_for("analyst")
    relay = Relay(relay_db, worker_id="relay-1")
    # The session database is shared by the whole suite; drain earlier tests' backlog first so this message is not
    # beyond the claim limit (the suite can leave more than 1000 undelivered messages, e.g. when browser tests run first).
    while backlog := relay.claim(limit=1000):
        for m in backlog:
            relay.mark_delivered(m)
    case = run(analyst, lambda s: s.cases.create(scope_id=world.a.project, title="outbox"))
    seen = []

    def failing(message):
        raise RuntimeError("downstream unavailable")
    # First relay attempt fails: message stays undelivered with backoff and recorded error.
    claimed = relay.claim(limit=1000)
    mine = [m for m in claimed if m.aggregate_id == case["id"]]
    assert len(mine) == 1 and mine[0].tenant_id == world.a.id
    for m in claimed:
        relay.mark_failed(m, "downstream unavailable") if m.aggregate_id == case["id"] else relay.mark_delivered(m)
    with relay_db.unbound_tx() as conn:
        conn.execute("UPDATE axiom.outbox SET available_at = clock_timestamp() WHERE id = %s", (mine[0].id,))

    def handler(message):
        with db.tenant_tx(type(analyst)(message.tenant_id, world.a.system, "workload", "relay")) as conn:
            if Inbox.first_delivery(conn, analyst, "test-consumer", message.id):
                seen.append(message.id)
    delivered, failed = relay.run_once(handler, limit=1000)
    assert failed == 0 and mine[0].id in seen
    # Redelivery of the same message is ignored by the consumer inbox.
    handler(mine[0])
    assert seen.count(mine[0].id) == 1
    with relay_db.unbound_tx() as conn:
        row = conn.execute("SELECT attempts, delivered_at, last_error FROM axiom.outbox WHERE id = %s",
                           (mine[0].id,)).fetchone()
    assert row["attempts"] == 2 and row["delivered_at"] is not None


def test_concurrent_relays_do_not_double_claim(world, run, ctx_for, relay_db):
    analyst = ctx_for("analyst")
    for i in range(20):
        run(analyst, lambda s: s.cases.create(scope_id=world.a.project, title=f"c{i}"))
    claims: dict[str, list] = {}

    def worker(name):
        claims[name] = Relay(relay_db, worker_id=name).claim(limit=1000)
    threads = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(2)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    ids = [m.id for msgs in claims.values() for m in msgs]
    assert len(ids) == len(set(ids)) and len(ids) >= 20
