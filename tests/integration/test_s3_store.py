"""Evidence lifecycle against a real S3-compatible endpoint.

Runs only when AXIOM_TEST_S3_ENDPOINT, AXIOM_TEST_S3_BUCKET and AWS credentials are set,
e.g. against the SeaweedFS service from deployments/compose.
"""
from __future__ import annotations

import hashlib
import os
import uuid

import pytest

from axiom.domains.evidence.objectstore import S3ObjectStore, SizeLimitExceeded
from axiom.domains.evidence.service import EvidenceService, IntegrityMismatch

pytestmark = [pytest.mark.db, pytest.mark.s3]


@pytest.fixture()
def s3_store():
    endpoint, bucket = os.environ.get("AXIOM_TEST_S3_ENDPOINT"), os.environ.get("AXIOM_TEST_S3_BUCKET")
    if not endpoint or not bucket:
        pytest.skip("AXIOM_TEST_S3_ENDPOINT / AXIOM_TEST_S3_BUCKET not set")
    import boto3
    return S3ObjectStore(boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1"), bucket)


def test_s3_roundtrip_and_size_limit(s3_store):
    key = f"tenants/{uuid.uuid4()}/evidence/{uuid.uuid4()}"
    data = os.urandom(3 * 1024 * 1024 + 17)
    stored = s3_store.put(key, iter([data[i:i + 65536] for i in range(0, len(data), 65536)]), max_bytes=len(data))
    assert stored.size == len(data) and stored.sha256 == hashlib.sha256(data).hexdigest()
    assert b"".join(s3_store.get(key)) == data
    with pytest.raises(SizeLimitExceeded):
        s3_store.put(key + "-big", iter([b"x" * 10]), max_bytes=5)
    assert not s3_store.exists(key + "-big")


def test_s3_evidence_finalise_and_tamper_detection(world, ctx_for, db, s3_store):
    service = EvidenceService(db, s3_store, max_bytes=10_000_000)
    analyst = ctx_for("analyst")
    content = b"qualys export " * 500
    rec = service.initiate(analyst, scope_id=world.a.project, sha256=hashlib.sha256(content).hexdigest(),
                           size=len(content), media_type="application/xml", classification="internal")
    service.upload(analyst, rec["id"], iter([content]))
    assert service.finalise(analyst, rec["id"])["status"] == "verified"
    assert b"".join(service.open_for_read(analyst, rec["id"], purpose="t").chunks) == content
    s3_store.put(rec["object_key"], iter([b"replaced"]), max_bytes=100)
    with pytest.raises(IntegrityMismatch):
        b"".join(service.open_for_read(analyst, rec["id"], purpose="t").chunks)
