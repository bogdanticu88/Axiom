"""S3 restore witness against a real S3-compatible service (SeaweedFS in CI and verification).

Needs AXIOM_TEST_S3_ENDPOINT / AXIOM_TEST_S3_BUCKET with full credentials in AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY,
plus AXIOM_TEST_S3_RO_KEY/SECRET (read and list only) and AXIOM_TEST_S3_NOLIST_KEY/SECRET (read and write, no list),
as configured by scripts/verify/foundation.sh. These results describe SeaweedFS 4.48 only; production storage must be
validated separately (ADR 0010, "Storage assumptions").
"""
from __future__ import annotations

import os
import random
import threading
import uuid

import pytest

from axiom.jobs.witness import KEEP, S3Witness, WitnessUnavailable, check

ENDPOINT, BUCKET = os.environ.get("AXIOM_TEST_S3_ENDPOINT"), os.environ.get("AXIOM_TEST_S3_BUCKET")
pytestmark = pytest.mark.skipif(not (ENDPOINT and BUCKET), reason="AXIOM_TEST_S3_ENDPOINT / AXIOM_TEST_S3_BUCKET not set")


def client(key=None, secret=None, endpoint=None, **cfg):
    import boto3
    from botocore.config import Config
    kw = {"aws_access_key_id": key, "aws_secret_access_key": secret} if key else {}
    return boto3.client("s3", endpoint_url=endpoint or ENDPOINT, region_name="us-east-1",
                        config=Config(retries={"max_attempts": 1}, connect_timeout=2, read_timeout=5, **cfg), **kw)


@pytest.fixture()
def prefix():
    return f"witness-test/{uuid.uuid4().hex}"


def test_roundtrip_write_once_and_pruning(prefix):
    c = client()
    w = S3Witness(c, BUCKET, prefix, "worker-a")
    w.probe()
    assert w.high_water() is None
    for n in range(1, 11):
        w.advance(n)
    assert w.high_water() == 10
    keys = [o["Key"] for o in c.list_objects_v2(Bucket=BUCKET, Prefix=prefix + "/")["Contents"]]
    assert len(keys) == KEEP and all(k.endswith("-worker-a") for k in keys)
    w.advance(7)                                  # a lower, late write never lowers the mark
    assert w.high_water() == 10


def test_concurrent_writers_and_duplicate_worker_ids_never_lower_the_mark(prefix):
    c = client(max_pool_connections=32)
    values = list(range(1, 201))
    random.Random(7).shuffle(values)
    chunks = [values[i::8] for i in range(8)]
    # workers 0..5 have distinct ids; 6 and 7 deliberately share one id (a misconfiguration)
    witnesses = [S3Witness(c, BUCKET, prefix, f"w{i}" if i < 6 else "dup") for i in range(8)]
    samples, stop = [], threading.Event()

    def reader():
        r = S3Witness(c, BUCKET, prefix, "reader")
        while not stop.is_set():
            samples.append(r.high_water() or 0)

    def writer(w, chunk):
        for v in chunk:
            w.advance(v)
    rt = threading.Thread(target=reader)
    rt.start()
    threads = [threading.Thread(target=writer, args=(w, ch)) for w, ch in zip(witnesses, chunks)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    stop.set()
    rt.join(30)
    assert S3Witness(c, BUCKET, prefix, "x").high_water() == 200
    # Samples are only monotonic if listings never "forget" a completed write; a decrease would show the store
    # (or pruning) can hide the mark. Record the observation rather than assume it.
    decreases = [(a, b) for a, b in zip(samples, samples[1:]) if b < a]
    assert decreases == [], f"high-water decreased between listings: {decreases[:5]}"


def test_unavailable_storage_fails_closed(prefix):
    dead = client(endpoint="http://127.0.0.1:9")                 # nothing listens on the discard port
    w = S3Witness(dead, BUCKET, prefix, "w")
    with pytest.raises(WitnessUnavailable):
        w.probe()
    with pytest.raises(WitnessUnavailable):
        w.advance(1)
    with pytest.raises(WitnessUnavailable):
        w.high_water()

    class Conn:      # check() propagates so callers retry rather than proceed
        def execute(self, *_a, **_k):
            class R:
                def fetchone(self):
                    return {"last_value": 5, "is_called": True}
            return R()
    with pytest.raises(WitnessUnavailable):
        check(Conn(), w)


def test_lost_acknowledgement_is_recorded_and_never_lowers_or_false_alarms(prefix):
    """The PUT reaches storage but the client sees an error. The gate rolls back and sends nothing; the record is
    nevertheless present. Because the database sequence already advanced past that watermark, the next comparison
    does not report a rollback."""
    real = client()

    class LostAck:
        def __getattr__(self, name):
            return getattr(real, name)

        def put_object(self, **kw):
            real.put_object(**kw)
            raise ConnectionError("connection reset after the request was sent")
    w = S3Witness(LostAck(), BUCKET, prefix, "w")
    with pytest.raises(WitnessUnavailable):
        w.advance(42)
    assert S3Witness(real, BUCKET, prefix, "r").high_water() == 42
    w2 = S3Witness(real, BUCKET, prefix, "w")
    w2.advance(42)                                               # the retry writes the same record again: harmless
    assert w2.high_water() == 42

    class Conn:
        def execute(self, *_a, **_k):
            class R:
                def fetchone(self):
                    return {"last_value": 42, "is_called": True}
            return R()
    assert check(Conn(), w2) is None


@pytest.mark.skipif(not os.environ.get("AXIOM_TEST_S3_RO_KEY"), reason="restricted identities not configured")
def test_insufficient_permissions_refuse(prefix):
    ro = S3Witness(client(os.environ["AXIOM_TEST_S3_RO_KEY"], os.environ["AXIOM_TEST_S3_RO_SECRET"]), BUCKET, prefix, "w")
    with pytest.raises(WitnessUnavailable, match="AccessDenied"):
        ro.probe()                                              # cannot write
    with pytest.raises(WitnessUnavailable):
        ro.advance(1)
    nolist = S3Witness(client(os.environ["AXIOM_TEST_S3_NOLIST_KEY"], os.environ["AXIOM_TEST_S3_NOLIST_SECRET"]),
                       BUCKET, prefix, "w")
    with pytest.raises(WitnessUnavailable, match="AccessDenied"):
        nolist.probe()                                          # can write, cannot list
    with pytest.raises(WitnessUnavailable, match="AccessDenied"):
        nolist.high_water()
