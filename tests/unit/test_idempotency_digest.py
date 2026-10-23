"""Request digests compare arguments by meaning: a timestamp is the instant it names (API-07)."""
from datetime import datetime, timedelta, timezone

from axiom.idempotency import request_digest

UTC = datetime(2026, 10, 27, 20, 0, tzinfo=timezone.utc)
EEST = timezone(timedelta(hours=3))


def digest(expires):
    return request_digest("POST /x", {}, {"expires_at": expires, "nested": [{"at": expires}]})


def test_the_same_instant_with_another_offset_has_the_same_digest():
    assert digest(UTC) == digest(UTC.astimezone(EEST))


def test_a_different_instant_has_a_different_digest():
    assert digest(UTC) != digest(UTC + timedelta(seconds=1))
    assert digest(UTC) != digest(UTC.replace(tzinfo=EEST))        # same wall-clock time, different instant


def test_values_that_are_not_timestamps_are_unchanged():
    body = {"approval_id": "7f6c", "count": 3, "flag": True, "items": ["a", "b"]}
    assert request_digest("POST /x", {}, body) == request_digest("POST /x", {}, dict(body))
    assert request_digest("POST /x", {}, body) != request_digest("POST /x", {}, {**body, "count": 4})
