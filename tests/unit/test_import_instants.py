"""Imported timestamps follow the same rule as the API: without "Z" or an offset they are not an instant.

The adapters record such a value as unknown (source_time is empty) instead of guessing a zone. The raw value stays in
the stored source record and the original evidence file.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from axiom.adapters.base import FindingRecord, parse_time
from axiom.adapters.trivy import TrivyParser

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "trivy" / "debian-bullseye-20230612-slim.subset.json"


@pytest.mark.parametrize("value", ["2026-10-27T20:00:00", "2026-10-27 20:00:00", "2026-10-27", "", None, 1761595200])
def test_offset_free_or_missing_source_times_are_unknown(value):
    assert parse_time(value) is None


def test_equivalent_source_times_are_the_same_instant():
    a, b = parse_time("2026-10-27T20:00:00Z"), parse_time("2026-10-27T23:00:00+03:00")
    assert a == b == datetime(2026, 10, 27, 20, tzinfo=timezone.utc)
    assert parse_time("2026-10-27T20:00:00+03:00") != a


@pytest.mark.parametrize("created, expected", [
    ("2026-10-21T22:04:00Z", datetime(2026, 10, 21, 22, 4, tzinfo=timezone.utc)),
    ("2026-10-22T01:04:00+03:00", datetime(2026, 10, 21, 22, 4, tzinfo=timezone.utc)),
    ("2026-10-21T22:04:00", None),
])
def test_trivy_created_at_without_offset_is_not_guessed(created, expected):
    doc = json.loads(FIXTURE.read_text())
    doc["CreatedAt"] = created
    records = [e for e in TrivyParser().parse(json.dumps(doc).encode()) if isinstance(e, FindingRecord)]
    assert records and {r.source_time for r in records} == {expected}
