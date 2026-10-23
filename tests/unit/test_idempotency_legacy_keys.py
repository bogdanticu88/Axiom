"""Idempotency keys stored before timestamps were normalised (ADR 0015), retried after the change.

The legacy digest is recomputed here exactly as the code at 8c0b483 computed it: the body parsed with plain
`datetime` fields, passed through FastAPI's `jsonable_encoder`, hashed without normalisation. The current digest is
what the API computes now. A retry replays only if the two are equal.
"""
import hashlib
import json
import uuid
from datetime import datetime

import pytest
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, ValidationError

from axiom import idempotency
from axiom.api import schemas

CASE, CONN = str(uuid.uuid4()), str(uuid.uuid4())
BASE = {"case_id": CASE, "effect_class": "ticket.create", "connection_id": CONN,
        "payload": {"project_key": "SEC", "labels": ["a"]}, "verification_criteria": "ticket exists"}


class LegacyCreateProposal(BaseModel):                      # schemas.CreateProposal as it was at 8c0b483
    model_config = ConfigDict(extra="forbid")
    case_id: uuid.UUID
    effect_class: str
    connection_id: uuid.UUID
    payload: dict
    verification_criteria: str
    rollback_guidance: str | None = None
    expires_at: datetime


def legacy_digest(expires: str) -> str:
    body = jsonable_encoder(LegacyCreateProposal(**BASE, expires_at=expires))
    doc = json.dumps({"endpoint": "POST /action-proposals", "params": {}, "body": body}, sort_keys=True,
                     separators=(",", ":"), default=str)
    return hashlib.sha256(doc.encode()).hexdigest()


def current_digest(expires) -> str:
    """As api/operations.py computes it: the schema-validated body (instants already in UTC), JSON-encoded."""
    body = schemas.CreateProposal(**BASE, expires_at=expires)          # raises for values without an offset
    digest = idempotency.request_digest("POST /action-proposals", {}, jsonable_encoder(body))
    # direct callers that pass datetimes get the same digest through canonical()
    assert digest == idempotency.request_digest("POST /action-proposals", {},
                                                jsonable_encoder(idempotency.canonical(body.model_dump())))
    return digest


Z, UTC, EEST, EEST_COMPACT, OFFSET_FREE = ("2026-10-27T20:00:00Z", "2026-10-27T20:00:00+00:00",
                                           "2026-10-27T23:00:00+03:00", "2026-10-27T23:00:00+0300",
                                           "2026-10-27T20:00:00")
RETRIES = [Z, UTC, EEST, EEST_COMPACT]                                  # all the same instant

# stored as -> expected outcome of each equivalent retry (replay, or rejected as a reused key)
MATRIX = [
    (Z, {Z: "replay", UTC: "replay", EEST: "replay", EEST_COMPACT: "replay"}),
    (UTC, {Z: "replay", UTC: "replay", EEST: "replay", EEST_COMPACT: "replay"}),
    (EEST, {Z: "rejected", UTC: "rejected", EEST: "rejected", EEST_COMPACT: "rejected"}),
]


@pytest.mark.parametrize("stored, expected", MATRIX, ids=["stored-Z", "stored-+00:00", "stored-+03:00"])
def test_legacy_keys_after_normalisation(stored, expected):
    for retry in RETRIES:
        outcome = "replay" if current_digest(retry) == legacy_digest(stored) else "rejected"
        assert outcome == expected[retry], (stored, retry)


def test_a_legacy_key_stored_without_an_offset_never_replays():
    with pytest.raises(ValidationError):                                # the identical retry is now refused
        current_digest(OFFSET_FREE)
    assert all(current_digest(r) != legacy_digest(OFFSET_FREE) for r in RETRIES)

