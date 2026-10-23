"""API timestamps that name an instant must carry "Z" or a numeric offset (API contract correction, run 24).

Before the correction an offset-free value such as "2026-10-27T20:00:00" was accepted and stored as the database
session's local time, so it meant 20:00 UTC on a UTC server and 18:00 UTC on a Europe/Bucharest one. These tests are
run under both time zones (TZ and PGTZ) by the CI records; their assertions do not depend on either.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from axiom.provisioning import Provisioner

from .test_api import as_, client  # noqa: F401 - fixtures

pytestmark = pytest.mark.db
U = lambda: str(uuid.uuid4())                                         # noqa: E731
OFFSET_FREE = ["2026-10-27T20:00:00", "2026-10-27 20:00:00", "2026-10-27", 1761595200]

# every request body that carries an instant, with the instant field last; ids are random (validation runs first)
ENDPOINTS = [
    ("/cases/{x}/commands/defer", {"expected_version": 0, "rationale": "r"}, "review_at"),
    ("/cases/{x}/commands/accept-risk", {"expected_version": 0, "rationale": "r"}, "expires_at"),
    ("/assets/{x}/versions", {}, "observed_at"),
    ("/role-bindings", {"principal_id": "{x}", "role_id": "analyst", "scope_id": "{x}", "reason": "r"}, "valid_until"),
    ("/action-proposals", {"case_id": "{x}", "effect_class": "ticket.create", "connection_id": "{x}", "payload": {},
                           "verification_criteria": "c"}, "expires_at"),
    ("/action-proposals/{x}/versions", {"expected_version": 1, "payload": {}, "verification_criteria": "c"},
     "expires_at"),
    ("/action-proposals/{x}/versions/1/decisions", {"decision": "approved", "rationale": "r"}, "valid_until"),
    ("/cases/{x}/risk-acceptance-requests", {"expected_version": 0, "rationale": "r"}, "expires_at"),
    ("/reports/snapshots", {"kind": "exposure_summary", "scope_id": "{x}"}, "as_of"),
    ("/cases/{x}/commands/override-priority", {"expected_version": 0, "rationale": "r", "priority": "high"},
     "expires_at"),
]
TABLES = ["decisions", "audit_events", "case_events", "outbox", "jobs", "effect_intents", "idempotency_keys",
          "asset_versions", "role_bindings", "action_proposals", "action_proposal_versions", "approvals",
          "risk_acceptance_requests", "risk_acceptances", "priority_overrides", "report_snapshots", "finding_cases"]


def counts(admin_conn) -> dict:
    return {t: admin_conn.execute(f"SELECT count(*) AS n FROM axiom.{t}").fetchone()["n"] for t in TABLES}


def fill(template, x):
    if isinstance(template, dict):
        return {k: fill(v, x) for k, v in template.items()}
    return x if template == "{x}" else template


@pytest.mark.parametrize("value", OFFSET_FREE, ids=["T", "space", "date-only", "epoch-number"])
def test_offset_free_timestamps_are_refused_before_anything_is_written(client, as_, world, admin_conn, value):  # noqa: F811
    before = counts(admin_conn)
    headers = {**as_("admin"), "Idempotency-Key": f"instant-{uuid.uuid4().hex[:12]}"}
    for path, body, field in ENDPOINTS:
        x = U()
        r = client.post("/api/v1" + path.replace("{x}", x), headers=headers, json={**fill(body, x), field: value})
        assert r.status_code == 422, (path, r.text)
        err = r.json()["error"]
        assert err["code"] == "validation_failed"
        [detail] = err["details"]["errors"]                             # the timestamp is the only problem
        assert detail["loc"][-1] == field and "numeric UTC offset" in detail["msg"], (path, detail)
    assert counts(admin_conn) == before                                 # no row, job, intent or key was written


def test_equivalent_instants_are_stored_identically_and_different_instants_stay_distinct(client, as_, world,  # noqa: F811
                                                                                         admin_conn):
    analyst = as_("analyst")
    created = client.post("/api/v1/assets", headers=analyst, json={
        "scope_id": str(world.a.project), "kind": "container_image", "display_name": "instants"})
    assert created.status_code == 201, created.text
    asset = created.json()["id"]
    base = datetime(2026, 10, 27, 20, 0, tzinfo=timezone.utc)
    spellings = {"z": "2026-10-27T20:00:00Z", "utc": "2026-10-27T20:00:00+00:00", "bucharest": "2026-10-27T23:00:00+03:00",
                 "new_york": "2026-10-27T16:00:00-04:00", "compact": "2026-10-27T23:00:00+0300",
                 "same_wall_clock_other_zone": "2026-10-27T20:00:00+03:00", "one_second_later": "2026-10-27T20:00:01Z"}
    ids = {}
    for name, value in spellings.items():
        r = client.post(f"/api/v1/assets/{asset}/versions", headers=analyst,
                        json={"observed_at": value, "deployment_digest": "sha256:" + uuid.uuid4().hex * 2})
        assert r.status_code == 201, (name, r.text)
        ids[name] = r.json()["id"]
    stored = {name: admin_conn.execute("SELECT observed_at FROM axiom.asset_versions WHERE id = %s",
                                       (i,)).fetchone()["observed_at"] for name, i in ids.items()}
    for name in ("z", "utc", "bucharest", "new_york", "compact"):
        assert stored[name] == base, name
    assert stored["same_wall_clock_other_zone"] == base - timedelta(hours=3)
    assert stored["one_second_later"] == base + timedelta(seconds=1)


def test_equivalent_instants_on_role_expiry_and_report_time(client, as_, world, dbinfo, admin_conn):  # noqa: F811
    Provisioner(dbinfo.admin_cli_dsn).bootstrap_role(world.a.id, world["admin"], "policy_admin", world.a.root, "test")
    admin = as_("admin")
    until = (datetime.now(timezone.utc) + timedelta(days=3)).replace(microsecond=0)
    bindings = []
    for value in (until.isoformat().replace("+00:00", "Z"), until.astimezone(timezone(timedelta(hours=3))).isoformat()):
        r = client.post("/api/v1/role-bindings", headers=admin, json={
            "principal_id": str(world["viewer"]), "role_id": "analyst", "scope_id": str(world.a.project),
            "reason": "instants", "valid_until": value})
        assert r.status_code == 201, r.text
        bindings.append(r.json()["id"])
    got = [admin_conn.execute("SELECT valid_until FROM axiom.role_bindings WHERE id = %s", (b,)).fetchone()["valid_until"]
           for b in bindings]
    assert got == [until, until]
    as_of = datetime.now(timezone.utc).replace(microsecond=0)
    snaps = []
    for value in (as_of.isoformat(), as_of.astimezone(timezone(timedelta(hours=-5))).isoformat()):
        r = client.post("/api/v1/reports/snapshots", headers=as_("auditor"), json={
            "kind": "exposure_summary", "scope_id": str(world.a.project), "as_of": value})
        assert r.status_code == 201, r.text
        snaps.append(r.json())
    assert snaps[0]["content"] == snaps[1]["content"]


def test_an_offset_free_list_cursor_is_refused(client, as_):  # noqa: F811
    import base64
    cursor = base64.urlsafe_b64encode(f"2026-10-27T20:00:00|{uuid.uuid4()}".encode()).decode()
    r = client.get("/api/v1/cases", headers=as_("analyst"), params={"cursor": cursor})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_failed"


def test_the_services_refuse_offset_free_instants_from_internal_callers(world, run, ctx_for):
    """Defence in depth for callers that bypass the API schema: the two services that used to store or crash on an
    offset-free value now refuse it."""
    from axiom.errors import ValidationFailed
    asset = run(ctx_for("analyst"), lambda s: s.assets.create_asset(scope_id=world.a.project, kind="host",
                                                                    display_name="internal"))
    with pytest.raises(ValidationFailed, match="UTC offset"):
        run(ctx_for("analyst"), lambda s: s.assets.record_version(asset_id=asset["id"],
                                                                  observed_at=datetime(2026, 10, 27, 20, 0)))
    with pytest.raises(ValidationFailed, match="UTC offset"):
        run(ctx_for("admin"), lambda s: s.tenancy.assign_role(principal_id=world["viewer"], role_id="analyst",
                                                              scope_id=world.a.project, reason="r",
                                                              valid_until=datetime(2027, 1, 1)))
