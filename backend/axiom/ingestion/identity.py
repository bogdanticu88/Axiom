"""Asset identity resolution with explicit uncertainty (S 5, D 5).

Rules:
* Only STRONG identifiers (provider IDs, registry repositories, repository URIs, source-scoped IDs) can match
  an existing asset. A record must carry at least one strong identifier.
* One strong match: reuse that asset. Several different assets matched: create a new asset marked
  'conflict' and open a review candidate. Nothing is merged automatically.
* WEAK identifiers (hostname, IP, FQDN, names) never match; overlaps open a 'weak_identifier_overlap'
  candidate for review and the assets stay separate.
* Strong identifiers already owned by another asset are not copied (the unique index would refuse it);
  they are recorded in the candidate instead.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from ..adapters.base import Identifier, SubjectHints, stable_digest
from ..db import TenantContext


@dataclass
class Resolution:
    asset_id: UUID
    created: bool
    identity_status: str
    pending_identifiers: list[Identifier]
    candidates: list[tuple[str, list[UUID], list[dict]]]   # (method, asset_ids, matched identifiers)


def resolve(conn: psycopg.Connection, ctx: TenantContext, subject: SubjectHints, scope_id: UUID) -> Resolution:
    strong = [i for i in subject.identifiers if i.strength == "strong"]
    weak = [i for i in subject.identifiers if i.strength == "weak"]
    if not strong:
        raise ValueError("subject has no strong identifier")
    rows = conn.execute(
        """SELECT asset_id, namespace, value FROM axiom.asset_identifiers
            WHERE strength = 'strong' AND valid_until IS NULL
              AND (namespace, value) IN (SELECT * FROM unnest(%s::text[], %s::text[]))""",
        ([i.namespace for i in strong], [i.value for i in strong])).fetchall()
    owners: dict[UUID, list[dict]] = {}
    for r in rows:
        owners.setdefault(r["asset_id"], []).append({"namespace": r["namespace"], "value": r["value"]})
    candidates: list[tuple[str, list[UUID], list[dict]]] = []
    claim = None
    if len(owners) > 1:
        # The same conflicting claim must resolve to the same holding asset on every record and every run,
        # instead of creating a new conflict asset each time.
        claim = Identifier("identity_claim", stable_digest(sorted((i.namespace, i.value) for i in strong)))
        held = conn.execute(
            """SELECT asset_id FROM axiom.asset_identifiers WHERE namespace = 'identity_claim' AND value = %s
                 AND valid_until IS NULL""", (claim.value,)).fetchone()
        if held:
            owners = {held["asset_id"]: [{"namespace": claim.namespace, "value": claim.value}]}
    if len(owners) == 1:
        asset_id, created, status = next(iter(owners)), False, None
    else:
        asset_id, created = uuid.uuid4(), True
        status = "conflict" if len(owners) > 1 else "resolved"
        conn.execute(
            """INSERT INTO axiom.assets(tenant_id, id, scope_id, asset_kind, display_name, identity_status)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (ctx.tenant_id, asset_id, scope_id, subject.kind, subject.display_name[:500], status))
        if len(owners) > 1:
            candidates.append(("strong_identifier_conflict", sorted(owners) + [asset_id],
                               [m for ms in owners.values() for m in ms]))
    if weak:
        overlap = conn.execute(
            """SELECT asset_id, namespace, value FROM axiom.asset_identifiers
                WHERE valid_until IS NULL AND asset_id <> %s
                  AND (namespace, value) IN (SELECT * FROM unnest(%s::text[], %s::text[]))""",
            (asset_id, [i.namespace for i in weak], [i.value for i in weak])).fetchall()
        others: dict[UUID, list[dict]] = {}
        for r in overlap:
            others.setdefault(r["asset_id"], []).append({"namespace": r["namespace"], "value": r["value"]})
        for other, matched in others.items():
            pair = sorted([asset_id, other])
            exists = conn.execute(
                """SELECT 1 FROM axiom.identity_candidates WHERE status = 'open' AND asset_ids @> %s::uuid[]
                     AND method = 'weak_identifier_overlap'""", (pair,)).fetchone()
            if not exists:
                candidates.append(("weak_identifier_overlap", pair, matched))
    owned_elsewhere = {(r["namespace"], r["value"]) for r in conn.execute(
        """SELECT namespace, value FROM axiom.asset_identifiers WHERE strength = 'strong' AND valid_until IS NULL
             AND asset_id <> %s AND (namespace, value) IN (SELECT * FROM unnest(%s::text[], %s::text[]))""",
        (asset_id, [i.namespace for i in strong], [i.value for i in strong]))}
    current = {(r["namespace"], r["value"]) for r in conn.execute(
        "SELECT namespace, value FROM axiom.asset_identifiers WHERE asset_id = %s AND valid_until IS NULL", (asset_id,))}
    claimed = [claim] if claim is not None and created else []
    pending = claimed + [i for i in subject.identifiers
               if (i.namespace, i.value) not in current
               and (i.strength == "weak" or (i.namespace, i.value) not in owned_elsewhere)]
    return Resolution(asset_id, created, status or "resolved", pending, candidates)


def record_identifiers(conn: psycopg.Connection, ctx: TenantContext, resolution: Resolution, *,
                       observation_id: UUID | None, declared: bool) -> None:
    for ident in resolution.pending_identifiers:
        conn.execute(
            """INSERT INTO axiom.asset_identifiers(tenant_id, id, asset_id, namespace, value, strength, origin,
                   source_observation_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT DO NOTHING""",
            (ctx.tenant_id, uuid.uuid4(), resolution.asset_id, ident.namespace, ident.value, ident.strength,
             "declared_by_importer" if declared else "observed", observation_id))


def record_candidates(conn: psycopg.Connection, ctx: TenantContext, resolution: Resolution, *, run_id: UUID,
                      observation_id: UUID | None) -> int:
    for method, asset_ids, matched in resolution.candidates:
        conn.execute(
            """INSERT INTO axiom.identity_candidates(tenant_id, id, run_id, observation_id, method, asset_ids,
                   matched_identifiers) VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (ctx.tenant_id, uuid.uuid4(), run_id, observation_id, method, asset_ids, Jsonb(matched)))
    return len(resolution.candidates)


def asset_version(conn: psycopg.Connection, ctx: TenantContext, asset_id: UUID, subject: SubjectHints,
                  observed_at: datetime) -> UUID:
    if subject.deployment_digest:
        row = conn.execute("SELECT id FROM axiom.asset_versions WHERE asset_id = %s AND deployment_digest = %s "
                           "ORDER BY observed_at LIMIT 1", (asset_id, subject.deployment_digest)).fetchone()
    else:
        row = conn.execute(
            """SELECT id FROM axiom.asset_versions WHERE asset_id = %s AND deployment_digest IS NULL
                 AND version_label IS NOT DISTINCT FROM %s ORDER BY observed_at DESC LIMIT 1""",
            (asset_id, subject.version_label)).fetchone()
    if row:
        return row["id"]
    version_id = uuid.uuid4()
    conn.execute(
        """INSERT INTO axiom.asset_versions(tenant_id, id, asset_id, deployment_digest, version_label, observed_at)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (ctx.tenant_id, version_id, asset_id, subject.deployment_digest, subject.version_label, observed_at))
    return version_id
