# ADR 0015: API timestamps must name an instant

Status: accepted (2026-10-23). Corrects the API contract; see run 24 in docs/VERIFICATION.md.

## Problem
Request fields such as `expires_at` were declared as plain `datetime`. The API therefore accepted values without an
offset (`"2026-10-27T20:00:00"`, `"2026-10-27"`, and even a bare number of seconds). psycopg sends a value without an
offset as a local time, and PostgreSQL reads it in the session's time zone, which comes from the server's
configuration. The same request named 20:00 UTC on a UTC server and 18:00 UTC on a Europe/Bucharest server
(2026-10-27 is after the change to winter time). Nothing recorded which reading was used.

A related defect in the idempotency digest (fixed in `b3daefb`) compared timestamps by spelling, so the same instant
with another offset was treated as a different request.

## Decision
Every request field that names an instant must be an RFC 3339 date-time with `Z` or a numeric offset (`+03:00`, also
`+0300`). Anything else is refused with `422 validation_failed`, before any handler runs, with the message
"timestamp must be an RFC 3339 date-time with 'Z' or a numeric UTC offset". The server never assigns a zone. Accepted
values are converted to UTC on input, so persistence and the idempotency digest see one form.

| Request field | Endpoint |
|---|---|
| `review_at` | `POST /cases/{id}/commands/defer` |
| `expires_at` | `POST /cases/{id}/commands/accept-risk`, `POST /cases/{id}/risk-acceptance-requests`, `POST /cases/{id}/commands/override-priority` (optional), `POST /action-proposals`, `POST /action-proposals/{id}/versions` |
| `observed_at` | `POST /assets/{id}/versions` |
| `valid_until` | `POST /role-bindings` (optional), `POST /action-proposals/{id}/versions/{v}/decisions` (optional) |
| `as_of` | `POST /reports/snapshots` (optional) |
| list cursor | `GET /cases?cursor=…` (issued by the server with an offset; one without is refused) |

The two services that did not check offsets themselves (`AssetService.record_version`, `TenancyService.assign_role`)
now refuse values without one, for callers that bypass the API schema. The other services already refused them.

**No field is date-only or local-calendar.** There are no birthday-style dates, business calendars or "local
midnight" fields in the API or the policies. Durations (hours, days) and Tenable's `since` (a number of seconds since
the Unix epoch, sent by the server) are not timestamps in this sense.

**Imports.** The scanner adapters already followed this rule: `parse_time` returns "unknown" for a source time without
an offset, so the observation's `source_time` is empty instead of guessed. The raw value is kept in the stored source
record and the evidence file. When the source time is unknown, the asset version created by the import uses the
import's own time, which is when Axiom observed it.

**Analyst UI.** Date and time inputs are the browser's `datetime-local`, which has no offset. The UI converts them in
the browser's own zone and sends UTC (`…Z`). The labels say "your local time". Before this change the default value of
the risk-acceptance and override inputs was written in UTC but read as local time, so the default was off by the
browser's offset; the instant sent was still explicit.

Responses are unchanged: the database renders timestamps with the session's offset (for example `+02:00`), which is
unambiguous.

## Idempotency keys created before normalisation
Keys are kept for 7 days. Whether a retry after the upgrade replays depends on how the instant was spelled in the
**original** request, because that is what the stored digest covers. Earlier versions digested the body as FastAPI
encodes it, which writes a UTC instant as `...Z` and keeps any other offset as sent. The API now converts every instant
to UTC before encoding, so every equivalent retry produces the `...Z` form.

| Original request stored with | Retry with `Z` | Retry with `+00:00` | Retry with `+03:00` | Retry with `+0300` | Retry without offset |
|---|---|---|---|---|---|
| `Z` | replays | replays | replays | replays | refused (422 validation) |
| `+00:00` | replays | replays | replays | replays | refused (422 validation) |
| a nonzero offset, e.g. `+03:00` | rejected | rejected | rejected, even with the identical text | rejected | refused (422 validation) |
| no offset | rejected | rejected | rejected | rejected | refused (422 validation) |

"Rejected" means `422 idempotency_key_reused`: nothing is created twice, and the client must send the command again
with a new key. The retry's own offset does not decide the outcome; the original spelling does. The table is checked
by `tests/unit/test_idempotency_legacy_keys.py`, which recomputes the stored digest exactly as the earlier code did.

## Records accepted before the correction
Behaviour of the code before the correction, per path:
* `POST /assets/{id}/versions` stored an offset-free `observed_at`, read in the server's time zone (tested: the same
  request stored 20:00 UTC under UTC and 18:00 UTC under Europe/Bucharest).
* `POST /role-bindings` with an offset-free `valid_until` failed with a server error (comparison of naive and aware
  times) inside the transaction and stored nothing (tested under UTC).
* Every other field above was refused by its service, which already required a timezone-aware value, and stored
  nothing (established by reading the code: `defer`, risk requests and direct acceptance, proposal create and revise,
  approval decisions, priority overrides, report snapshots).
* Imports never stored a guessed source time (`parse_time`, unchanged since the adapters were written).

So the only possibly ambiguous history is the `observed_at` of asset versions recorded by hand through the API. **Such
records cannot be identified afterwards.** The column holds only the resulting instant; the submitted text is not
stored; the audit event (`asset.version_recorded`) records the asset and digest but not the time; and the session time
zone in force at the time is not recorded. Versions created by that command can be listed from the audit log, but
whether any of them was sent without an offset, and what zone the sender meant, cannot be reconstructed from Axiom's
records. Only outside evidence (the sender's own logs or deployment records) could settle it. Nothing has been
reinterpreted.

No long-lived installation exists: every database so far was a disposable test, demonstration or Compose smoke
database.

## Consequences
* Clients that sent offset-free timestamps now receive `422`. This is a breaking change for them, made deliberately.
* `observed_at`, `valid_until` and the other fields are validated at the edge; services still check the remaining
  constraints (future, maximum length) as before.
