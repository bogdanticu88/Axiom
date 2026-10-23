# Controlled failures of the Compose smoke diagnostics

Each log is one run of `scripts/verify/compose-smoke.sh`, made to fail on purpose. The harness, not the script, put
the seconds since the run started at the front of every line. The failures were induced from outside the script or in
a throwaway copy of the checkout (shown as `<harness copy>`); nothing here is part of the change itself. Every run
used images already on the machine, so none of them is a cold install (see "Registry throttling" in
`docs/IMPLEMENTATION_STATUS.md`).

## The time limit, and why an earlier record said "about 140 s"

The first version of the diagnostics claimed "about two minutes overall" and recorded "about 140 s" for a hung Docker.
Measured again with that first version (`before-hang.log`, `before-hangterm.log`):

* With a `docker` that sleeps 60 s (`before-hang.log`), collection took 120.0 s (47.7 s to 167.7 s), then cleanup
  with the real Docker took 21 s. The earlier "about 140 s" was that sum, measured from the failure to the end of the
  run, and was reported as if it were collection alone.
* The limit was checked only before each loop step, so a step started just before it could run its whole allowance
  (20 s) after it: up to about 140 s of collection, not 120.
* `timeout` sent SIGTERM but never SIGKILL. With a `docker` that ignores SIGTERM (`before-hangterm.log`), each
  "20 s" command ran for its full 60 s. A process that never exited would have kept collection running indefinitely.
* Cleanup (`docker compose down -v`) had no limit.

Now every collection command gets the smaller of its own allowance and what remains of the overall limit, including a
5 s grace period before SIGKILL, so collection ends within `DIAG_LIMIT` (120 s). Cleanup has its own limit of 60 s
plus 10 s before SIGKILL. After a failure, collection and cleanup together take at most about 190 s whatever state
Docker is in, and the exit status is still that of the original failure.

## Runs of the current version

| Log | How the failure was caused | Exit status | What the output shows |
|---|---|---|---|
| `build.log` | `BUILD=1`, with a stand-in for `docker build` only, which prints a registry URL with a password and an `Authorization: Basic` header and fails | 1 | the build output with both replaced (`https://<redacted>@...`, `Authorization: Basic <redacted>`) |
| `startup.log` | a process held the API's host port 127.0.0.1:18010 | 1 | the `docker compose up` output ending in "failed to bind host port 127.0.0.1:18010/tcp: address already in use"; container states (api `created`, exit 128, same error); health results; service logs |
| `browser.log` | the copy's browser check printed the demo password, a JWT-shaped string, an `Authorization: Bearer` header, a proxy URL with a password and a private key block, then exited 1 | 1 | all five replaced, then states, health and logs |
| `unexpected.log` | the copy ran a `curl` to a closed port after the first check, outside any `fail` call | 7 (curl's) | "unexpected exit 7 at line 142" with the command, then diagnostics |
| `broken.log` | a `docker` that always fails, first on `PATH` during collection, then `fail` | 1 | every collection step reports the failure; cleanup with the real Docker removes the project |
| `hang.log` | a `docker` that sleeps 60 s during collection | 1 | collection 114 s (30.0 s to 144.1 s), each step cut at 20 s or at the overall limit; cleanup 21 s |
| `hangterm.log` | a `docker` that ignores SIGTERM and sleeps 60 s | 1 | four steps killed 5 s after SIGTERM ("Killed"); collection 119 s (30.0 s to 149.0 s); cleanup 21 s |
| `cleanuphang.log` | a `docker` that ignores SIGTERM and sleeps 600 s, also left on `PATH` for the cleanup | 1 | collection 119 s; cleanup killed at 70.0 s (148.7 s to 218.7 s), then "cleanup: ... did not finish within 60 s; project ... may remain" |
| `normal.log` | no failure | 0 | `SMOKE PASS`; no diagnostics |

After every run except `cleanuphang`, no container or volume of the project remained. In `cleanuphang` the cleanup
was prevented on purpose: 8 containers and 6 volumes remained, and the harness removed them afterwards. No stand-in
process was still running after any run.

Two earlier `cleanuphang` attempts used a stand-in that slept only 60 s, so it exited by itself exactly at the cleanup
limit, before SIGKILL was needed. They did not test the kill and are not recorded here.

None of the planted values appears in any log, and neither does any 32-character hexadecimal string (the shape of the
generated secrets). That is evidence about these runs, not a guarantee. The filter replaces values it was given and a
few known shapes; it cannot recognise every secret (`scripts/verify/smoke_redact.py`).
