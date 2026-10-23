# Controlled failures of the Compose smoke diagnostics

Each log is one run of `scripts/verify/compose-smoke.sh` from the diagnostics change, made to fail on purpose. The
failures were induced from outside the script or in a throwaway copy of the checkout (shown as `<harness copy>`);
nothing here is part of the change itself.

| Log | How the failure was caused | Exit status | What the output shows |
|---|---|---|---|
| `startup.log` | a process held the API's host port 127.0.0.1:18010 before the run | 1 | the `docker compose up` output, ending in "failed to bind host port 127.0.0.1:18010/tcp: address already in use"; container states (api `created`, exit 128, with the same error); health results; service logs |
| `browser.log` | the copy's browser check printed the demo password and a token-shaped string, then exited non-zero | 1 | the browser check output with both replaced (`<redacted>`, `<redacted-token>`), then states, health and logs |
| `unexpected.log` | the copy ran an extra `curl` to a closed port after the first check, outside any `fail` call | 7 (curl's) | "unexpected exit 7 at line 111" with the command, then diagnostics; before this change such a failure ended the script with no message |
| `broken.log` | the copy put a `docker` that always fails first on `PATH`, then called `fail` | 1 | every collection step reports the failure; the run still exits 1 and the cleanup still removes the project |
| `hang.log` | as above, with a `docker` that sleeps 60 s | 1 | per-command limits and "(diagnostics time limit reached)"; about 140 s of collection; exit 1 |
| `normal.log` | no failure | 0 | `SMOKE PASS`; no diagnostics printed |

After every run no container of the project remained (`docker ps -a` with the project label was empty).
