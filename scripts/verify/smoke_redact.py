"""Filter for everything the Compose smoke test prints about a failure (scripts/verify/compose-smoke.sh).

    python3 scripts/verify/smoke_redact.py ENV_FILE < text > filtered

Replaces, line by line:
* every value in ENV_FILE (the secrets the smoke test generated) of 8 characters or more, wherever it appears;
* strings shaped like a JWT;
* the value after "Authorization: Bearer" or "Authorization: Basic";
* user information in URLs (scheme://user:password@host);
* the body of PEM private key blocks.

This is a best-effort filter for known shapes. It cannot recognise a secret it was not given and that has none of
these shapes (for example one that was encoded or split across lines), so output that passed through it should still
be treated as possibly sensitive. Each line is written as soon as it is filtered.
"""
from __future__ import annotations

import re
import sys

JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
AUTH = re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)\S+")
USERINFO = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/\s@]+@")
PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")


def load_secrets(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        values = [line.split("=", 1)[1].strip() for line in f if "=" in line]
    return sorted({v for v in values if len(v) >= 8}, key=len, reverse=True)


def redact_lines(lines, secrets: list[str]):
    in_key = False
    for line in lines:
        if in_key:                                   # inside a private key: drop everything up to its END line
            end = PEM_END.search(line)
            if not end:
                continue
            in_key = False
            line = line[end.end():]
            if not line.strip():
                continue
        begin = PEM_BEGIN.search(line)
        if begin:
            end = PEM_END.search(line, begin.end())
            if end:
                line = line[:begin.start()] + "<redacted-private-key>" + line[end.end():]
            else:
                in_key = True
                line = line[:begin.start()] + "<redacted-private-key>\n"
        for s in secrets:
            line = line.replace(s, "<redacted>")
        line = JWT.sub("<redacted-token>", line)
        line = AUTH.sub(r"\1<redacted>", line)
        line = USERINFO.sub(r"\1<redacted>@", line)
        yield line


def main(argv: list[str]) -> int:
    secrets = load_secrets(argv[1])
    for line in redact_lines(sys.stdin, secrets):
        sys.stdout.write(line)
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
