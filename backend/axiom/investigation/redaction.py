"""Secret redaction applied to every string the gateway sends to a model provider (prompts and tool results).

Pattern-based, so it is a safety net, not a guarantee: it catches common credential shapes (cloud keys, private key
blocks, bearer tokens, JWTs, credentials in URLs and connection strings, key=value secrets, well-known token
prefixes). Each redaction is counted per run. Content that should never leave the installation must be excluded by
classification (gateway) rather than relying on this.
"""
from __future__ import annotations

import re

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{12,}")),
    ("url_credentials", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@")),
    ("key_value_secret", re.compile(
        r"(?i)\b(password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?key|token|aws_secret_access_key)"
        r"(\s*[:=]\s*)(\"[^\"]{4,}\"|'[^']{4,}'|[^\s,;\"']{4,})")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("generic_sk", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
]


def redact(text: str) -> tuple[str, int]:
    """Return the redacted text and the number of redactions."""
    count = 0

    def sub(kind: str):
        def _f(m: re.Match) -> str:
            nonlocal count
            count += 1
            if kind == "bearer":
                return f"{m.group(1)} [REDACTED:{kind}]"
            if kind == "url_credentials":
                return f"{m.group(1)}[REDACTED:{kind}]@"
            if kind == "key_value_secret":
                return f"{m.group(1)}{m.group(2)}[REDACTED:{kind}]"
            return f"[REDACTED:{kind}]"
        return _f

    for kind, pattern in _PATTERNS:
        text = pattern.sub(sub(kind), text)
    return text, count
