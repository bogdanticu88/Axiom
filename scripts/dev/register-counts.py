#!/usr/bin/env python3
"""Count requirement statuses directly from docs/REQUIREMENTS.md.

Every table row whose first cell is an identifier is counted, using the column headed "Status" (or "Support level" in
the integration catalogue). A row whose status cell does not start with a known status word is reported and makes the
script exit non-zero, so no row can silently fall out of the totals. Rows in the "Known gaps" summary are not
requirements and are skipped.

    python3 scripts/dev/register-counts.py [--markdown]
"""
from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

REGISTER = Path(__file__).resolve().parents[2] / "docs" / "REQUIREMENTS.md"
STATUSES = ("verified", "implementing", "implemented_unverified", "planned", "blocked")
SUPPORT = ("fixture-tested", "sandbox-validated", "production-supported", "planned")
ID = re.compile(r"^[A-Z][A-Za-z]*-?\d+[a-z]?$")


def cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def first_word(cell: str) -> str:
    return re.sub(r"[^a-z_-]", "", cell.split()[0].lower()) if cell.split() else ""


def main() -> int:
    section, header = None, None
    counts: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    catalogue: collections.Counter = collections.Counter()
    problems, seen = [], collections.Counter()
    for n, line in enumerate(REGISTER.read_text().splitlines(), 1):
        if line.startswith("## "):
            section, header = line[3:].strip(), None
            continue
        if not line.startswith("|"):
            header = None if not line.strip() else header
            continue
        c = cells(line)
        if header is None:
            header = [h.lower() for h in c]
            continue
        if set(line.replace("|", "").strip()) <= set("-: "):
            continue
        if not ID.match(c[0]) or section is None or section.startswith("Known gaps"):
            continue
        seen[c[0]] += 1
        if "support level" in header:
            word = c[header.index("support level")].replace("*", "").split(" ")[0].lower()
            word = word if word in SUPPORT else "?"
            catalogue[word] += 1
            if word == "?":
                problems.append(f"line {n}: {c[0]} has no recognised support level")
            continue
        if "status" not in header:
            problems.append(f"line {n}: {c[0]} is in a table without a Status column")
            continue
        word = first_word(c[header.index("status")])
        if word not in STATUSES:
            problems.append(f"line {n}: {c[0]} status {c[header.index('status')]!r} is not one of {STATUSES}")
            word = "?"
        counts[section][word] += 1
    total = collections.Counter()
    for sec_counts in counts.values():
        total.update(sec_counts)
    md = "--markdown" in sys.argv
    if md:
        print("| Section | " + " | ".join(STATUSES) + " | Rows |")
        print("|---|" + "---|" * (len(STATUSES) + 1))
    for sec, c in counts.items():
        row = [str(c.get(s, 0)) for s in STATUSES]
        print(f"| {sec} | " + " | ".join(row) + f" | {sum(c.values())} |" if md else
              f"{sec[:58]:58} " + " ".join(f"{s}={c.get(s, 0)}" for s in STATUSES) + f" rows={sum(c.values())}")
    summary = " + ".join(f"{s} {total.get(s, 0)}" for s in STATUSES)
    print(f"\nRequirements: {summary} = {sum(total.values())} rows"
          + (f" (unrecognised: {total['?']})" if total.get("?") else ""))
    print("Integration catalogue: " + ", ".join(f"{k} {v}" for k, v in sorted(catalogue.items()))
          + f" = {sum(catalogue.values())} rows")
    dup = [k for k, v in seen.items() if v > 1]
    if dup:
        problems.append(f"duplicate identifiers: {dup}")
    for p in problems:
        print("PROBLEM:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
