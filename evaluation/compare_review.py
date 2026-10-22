#!/usr/bin/env python3
"""Compare one reviewer's completed worksheet with the author's labels, keeping both and every disagreement.

    python3 evaluation/compare_review.py AUTHOR_LABELS_CSV WORKSHEET_CSV OUT_DIR

Writes OUT_DIR/comparison.csv (one row per scenario and field: author value, reviewer value, agree yes/no) and
OUT_DIR/comparison.md (counts and the disagreements with both rationales). It never edits evaluation/cases.json:
changing a label is a separate, recorded decision (evaluation/REVIEW-PROCEDURE.md). Rows the reviewer left blank are
reported as "not reviewed", not as agreement.
"""
from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path

FIELDS = [("presence", "author_presence", "reviewer_presence"),
          ("assessment", "author_assessment", "reviewer_assessment"),
          ("urgent", "author_urgent", "reviewer_urgent"),
          ("must_flag", "author_must_flag", "reviewer_must_flag")]


def norm(field: str, value: str) -> str:
    v = (value or "").strip().lower()
    if field == "must_flag":
        return " ".join(sorted(v.replace(",", " ").split()))
    if field == "urgent":
        return {"true": "yes", "false": "no"}.get(v, v)
    return v


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    author_path, sheet_path, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    author = {r["case"]: r for r in csv.DictReader(open(author_path))}
    sheet = {r["case"]: r for r in csv.DictReader(open(sheet_path))}
    out.mkdir(parents=True, exist_ok=True)
    rows, disagreements, counts = [], [], {"agree": 0, "disagree": 0, "not_reviewed": 0}
    for case, a in author.items():
        r = sheet.get(case, {})
        for name, af, rf in FIELDS:
            av, rv = norm(name, a.get(af, "")), norm(name, r.get(rf, ""))
            state = "not_reviewed" if not rv and name != "must_flag" else ("agree" if av == rv else "disagree")
            if name == "must_flag" and not r.get("reviewer_name"):
                state = "not_reviewed"
            counts[state] += 1
            rows.append({"case": case, "split": a["split"], "field": name, "author": av, "reviewer": rv,
                         "state": state, "reviewer_name": r.get("reviewer_name", "")})
            if state == "disagree":
                disagreements.append((case, name, av, rv, a.get("author_rationale", ""),
                                      r.get("reviewer_reasoning", ""), r.get("post_reveal_comment", "")))
    with open(out / "comparison.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    md = [f"# Label comparison: {sheet_path.name}\n",
          f"Worksheet sha256 `{hashlib.sha256(sheet_path.read_bytes()).hexdigest()}`; author labels sha256 "
          f"`{hashlib.sha256(author_path.read_bytes()).hexdigest()}`.\n",
          f"Fields: {counts['agree']} agree, {counts['disagree']} disagree, {counts['not_reviewed']} not reviewed.\n",
          "Nothing in evaluation/cases.json was changed by this comparison.\n", "## Disagreements\n"]
    if not disagreements:
        md.append("None recorded.\n")
    for case, field, av, rv, ar, rr, post in disagreements:
        md.append(f"* **{case} {field}**: author `{av}`, reviewer `{rv}`.\n  Author: {ar}\n  Reviewer: {rr}"
                  + (f"\n  After reveal: {post}" if post else "") + "\n")
    (out / "comparison.md").write_text("\n".join(md))
    print(f"{counts}; written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
