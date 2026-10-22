"""The label-comparison tool keeps author labels and reviewer judgements apart and never edits cases.json."""
from __future__ import annotations

import csv
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def write(path, rows):
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def test_comparison_reports_agreement_disagreement_and_unreviewed(tmp_path):
    author = [{"case": c, "split": "dev", "label_status": "author-generated", "author_presence": p,
               "author_assessment": "supported", "author_urgent": "no", "author_must_flag": f, "author_rationale": "a"}
              for c, p, f in (("D1", "supported", ""), ("D2", "contradicted", "presence_disagreement"), ("D3", "unknown", ""))]
    sheet = [{"case": "D1", "reviewer_presence": "supported", "reviewer_assessment": "supported", "reviewer_urgent": "no",
              "reviewer_must_flag": "", "reviewer_reasoning": "r", "reviewer_name": "x", "post_reveal_comment": ""},
             {"case": "D2", "reviewer_presence": "unknown", "reviewer_assessment": "supported", "reviewer_urgent": "no",
              "reviewer_must_flag": "presence_disagreement", "reviewer_reasoning": "order unclear",
              "reviewer_name": "x", "post_reveal_comment": ""},
             {"case": "D3", "reviewer_presence": "", "reviewer_assessment": "", "reviewer_urgent": "",
              "reviewer_must_flag": "", "reviewer_reasoning": "", "reviewer_name": "", "post_reveal_comment": ""}]
    write(tmp_path / "a.csv", author)
    write(tmp_path / "w.csv", sheet)
    cases = ROOT / "evaluation" / "cases.json"
    before = hashlib.sha256(cases.read_bytes()).hexdigest()
    subprocess.run([sys.executable, str(ROOT / "evaluation" / "compare_review.py"), str(tmp_path / "a.csv"),
                    str(tmp_path / "w.csv"), str(tmp_path / "out")], check=True, capture_output=True)
    rows = list(csv.DictReader(open(tmp_path / "out" / "comparison.csv")))
    state = {(r["case"], r["field"]): r["state"] for r in rows}
    assert state[("D1", "presence")] == "agree" and state[("D2", "presence")] == "disagree"
    assert state[("D3", "presence")] == "not_reviewed" and state[("D3", "must_flag")] == "not_reviewed"
    assert {(r["author"], r["reviewer"]) for r in rows if (r["case"], r["field"]) == ("D2", "presence")} == \
        {("contradicted", "unknown")}                          # both values kept side by side
    assert "order unclear" in (tmp_path / "out" / "comparison.md").read_text()
    assert hashlib.sha256(cases.read_bytes()).hexdigest() == before


def test_cases_file_marks_review_pending_and_calls_nothing_held_out():
    import json
    cases = json.loads((ROOT / "evaluation" / "cases.json").read_text())
    assert cases["review_status"].startswith("pending")
    assert {c["split"] for c in cases["cases"]} == {"dev", "regression"}       # nothing is called held-out
