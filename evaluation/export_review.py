#!/usr/bin/env python3
"""Build the independent-review package for the evaluation scenarios (procedure: evaluation/REVIEW-PROCEDURE.md).

    python3 evaluation/export_review.py EVAL_OUT_DIR PACKAGE_DIR

EVAL_OUT_DIR is the directory the harness wrote with AXIOM_EVAL_OUT (results.jsonl, evidence/, pipeline/).

Layout, designed so a reviewer can judge blind and the author's labels stay separately traceable:
  blind/<case>/evidence.json     frozen evidence only (no label, rationale, note or pipeline output)
  worksheet.csv                  one row per scenario; reviewer columns empty
  sealed/author-labels.csv       the author's labels and rationales (open after the worksheet is complete)
  sealed/scenarios/<case>.json   scenario definitions (operations and notes reveal the construction)
  pipeline-output/<case>.json    the deterministic fake's output (not a reference)
  security-boundary.md           misbehaving-fake results (not reasoning quality)
  README.md, SHA256SUMS

Nothing here is computed beyond copying and tabulating the inputs.
"""
from __future__ import annotations

import csv
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LABEL_STATUS = "author-generated, unreviewed"
REVIEWER_COLUMNS = ["reviewer_presence", "reviewer_assessment", "reviewer_urgent", "reviewer_must_flag",
                    "reviewer_reasoning", "reviewer_name", "reviewed_at", "post_reveal_comment"]

README = """# Evaluation labels: independent review package ({version})

**Review status: pending.** No independent reviewer has taken part. The labels are {status}.
**Neither split is held out** (evaluation/EXPOSURE.md): `dev` and `regression` (formerly held-out) were both written
and inspected by the author.

Follow evaluation/REVIEW-PROCEDURE.md (copied here as REVIEW-PROCEDURE.md):

1. Judge each scenario from `blind/<case>/evidence.json` only, filling in `worksheet.csv`.
2. Record `sha256sum worksheet.csv` and send it to the coordinator.
3. Only then open `sealed/author-labels.csv` and add post-reveal comments.
4. Run `python3 evaluation/compare_review.py sealed/author-labels.csv worksheet.csv OUT_DIR`.

`pipeline-output/` is the deterministic fake's output (`fake-rules-v1`, a rule-based stand-in, not a language model).
It is not a reference; its agreement with the author's labels says nothing about model quality.
`security-boundary.md` reports whether misbehaving fakes got a wrong definite conclusion accepted; that is a test of
the platform's guards, not of reasoning quality.

Scenario file: `evaluation/cases.json` ({version}), sha256 `{cases_sha}`.
Harness results: `results.jsonl` from the run that produced this package, sha256 `{results_sha}`.
"""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    cases_path = ROOT / "cases.json"
    cases = json.loads(cases_path.read_text())
    results_path = src / "results.jsonl"
    results = {}
    if results_path.is_file():
        for line in results_path.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                results[r["case"]] = r
    if dst.exists():
        shutil.rmtree(dst)
    (dst / "sealed" / "scenarios").mkdir(parents=True)
    (dst / "pipeline-output").mkdir()
    missing, worksheet, author = [], [], []
    for c in cases["cases"]:
        ev = src / "evidence" / f"{c['id']}.json"
        (dst / "blind" / c["id"]).mkdir(parents=True)
        if ev.is_file():
            shutil.copy(ev, dst / "blind" / c["id"] / "evidence.json")
        else:
            missing.append(c["id"])
        pipe = src / "pipeline" / f"{c['id']}.json"
        if pipe.is_file():
            shutil.copy(pipe, dst / "pipeline-output" / f"{c['id']}.json")
        target = results.get(c["id"], {}).get("target", "")
        (dst / "sealed" / "scenarios" / f"{c['id']}.json").write_text(json.dumps({
            "id": c["id"], "split": c["split"], "target_index": c["target"], "target_vulnerability": target,
            "operations": c["ops"], "note": c["note"]}, indent=1))
        worksheet.append({"case": c["id"], "split": c["split"], "target_vulnerability": target,
                          "evidence": f"blind/{c['id']}/evidence.json", **{k: "" for k in REVIEWER_COLUMNS}})
        ref = c["reference"]
        author.append({"case": c["id"], "split": c["split"], "label_status": LABEL_STATUS,
                       "author_presence": ref["presence"], "author_assessment": ref["assessment"],
                       "author_urgent": "yes" if ref["urgent"] else "no",
                       "author_must_flag": " ".join(ref["must_flag"]), "author_rationale": c["rationale"]})
    for name, rows in (("worksheet.csv", worksheet), ("sealed/author-labels.csv", author)):
        with open(dst / name, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    sb = ["# Security-boundary tests (not a measure of reasoning quality)\n",
          "Each regression scenario was also run with deliberately misbehaving deterministic fakes. The question is "
          "only whether the platform accepted a wrong definite conclusion (`supported` or `contradicted` that "
          "differs from the author's unreviewed label). A corrected label could change a count.\n",
          "| Scenario | Behaviour | Run status | Claims | Rejected | Downgraded | Wrong definite conclusions accepted |",
          "|---|---|---|---|---|---|---|"]
    for cid, r in results.items():
        for b, v in sorted(r.get("adversarial", {}).items()):
            sb.append(f"| {cid} | {b} | {v['status']} | {v['claims']} | {v['rejected']} | {v['downgraded']} | "
                      f"{v['unsupported_accepted']} |")
    if len(sb) == 4:
        sb.append("| (no adversarial results in this run) | | | | | | |")
    (dst / "security-boundary.md").write_text("\n".join(sb) + "\n")
    if results_path.is_file():
        shutil.copy(results_path, dst / "results.jsonl")
    shutil.copy(cases_path, dst / "sealed" / "cases.json")
    for doc in ("REVIEW-PROCEDURE.md", "EXPOSURE.md"):
        shutil.copy(ROOT / doc, dst / doc)
    (dst / "README.md").write_text(README.format(
        version=cases["version"], status=LABEL_STATUS, cases_sha=sha256(cases_path),
        results_sha=sha256(results_path) if results_path.is_file() else "(not available)"))
    files = sorted(p for p in dst.rglob("*") if p.is_file())
    (dst / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.relative_to(dst)}\n" for p in files))
    print(f"wrote {len(files)} files to {dst}; scenarios without evidence: {missing or 'none'}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
