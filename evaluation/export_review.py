#!/usr/bin/env python3
"""Build a human-reviewable package of the evaluation scenarios and their reference labels.

    python3 evaluation/export_review.py EVAL_OUT_DIR PACKAGE_DIR

EVAL_OUT_DIR is the directory the harness wrote with AXIOM_EVAL_OUT (results.jsonl, evidence/, pipeline/). The package
separates dev and held-out scenarios. For each scenario it contains the scenario definition, the reference label and
its rationale, and the frozen evidence snapshot the label should be judged against. The deterministic fake's output is
kept in a separate folder so reviewers can judge labels without being anchored on it. Security-boundary results
(adversarial fakes) are reported on their own and are not a measure of reasoning quality.

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

README = """# Evaluation scenarios: independent review package ({version})

**Status of the reference labels: {status}.** Nobody other than their author has reviewed them. Please treat them as a
proposal to check, not as ground truth.

## What to review

For each scenario in `dev/` and `heldout/`:

1. Read `scenario.json` (what was imported and changed) and `evidence.json` (the frozen evidence snapshot, exactly as
   an analyst sees it: members, their freshness, contradictions with the platform's ordering result, and gaps).
2. Decide, from the evidence alone, whether the reference label is right: presence (`supported`, `contradicted`,
   `unknown`), assessment, urgency, and which gaps or contradictions must be flagged.
3. Record your judgement in `review.csv` (one row per scenario). Leave the reference columns unchanged; fill the
   `reviewer_*` columns. Disagreement is the useful outcome; please give a reason.

`review.csv` columns: `reviewer_agrees` (yes/no/partly), `reviewer_presence`, `reviewer_urgent`,
`reviewer_must_flag`, `reviewer_notes`, `reviewer_name`, `reviewed_at`.

## Rules for using this package

* **Dev and held-out are separate.** The held-out split must not be used to tune prompts, rules or thresholds. Labels
  may be corrected after review, but a correction made after looking at pipeline results on held-out cases must be
  recorded as such in `evaluation/cases.json`.
* **`pipeline-output/` is not a reference.** It holds what the deterministic fake (`fake-rules-v1`, a rule-based
  stand-in, not a language model) concluded. Its rules and the reference labels share an author, so agreement
  between them says nothing about model quality. Review the labels before opening it.
* **`security-boundary.md` is not reasoning quality.** It reports whether misbehaving fakes could get a wrong definite
  conclusion accepted (fabricated references, ignored contradictions, obeyed injected text, stale support). Those are
  tests of the platform's guards.

## Provenance

{provenance}

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
    missing = []
    rows = []
    for c in cases["cases"]:
        d = dst / c["split"] / c["id"]
        d.mkdir(parents=True)
        (d / "scenario.json").write_text(json.dumps({
            "id": c["id"], "split": c["split"], "target_index": c["target"],
            "target_vulnerability": results.get(c["id"], {}).get("target"), "operations": c["ops"],
            "note": c["note"], "reference": c["reference"], "rationale": c["rationale"],
            "label_status": LABEL_STATUS}, indent=1))
        ev = src / "evidence" / f"{c['id']}.json"
        if ev.is_file():
            shutil.copy(ev, d / "evidence.json")
        else:
            missing.append(c["id"])
        pipe = src / "pipeline" / f"{c['id']}.json"
        if pipe.is_file():
            (dst / "pipeline-output" / c["split"]).mkdir(parents=True, exist_ok=True)
            shutil.copy(pipe, dst / "pipeline-output" / c["split"] / f"{c['id']}.json")
        ref = c["reference"]
        rows.append({"case": c["id"], "split": c["split"],
                     "target_vulnerability": results.get(c["id"], {}).get("target", ""),
                     "label_status": LABEL_STATUS, "reference_presence": ref["presence"],
                     "reference_assessment": ref["assessment"], "reference_urgent": ref["urgent"],
                     "reference_must_flag": " ".join(ref["must_flag"]), "rationale": c["rationale"],
                     "reviewer_agrees": "", "reviewer_presence": "", "reviewer_urgent": "", "reviewer_must_flag": "",
                     "reviewer_notes": "", "reviewer_name": "", "reviewed_at": ""})
    with open(dst / "review.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    # security-boundary results, kept apart from label review
    sb = ["# Security-boundary tests (not a measure of reasoning quality)\n",
          "Each held-out scenario was also run with deliberately misbehaving deterministic fakes. The question is only "
          "whether the platform accepted a wrong definite conclusion (`supported` or `contradicted` that differs from "
          "the provisional reference). Because the reference is unreviewed, a corrected label could change a count.\n",
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
    shutil.copy(cases_path, dst / "cases.json")
    (dst / "README.md").write_text(README.format(
        version=cases["version"], status=LABEL_STATUS, provenance=cases["provenance"], cases_sha=sha256(cases_path),
        results_sha=sha256(results_path) if results_path.is_file() else "(not available)"))
    files = sorted(p for p in dst.rglob("*") if p.is_file())
    (dst / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.relative_to(dst)}\n" for p in files))
    print(f"wrote {len(files)} files to {dst}; scenarios without evidence: {missing or 'none'}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
