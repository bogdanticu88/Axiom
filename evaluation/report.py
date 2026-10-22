#!/usr/bin/env python3
"""Aggregate evaluation results (results.jsonl from tests/integration/test_evaluation_harness.py) into a report.

    python3 evaluation/report.py RESULTS_JSONL [OUT_MD]

Every figure comes from the result rows; nothing is estimated here. Limitations are printed with the figures.
"""
from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

LIMITATIONS = """\
* **No language model was evaluated.** The AI-assisted arm used the deterministic fake (`fake-rules-v1`), a
  rule-based stand-in. These figures describe the platform's pipeline and guards on these scenarios, not the quality
  of any model. A real-model arm exists (`AXIOM_TEST_REAL_MODEL=1`) and has not been run.
* **Agreement between the fake and the reference is expected, not evidence of accuracy.** The fake's rules and the
  reference labels were both written by the author from the same reading of the evidence rules. The useful
  results here are the guards: what the validator rejected or downgraded, and that no adversarial output was accepted
  as a wrong definite conclusion.
* **The reference labels and their rationales are author-generated and unreviewed.** "Reviewer corrections" are simulated: they
  count accepted AI conclusions that differ from the provisional reference.
* **The dataset is small** (16 scenarios, all derived from one real Trivy report of one image with labelled
  modifications). It covers presence, absence, staleness, partial coverage, injected text, credential-shaped text and
  asserted business context. It does not cover exploitability, reachability, multiple scanners or other asset types.
* **The deterministic policy does not assess presence.** It sets priority only, so its presence column is "not
  assessed". Missed urgent cases are identical for both arms by design: the AI arm cannot change priority.
* Latency was measured in-process on the CI machine against a local PostgreSQL. Token counts for the fake are
  estimates (characters divided by 4), and the cost is zero because the fake route has no price.
"""


def pct(n, d):
    return f"{n}/{d} ({100 * n / d:.0f}%)" if d else "0/0"


def main() -> int:
    rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()]
    out = []
    w = out.append
    version = json.loads((Path(__file__).resolve().parent / "cases.json").read_text())["version"]
    w(f"# Evaluation report ({version})\n")
    w(f"Scenarios: {len(rows)} ({sum(r['split'] == 'dev' for r in rows)} dev, "
      f"{sum(r['split'] == 'heldout' for r in rows)} held-out).\n")
    w("## Limitations (read first)\n")
    w(LIMITATIONS)
    for split in ("dev", "heldout", "all"):
        rs = [r for r in rows if split == "all" or r["split"] == split]
        if not rs:
            continue
        ai = [r["ai"] for r in rs]
        w(f"\n## Split: {split} ({len(rs)} scenarios)\n")
        w("| Measure | Deterministic policy | AI-assisted (fake-rules-v1) |")
        w("|---|---|---|")
        w(f"| Presence conclusion matches reference | not assessed | {pct(sum(a['presence_correct'] for a in ai), len(ai))} |")
        w(f"| Evidence correctness (accepted presence claims all match reference) | n/a | "
          f"{pct(sum(a['evidence_correct'] for a in ai), len(ai))} |")
        w(f"| Unsupported definite conclusions accepted | n/a | {sum(a['unsupported_conclusions'] for a in ai)} |")
        w(f"| Missed urgent cases (reference urgent, priority not urgent) | "
          f"{sum(r['policy']['missed_urgent'] for r in rs)} of {sum(r['reference']['urgent'] for r in rs)} | "
          f"{sum(a['missed_urgent'] for a in ai)} of {sum(r['reference']['urgent'] for r in rs)} (cannot change priority) |")
        w(f"| Simulated reviewer corrections | n/a | {sum(a['reviewer_corrections'] for a in ai)} |")
        w(f"| Claims downgraded by validation | n/a | {sum(a['downgraded'] for a in ai)} |")
        w(f"| Required gaps or contradictions not flagged | n/a | {sum(len(a['flags_missing']) for a in ai)} |")
        lat = [a["latency_ms"] for a in ai]
        plat = [r["policy"]["latency_ms"] for r in rs]
        w(f"| Latency per case, median / max (ms) | {statistics.median(plat):.0f} / {max(plat)} | "
          f"{statistics.median(lat):.0f} / {max(lat)} |")
        w(f"| Model calls / tool calls (total) | 0 / 0 | {sum(a['model_calls'] for a in ai)} / "
          f"{sum(a['tool_calls'] for a in ai)} |")
        w(f"| Tokens in / out (estimated) | 0 / 0 | {sum(a['input_tokens_estimated'] for a in ai)} / "
          f"{sum(a['output_tokens_estimated'] for a in ai)} |")
        w(f"| Cost (micro-units) | 0 | {sum(a['cost_micros'] for a in ai)} |")
    w("\n## Per scenario\n")
    w("| Case | Split | Reference presence | AI presence | Policy priority | Reference urgent | Notes |")
    w("|---|---|---|---|---|---|---|")
    for r in rows:
        notes = []
        if r["policy"]["missed_urgent"]:
            notes.append("policy missed urgent")
        if not r["ai"]["presence_correct"]:
            notes.append("AI presence differs")
        if r["ai"]["redactions"]:
            notes.append(f"{r['ai']['redactions']} redaction(s)")
        w(f"| {r['case']} | {r['split']} | {r['reference']['presence']} | {r['ai']['presence']} | "
          f"{r['policy']['priority']} | {r['reference']['urgent']} | {'; '.join(notes)} |")
    adv = defaultdict(lambda: defaultdict(int))
    for r in rows:
        for b, v in r["adversarial"].items():
            for k in ("claims", "rejected", "downgraded", "unsupported_accepted"):
                adv[b][k] += v[k]
            adv[b]["runs"] += 1
    if adv:
        w("\n## Security-boundary tests (separate from reasoning quality)\n")
        w("These runs use deliberately misbehaving fakes on the held-out scenarios. They test whether the platform's "
          "guards stop a wrong definite conclusion from being accepted; they are not a measure of reasoning quality "
          "and are not combined with the figures above.\n")
        w("| Behaviour | Runs | Claims | Rejected | Downgraded | Unsupported definite conclusions accepted |")
        w("|---|---|---|---|---|---|")
        for b, v in sorted(adv.items()):
            w(f"| {b} | {v['runs']} | {v['claims']} | {v['rejected']} | {v['downgraded']} | {v['unsupported_accepted']} |")
    text = "\n".join(out) + "\n"
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
