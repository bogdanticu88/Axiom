# Exposure of the former held-out scenarios (recorded 2026-10-22, checkpoint 6)

**Conclusion: the ten scenarios H1 to H10 are not an untouched held-out set.** From eval-cases@4 they are labelled
`regression`. They remain useful as regression tests; they cannot support a claim about generalisation, and no
figure computed on them is reported as held-out performance.

## What happened, from the repository record
| When (2026-10-22) | Exposure | Record |
|---|---|---|
| Checkpoint 4 | The same author wrote the scenarios, their reference labels and the deterministic fake's rules. Every label was read while writing it. | evaluation/cases.json (eval-cases@1), `investigation/providers.py` |
| Checkpoint 4 | **An implementation change was made in response to a held-out result.** Running H2 with the `stale_support` adversarial fake showed the claim validator accepting a conclusion against the latest observation; the `latest_observation_disagrees` downgrade was added. | docs/VERIFICATION.md run 16 ("Found by the evaluation harness (held-out H2, `stale_support` behaviour)"); commit c96cf14 |
| Checkpoint 5 | The scenario construction was changed (eval-cases@2: each import gets a later scan time). The stated reason was the new ordering rule, made before running either split under it; the change still applied to the held-out scenarios. | evaluation/cases.json `changes` |
| Checkpoint 5 | A written rationale was added for every held-out label (eval-cases@3), and held-out IDs were cited in design documents (H3, H10 in ADR 0012's amendment). | evaluation/cases.json, docs/adr/0012 |
| Checkpoints 4 and 5 | Held-out results (fake agreement, adversarial counts) were viewed in reports at every CI run. | docs/verification/*/evaluation-report.md |

No prompt exists to tune (no language model has been called). The fake's rules were not edited to match any held-out
label after they were written; the validator change above is the one recorded implementation change prompted by a
held-out result. That alone ends the set's status as held-out.

## Consequences
* `split: "regression"` for H1 to H10; `dev` for D1 to D6. Neither split is held out.
* Reports print "regression (formerly held-out; exposed)" and never "held-out".
* A real held-out set needs scenarios written and labelled by someone other than the author, stored where the author
  and the implementation work do not read them, and run only for a release decision. None exists.
* Independent review of the labels (evaluation/REVIEW-PROCEDURE.md) is a separate matter: it checks whether the
  author's labels are right, not whether the set is unseen. It is **pending**: no independent reviewer has taken part.
