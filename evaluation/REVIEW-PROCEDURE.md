# Independent review of the evaluation labels

Status: **pending**. No independent reviewer has taken part. Until one does, every label in
`evaluation/cases.json` is the author's and is reported as author-generated and unreviewed.

## Who
One or more people who did not write the scenarios, the labels or the platform's validator, with working knowledge of
container-image vulnerability scanning. Each reviewer works alone; record each reviewer separately.

## Materials (from `evaluation/export_review.py`)
* `blind/<case>/evidence.json` for every scenario: the frozen evidence snapshot exactly as an analyst sees it
  (members, freshness, contradictions with the platform's ordering result, gaps). Credential-shaped text is redacted.
  The blind folder contains **no** author label, rationale, scenario note or pipeline output.
* `worksheet.csv`: one row per scenario, the reviewer's columns empty.
* `sealed/author-labels.csv`: the author's labels and rationales. Open it only after the worksheet is complete.
* `pipeline-output/`: what the deterministic fake concluded. It is not a reference and is not needed for the review.

## Steps
1. **Blind judgement.** For each scenario, from `evidence.json` alone, fill in the worksheet:
   `reviewer_presence` (supported / contradicted / unknown: does the evidence establish that the vulnerability is
   present in the deployed version?), `reviewer_assessment` (supported / not_supported / inconclusive),
   `reviewer_urgent` (yes / no), `reviewer_must_flag` (space-separated gap and contradiction kinds a correct analysis
   must surface), `reviewer_reasoning` (one or two sentences), `reviewer_name`, `reviewed_at`.
   Do not open `sealed/` or `pipeline-output/` before this step is finished.
2. **Seal your answers.** Record `sha256sum worksheet.csv` and send it to the coordinator before step 3, so later
   edits to the blind judgements are detectable.
3. **Compare.** Open `sealed/author-labels.csv`. For each row where you disagree, you may add `post_reveal_comment`;
   do not change the blind columns.
4. **Run the comparison:** `python3 evaluation/compare_review.py <package>/sealed/author-labels.csv worksheet.csv
   OUT_DIR`. It writes `comparison.csv` and `comparison.md`, keeping author labels, the reviewer's judgements and each
   disagreement side by side. It changes nothing in the repository.
5. **Store** the completed worksheet, its recorded digest and the comparison under `evaluation/reviews/<reviewer>-<date>/`.

## Resolving disagreements
* The author's labels in `cases.json` are never overwritten silently. A changed label is a new version of
  `cases.json` (`eval-cases@N`) whose `changes` entry names the scenario, the old and new label, the reviewer record
  it relies on and who decided.
* A disagreement may also be resolved by keeping the author's label, with the reason recorded next to the comparison.
* Labels on the regression split (H1 to H10) may be corrected like any other; doing so does not make that split
  held-out again (evaluation/EXPOSURE.md).

## What review does not establish
Agreement between a reviewer and the author shows the labels are defensible. It does not measure any language model,
does not turn the deterministic fake's agreement into evidence of model quality, and does not turn the
security-boundary counts (misbehaving fakes rejected or downgraded) into reasoning quality.
