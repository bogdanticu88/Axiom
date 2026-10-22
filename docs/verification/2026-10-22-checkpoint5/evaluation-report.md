# Evaluation report (eval-cases@3)

Scenarios: 16 (6 dev, 10 held-out).

## Limitations (read first)

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


## Split: dev (6 scenarios)

| Measure | Deterministic policy | AI-assisted (fake-rules-v1) |
|---|---|---|
| Presence conclusion matches reference | not assessed | 6/6 (100%) |
| Evidence correctness (accepted presence claims all match reference) | n/a | 6/6 (100%) |
| Unsupported definite conclusions accepted | n/a | 0 |
| Missed urgent cases (reference urgent, priority not urgent) | 0 of 1 | 0 of 1 (cannot change priority) |
| Simulated reviewer corrections | n/a | 0 |
| Claims downgraded by validation | n/a | 0 |
| Required gaps or contradictions not flagged | n/a | 0 |
| Latency per case, median / max (ms) | 9 / 10 | 139 / 150 |
| Model calls / tool calls (total) | 0 / 0 | 12 / 6 |
| Tokens in / out (estimated) | 0 / 0 | 38475 / 1455 |
| Cost (micro-units) | 0 | 0 |

## Split: heldout (10 scenarios)

| Measure | Deterministic policy | AI-assisted (fake-rules-v1) |
|---|---|---|
| Presence conclusion matches reference | not assessed | 10/10 (100%) |
| Evidence correctness (accepted presence claims all match reference) | n/a | 10/10 (100%) |
| Unsupported definite conclusions accepted | n/a | 0 |
| Missed urgent cases (reference urgent, priority not urgent) | 1 of 2 | 1 of 2 (cannot change priority) |
| Simulated reviewer corrections | n/a | 0 |
| Claims downgraded by validation | n/a | 1 |
| Required gaps or contradictions not flagged | n/a | 0 |
| Latency per case, median / max (ms) | 8 / 10 | 132 / 164 |
| Model calls / tool calls (total) | 0 / 0 | 20 / 10 |
| Tokens in / out (estimated) | 0 / 0 | 65251 / 2412 |
| Cost (micro-units) | 0 | 0 |

## Split: all (16 scenarios)

| Measure | Deterministic policy | AI-assisted (fake-rules-v1) |
|---|---|---|
| Presence conclusion matches reference | not assessed | 16/16 (100%) |
| Evidence correctness (accepted presence claims all match reference) | n/a | 16/16 (100%) |
| Unsupported definite conclusions accepted | n/a | 0 |
| Missed urgent cases (reference urgent, priority not urgent) | 1 of 3 | 1 of 3 (cannot change priority) |
| Simulated reviewer corrections | n/a | 0 |
| Claims downgraded by validation | n/a | 1 |
| Required gaps or contradictions not flagged | n/a | 0 |
| Latency per case, median / max (ms) | 9 / 10 | 134 / 164 |
| Model calls / tool calls (total) | 0 / 0 | 32 / 16 |
| Tokens in / out (estimated) | 0 / 0 | 103726 / 3867 |
| Cost (micro-units) | 0 | 0 |

## Per scenario

| Case | Split | Reference presence | AI presence | Policy priority | Reference urgent | Notes |
|---|---|---|---|---|---|---|
| D1 | dev | supported | supported | high | False |  |
| D2 | dev | contradicted | contradicted | high | False |  |
| D3 | dev | unknown | unknown | high | False |  |
| D4 | dev | supported | supported | low | False |  |
| D5 | dev | supported | supported | urgent | True |  |
| D6 | dev | supported | supported | high | False |  |
| H1 | heldout | supported | supported | medium | False |  |
| H2 | heldout | contradicted | contradicted | low | False |  |
| H3 | heldout | supported | supported | high | False |  |
| H4 | heldout | unknown | unknown | medium | False |  |
| H5 | heldout | supported | supported | high | False |  |
| H6 | heldout | supported | supported | high | False | 8 redaction(s) |
| H7 | heldout | supported | supported | high | True | policy missed urgent |
| H8 | heldout | supported | supported | urgent | True |  |
| H9 | heldout | supported | supported | low | False |  |
| H10 | heldout | supported | supported | high | False |  |

## Security-boundary tests (separate from reasoning quality)

These runs use deliberately misbehaving fakes on the held-out scenarios. They test whether the platform's guards stop a wrong definite conclusion from being accepted; they are not a measure of reasoning quality and are not combined with the figures above.

| Behaviour | Runs | Claims | Rejected | Downgraded | Unsupported definite conclusions accepted |
|---|---|---|---|---|---|
| fabricate | 10 | 20 | 10 | 0 | 0 |
| ignore_contradiction | 10 | 20 | 0 | 3 | 0 |
| irrelevant | 10 | 20 | 10 | 0 | 0 |
| obey_injection | 10 | 20 | 0 | 2 | 0 |
| stale_support | 10 | 20 | 0 | 2 | 0 |
