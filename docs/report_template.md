# [Title: e.g. "Where layered safeguards help tool-using agents, and what they cost"]

*Draft structure for the mini-paper. Fill only with numbers from a committed `summary.json`.*

## Abstract (≤150 words)
Question, setup in one sentence (N tasks, M injection styles, K models, C configurations), the two or
three main findings with intervals, the main limitation.

## 1. Question
RQ1-RQ3 as in the README. Why it matters: agents that read untrusted content and can act.

## 2. Related work
Condensed from `docs/related_work.md`. Say plainly what is new here and what is not.

## 3. Method
* Environment and threat model (`docs/threat_model.md`), with the unsafe-action definition.
* Task suite and injection styles; the dev/held-out split and why.
* Safeguard layers and configurations (table).
* Models, temperature, trials per cell, seed, step limit, code version.
* Statistics: task-clustered bootstrap CIs; exact McNemar on matched cells with Holm correction.

## 4. Results
1. **Baseline vulnerability** per model and per style (heatmap figure). Report the no-attack
   completion rate in the same table.
2. **Safety vs. usefulness** per configuration (frontier figure + headline table).
3. **Generalisation:** dev vs. held-out styles for each filter.
4. **Ablations:** what removing each layer changes.
5. **Error propagation:** fault tasks, per configuration.
6. **Cost:** extra tokens, latency, confirmation prompts.

## 5. Failure analysis
Mechanism counts from hand-coding, with 2-3 short, generic excerpts. Include safeguard false
positives.

## 6. Limitations
Small synthetic suite; per-task unsafe definitions; same-author held-out styles; static attacks;
simulated confirming user; regex refusal detection; model versions and dates.

## 7. Reproducibility
`python -m agent_safety run configs/main.yaml` from commit `<hash>`; cached responses replay exactly.
