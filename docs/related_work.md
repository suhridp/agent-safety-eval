# Related work and positioning

Short literature pass (plan milestone 1). Check each paper's current version before citing.

## Benchmarks
* **AgentDojo** (Debenedetti et al., NeurIPS 2024 Datasets & Benchmarks; arXiv:2406.13352). A
  dynamic environment of realistic tool-using tasks (workspace, banking, travel, Slack) with
  injection tasks and pluggable attacks and defences. Reports both utility and attack success. The
  closest match to this project and the natural place to port these safeguards.
* **InjecAgent** (Zhan et al., Findings of ACL 2024; arXiv:2403.02691). A large set of indirect
  injection test cases across many tools, separating direct harm from data exfiltration. Single-turn
  style evaluation of whether the agent issues the attacker's tool call.
* **ToolEmu** (Ruan et al., ICLR 2024; arXiv:2309.15817). Uses an LLM to emulate tools and an LLM
  evaluator to flag risky actions caused by underspecified instructions, not attackers. Relevant to
  RQ2 (agents acting on bad state); differs in using LLM-judged risk instead of mechanical checks.
* **tau-bench** (Yao et al., 2024; arXiv:2406.12045). Tool-agent-user interaction with policy rules,
  scored by final database state. Its state-based scoring is the model for this project's
  completion checks; it measures reliability, not attacks.

## Defences
* **Spotlighting** (Hines et al., 2024; arXiv:2403.14720). Delimiting, datamarking or encoding
  untrusted input so the model can tell data from instructions. Implemented here as `spotlight`
  (delimiting plus datamarking).
* **CaMeL** (Debenedetti et al., 2025, "Defeating Prompt Injections by Design"; arXiv:2503.18813).
  Separates control flow (from the trusted query) from data flow (from untrusted tools) and enforces
  capability policies on values. This project's `grounding` layer is a much weaker, rule-based cousin
  of the same idea: targets of sensitive calls must come from trusted sources.
* **Instruction hierarchy / prompt hardening.** Telling the model that tool content is data. Cheap,
  widely used, and known to be bypassable; included as `hardened` as a baseline defence.
* **Classifier input filters.** Regex or model-based screening of tool output. Included as
  `regex_filter` (deliberately frozen, to measure overfitting) and `llm_screen`.

## Where this project fits
It is a small, fully understood harness, not a new benchmark. The contributions it can honestly
claim once results exist:
1. A controlled **ablation of layered safeguards** that reports safety and usefulness together on
   matched cells, with task-clustered uncertainty.
2. A **dev/held-out split of attack styles** that measures how much a filter's success is
   memorisation.
3. **Error propagation without an attacker** (RQ2) alongside injection, in the same harness.

The planned next step is to run the same layers on AgentDojo's tasks and attacks, which removes the
"same author wrote attacks and defences" weakness.
