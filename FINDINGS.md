# Findings Inventory

Every claim the paper and presentation can make, with provenance and status.
Update this as the overnight sweep completes and as writeup progresses.

**Status legend:**
- ✅ CONFIRMED — we have the data/artifact in hand
- ⏳ PENDING-SWEEP — waiting for `results_agentdojo.jsonl`
- 📝 NEEDS-WRITEUP — data exists but still needs paper prose
- 💭 INTERPRETATION — claim requires analysis, not just data

---

## 1. Methodological contributions (not dependent on sweep)

### F1. Adaptivity gap as a reporting metric
- **Claim:** Defenses claiming low ASR under hand-crafted attacks should also
  report ASR under attacker-aware rephrasing. The per-defense gap between
  these two numbers quantifies how much the baseline evaluation overstates
  real-world robustness.
- **Status:** ✅ CONFIRMED (concept + metric implementation)
- **Artifact:** `experiments/metrics.py::compute_adaptivity_gap`
- **Where in paper:** §5.3 intro paragraph

### F2. TSR × ASR joint reporting
- **Claim:** Agent-security evaluations should report task success rate (TSR)
  alongside attack success rate (ASR) because a defense that blocks attacks
  by also blocking legitimate tasks is useless. We adopt AgentDojo's utility
  measurement and rename it TSR for clarity.
- **Status:** ✅ CONFIRMED (metric implemented, driver reports both per cell)
- **Artifact:** `experiments/metrics.py::compute_tsr`, driver tables
- **Where in paper:** §5.4

### F3. Ground-truth TMR (fixes standard TMR's circularity)
- **Claim:** Standard TMR regex-matches tool arguments against the same
  patterns defenders use to detect misuse. Under adaptive attacks (`ev1l.com`
  instead of `evil.com`), TMR drops not because misuse decreased but because
  the metric lost sight of it. We propose a ground-truth variant that uses
  the attack's declared `target_tool` / `target_arg_check`.
- **Status:** ✅ CONFIRMED (implemented)
- **Artifact:** `experiments/metrics.py::compute_ground_truth_tmr`
- **Where in paper:** Short subsection in §5.3 (methodological footnote)

---

## 2. Artifact contributions (not dependent on sweep)

### F4. Two adaptive attack templates for AgentDojo
- **Claim:** `reworded_important_instructions` (rewords to avoid 11 regex
  injection-detection patterns) and `blended_task_context` (phrases as
  legitimate task content to slip past isolation/provenance markers).
- **Status:** ✅ CONFIRMED (registered with AgentDojo attack registry)
- **Artifact:** `agentdojo_integration/attacks_adaptive_agentdojo.py`
- **Where in paper:** §5.3 methods paragraph + appendix

### F5. Adaptive variants of the 8 legacy attacks
- **Claim:** Each of the 8 midterm attacks has an adaptive counterpart
  targeting one of three evasion strategies (reword / blend / obfuscate).
- **Status:** ✅ CONFIRMED
- **Artifact:** `experiments/attacks_adaptive.py`
- **Where in paper:** §5.3 appendix

### F6. Port of 4 defenses to AgentDojo's BasePipelineElement
- **Claim:** The four midterm defenses (prompt_isolation, provenance,
  tool_permission, prompt_detection) are ported to AgentDojo's pipeline API
  so the same defenses can be evaluated in a realistic stateful environment.
- **Status:** ✅ CONFIRMED
- **Artifact:** `agentdojo_integration/defenses_agentdojo.py`
- **Where in paper:** §5.4 methods

---

## 3. Empirical findings from the midterm (already shipped)

### F7. Direct vs. indirect ASR asymmetry in real LLMs
- **Claim:** LLMs with safety training (Llama 3.2 3B) refuse direct
  injection at ~70% (baseline ASR 30%) but follow indirect injection at
  ~75% — RLHF doesn't cover data returned by tools the agent requested
  itself.
- **Status:** ✅ CONFIRMED (midterm results, `experiments/results.md`)
- **Where in paper:** §5.1–5.2 (preserved from midterm)

### F8. Simulation overestimates direct ASR, underestimates indirect ASR
- **Claim:** Rule-based simulator reports 75% direct ASR vs LLM's 30%
  (no RLHF modeling); simulator reports 48.5% indirect vs LLM's 75%
  (no model of LLM tool-output trust).
- **Status:** ✅ CONFIRMED (midterm)
- **Where in paper:** §5.2

### F9. Tool-permission is strongest single defense at both layers
- **Claim:** Allowlists on tool args consistently outperform text-based
  defenses in the midterm evaluation.
- **Status:** ✅ CONFIRMED (midterm)
- **Where in paper:** §5.2

---

## 4. New empirical findings from this push

### F10. Legacy simulator structurally cannot evaluate adaptive attacks
- **Claim:** `SimulatedAgent._parse_tool_intent` uses regex to decide which
  tool to invoke. Rephrasing attacks to evade defense regexes also dodges
  the intent parser, so the simulated agent never reaches the target tool.
  Adaptive ASR comes out *lower* than baseline ASR on the simulator — a
  structurally misleading number. This itself is a finding: rule-based
  simulators are unsuited for adaptive-attack evaluation, motivating the
  move to a real LLM in a stateful environment.
- **Status:** ✅ CONFIRMED
  - Ran `python -m experiments.run_all --trials 20 --adaptive`
  - Direct: baseline ASR 75% → adaptive 25% (gap **-50pp**)
  - Indirect: baseline 53.8% → adaptive 11.2% (gap **-42.5pp**)
  - Tool_permission stays flat as expected (+0pp and +2.5pp), confirming
    it's the regex-parsing layer being dodged, not the attack succeeding.
- **Where in paper:** §5.3 "Why we moved to AgentDojo" paragraph
- **Numbers to cite in slides:** the -50pp and -42.5pp deltas, plus the
  tool_permission ≈0pp contrast

### F11. Feasibility of open-weight model (Qwen2.5 7B) on AgentDojo
- **Claim:** On local Ollama, Qwen2.5 7B passes 3/3 read-only banking
  tasks with no defenses. Sufficient baseline TSR to measure defense
  effects. Contrast with AgentDojo's published Llama 3 70B utility
  of 34% — Qwen 7B at this price point is adequate for defense
  evaluation.
- **Status:** ✅ CONFIRMED
  - `python -m agentdojo_integration.feasibility_check`
  - user_task_1: PASS (187.0s)
  - user_task_7: PASS (25.0s)
  - user_task_8: PASS (113.7s)
- **Where in paper:** §5.4 setup paragraph

### F12. Per-defense adaptivity gap on real LLM in stateful env
- **Claim:** [Expected shape, pending confirmation]:
  - `prompt_detection` gap large (>30pp) — regex is the most fragile layer
  - `prompt_isolation` + `provenance` gap moderate (10–25pp) — text markers help partially
  - `tool_permission` gap small (<10pp) — executes at arg layer, less fragile to text rephrasing
  - `all_combined` gap between the above — layered defenses partially compensate
- **Status:** ⏳ PENDING-SWEEP
- **Source when ready:** `agentdojo_integration/results_agentdojo.md`
- **Where in paper:** §5.3 headline table
- **Slide placement:** Slide 10–11 (the punchline)

### F13. TSR × ASR Pareto under each defense
- **Claim:** [Expected shape, pending confirmation]:
  - No-defense: high TSR, high ASR
  - prompt_isolation / provenance: moderate TSR drop, moderate ASR drop
  - tool_permission: minimal TSR drop, significant ASR drop
  - prompt_detection: may drop TSR noticeably (false positives)
  - all_combined: lowest ASR, but TSR hit worst
- **Status:** ⏳ PENDING-SWEEP
- **Where in paper:** §5.4 joint table
- **Slide placement:** Slide 12

### F14. Attacker-aware rephrasing doesn't hurt task utility
- **Claim:** [Expected]: adaptive attacks don't reduce TSR below the
  baseline-attack TSR meaningfully, because the legitimate user task
  doesn't depend on the injection being obvious. If confirmed, this
  strengthens the case that evaluations under-report attacker effectiveness:
  the attacker pays no task-utility cost for being smart.
- **Status:** ⏳ PENDING-SWEEP
- **Where in paper:** One paragraph in §5.3 or §5.4
- **Slide placement:** Slide 12 or sidebar

---

## 5. Honest limitations to acknowledge

### L1. Single suite, single model
- Banking only (4 domains in AgentDojo), Qwen2.5 7B only. Cross-suite and
  cross-model sweep is future work.

### L2. 2 trials per cell
- Bootstrap CIs are reported, but variance is still real. Larger trial
  counts are future work.

### L3. Simulated indirect retrieval
- Our "indirect" attacks are injections handed to the pipeline, not
  content retrieved from a real external source. AgentDojo's injections
  are planted in environment fields that the agent reads via its tools,
  which is more realistic than the midterm's harness-injected strings,
  but still not end-to-end web retrieval.

### L4. No optimization-based attacks (GCG)
- Paper-deep vulnerability surface left as future work.

### L5. No multi-turn decomposition
- Li et al. 2025 reports +16% ASR for multi-turn; we do not measure this.

### L6. No hybrid defense proposed
- FINAL_PROJECT_PLAN.md envisioned a novel hybrid (taint + LLM detector +
  spotlighting + HITL). Scope-cut for 3-day execution. Future work.

### L7. Potential confound: adaptive attack phrasings may be suboptimal
- Our adaptive attacks are hand-crafted. An automated attack-generation
  pipeline (e.g., LLM-guided rewriting) would give a tighter upper
  bound on attacker capability. Future work.

---

## 6. Claims to AVOID

These are things our numbers cannot support:

- ❌ "Our defenses are state-of-the-art" — they are not; MELON (ICML'25)
  gets >99% prevention on AgentDojo.
- ❌ "We propose a new defense architecture" — we don't; we propose a new
  *measurement*.
- ❌ "Our adaptive attacks are optimally strong" — they're hand-crafted
  and targeted at specific defense families; stronger attacks exist.
- ❌ Specific ASR/TSR numbers should not be reported without the CIs.

---

## 7. Data provenance cheat-sheet for slides

| Finding | Exact source file |
|---|---|
| F7–F9 | `experiments/results.md` (midterm) |
| F10 | stdout of `python -m experiments.run_all --trials 20 --adaptive` (can re-run anytime) |
| F11 | stdout of `python -m agentdojo_integration.feasibility_check` (re-runnable) |
| F12–F14 | `agentdojo_integration/results_agentdojo.md` (pending sweep) |
| Adaptive attack text | `agentdojo_integration/attacks_adaptive_agentdojo.py` (the template strings) |
