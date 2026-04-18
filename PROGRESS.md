# Progress and Handoff

This is the working state for the final-phase push of the prompt-injection defense
project. Use this doc to resume on a different machine. Last updated 2026-04-17.

---

## Quick orientation: what changed since the midterm

The midterm shipped: rule-based simulator + Llama 3.2 3B via Ollama, 4 direct + 4
indirect hardcoded attacks, 4 defenses, four metrics. See `Midterm_report.pdf`.

What we added in this push (in priority order):

1. **AgentDojo integration** — moved from text-only simulation to AgentDojo's
   stateful `banking` suite where the agent actually mutates a simulated
   environment and ground-truth checks are computable.
2. **TSR (Task Success Rate)** as a first-class metric alongside ASR. Reports
   are TSR × ASR per cell, not ASR alone.
3. **Adaptive attacks** — two new attack templates (`reworded_important_instructions`,
   `blended_task_context`) registered with AgentDojo's attack registry, plus
   `experiments/attacks_adaptive.py` for the legacy pipeline.
4. **Bootstrap CIs** — `bootstrap_ci()` in `metrics.py` so 2-trial sweeps still
   produce defensible numbers.
5. **Ground-truth TMR** — `compute_ground_truth_tmr()` fixes the regex-based
   TMR's circularity under adaptive attacks.
6. **Adaptivity gap** — `compute_adaptivity_gap()`. The new metric we report.

We **did not** ship the hybrid defense planned in `FINAL_PROJECT_PLAN.md` §6.3,
nanoGCG, or multi-turn attacks. Those remain future work.

---

## Decisions and rationale

| Decision | Rationale |
|---|---|
| ASR primary, TSR added; TMR/SDLR/TUD demoted to legacy-only | Per consensus, the AgentDojo experiment reports the joint ASR×TSR view because that's the security-utility tradeoff that actually matters in deployed agents. |
| AgentDojo banking suite (not slack/travel/workspace) | Clearest ground-truth checks (transfers either happened or didn't), small tool surface, 16 user_tasks and 9 injection_tasks gives room. |
| Qwen2.5 7B via Ollama, not Llama 3.2 3B | Feasibility check (3 read-only banking tasks) passed 3/3 on Qwen2.5 7B; the 3B Llama is too weak for AgentDojo's tool-calling protocol. |
| Ollama via OpenAI-compatible endpoint, no custom wrapper | Ollama serves `/v1/chat/completions` natively. AgentDojo's `OpenAILLM` accepts a pre-configured `openai.OpenAI` client, so we just point `base_url` at `localhost:11434/v1`. ~3 lines instead of ~80. |
| 4 existing defenses ported, no new defenses | 3-day budget. The novel contribution shifted from "propose a hybrid defense" to "propose adaptivity gap as a measurement methodology." |
| Adaptive attacks = baseline rephrased per evasion strategy | Three strategies: `reword` (avoid regex patterns), `blend` (sound like task context), `obfuscate` (rewrite args to slip past allowlist). One adaptive variant per evasion x defense family. |
| Sweep size: 6 defenses × 3 attacks × 3 user_tasks × 2 injection_tasks × 2 trials = 216 cells | Fits in ~4 hours overnight on Qwen2.5 7B; bootstrap CIs make 2 trials defensible. |

---

## Repo layout (as of this branch)

```
agent_security_project/
├── experiments/                      # legacy text-simulation pipeline (midterm)
│   ├── agent_env.py                  unchanged — simulated tools, canary tokens
│   ├── attacks.py                    unchanged — 8 baseline hardcoded attacks
│   ├── attacks_adaptive.py           NEW — adaptive variants of the 8 baselines
│   ├── defenses.py                   unchanged — 4 defenses (regex, allowlist, etc.)
│   ├── simulated_agent.py            unchanged — rule-based agent (limited; see gotchas)
│   ├── llm_agent.py                  unchanged — Llama 3.2 3B via Ollama
│   ├── metrics.py                    MODIFIED — added compute_tsr, compute_adaptivity_gap,
│   │                                 bootstrap_ci, compute_ground_truth_tmr
│   ├── run_all.py                    MODIFIED — added --adaptive flag + gap tables
│   └── results.md                    midterm results table (kept for reference)
│
├── agentdojo_integration/            NEW — everything AgentDojo-related
│   ├── __init__.py
│   ├── feasibility_check.py          GO/NO-GO gate — runs 3 read-only banking tasks
│   ├── defenses_agentdojo.py         the 4 defenses ported to BasePipelineElement
│   ├── attacks_adaptive_agentdojo.py 2 adaptive attack templates registered with AgentDojo
│   └── run_agentdojo.py              main driver — sweeps and emits results_agentdojo.{jsonl,md}
│
├── paper/                            existing — gitignored content (LaTeX assets, refs)
│
├── ATTACKS.md                        plain-English attack guide (baseline + adaptive)
├── FINAL_PROJECT_PLAN.md             aspirational 4-week plan (we shipped a 3-day subset)
├── PROGRESS.md                       THIS FILE — handoff state
├── CLAUDE.md                         Claude Code repo guidance
├── README.md                         user-facing setup + run instructions (slightly stale)
├── requirements.txt                  pinned deps for reproduction
├── Midterm_report.pdf                reference — what shipped at midterm
├── experiment_llm.tex                paper drafts (LaTeX, root level for now)
├── experiment_rule-based.tex
└── experiments.tex
```

---

## Where we left off (resume point)

**Status: code complete, sweep not yet run.**

Last verified working:
- All imports clean, all pipelines (6 defense configs) construct without error
- Feasibility check passed 3/3 on Qwen2.5 7B
- Legacy pipeline `--adaptive` smoke-tested at 20 trials (the resulting gap is
  expected to be misleading; see "known issues")

**Next action**: run the smoke test for the AgentDojo driver, then the full sweep.

---

## Resuming on another device

### 1. Clone and check out the branch
```bash
git clone <repo-url> agent_security_project
cd agent_security_project
git checkout adaptive-eval-agentdojo
```

### 2. Python env
Project was developed against Python 3.10. Use the same or newer.
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

This installs `agentdojo[transformers]>=0.1.35` (which pulls in `torch`,
`transformers`), `openai`, `langchain-core`, `requests`. Heavy install (~2 GB
disk including torch).

### 3. Ollama
```bash
# install ollama from https://ollama.com if not already
ollama serve &                      # if not already running on port 11434
ollama pull qwen2.5:7b-instruct     # ~4.7 GB download
```

### 4. Verify everything still works
```bash
# 30-second import check
python -c "
import agentdojo_integration.attacks_adaptive_agentdojo
from agentdojo_integration.defenses_agentdojo import build_defense_elements
from agentdojo_integration.run_agentdojo import build_pipeline, DEFENSE_CONFIGS
for name, defenses in DEFENSE_CONFIGS.items():
    p = build_pipeline('qwen2.5:7b-instruct', defenses)
print('all OK')
"

# 5-min feasibility check
python -m agentdojo_integration.feasibility_check
```

If feasibility passes (≥2/3), proceed.

---

## Next actions, in order

### Step 1 — AgentDojo smoke test (~2-5 min)
Confirm the driver runs end-to-end with one cell before committing to the full sweep:

```bash
python -m agentdojo_integration.run_agentdojo \
    --defenses none \
    --attacks important_instructions \
    --user-tasks user_task_7 \
    --injection-tasks injection_task_5 \
    --trials 1 \
    --out-json agentdojo_integration/smoke.jsonl \
    --out-md agentdojo_integration/smoke.md
```

Expected: prints "Sweep done", writes `smoke.jsonl` (one row) and `smoke.md`.

### Step 2 — Full overnight sweep (~4-6 hours)
Close browser/editor first to free RAM. Then:

```bash
python -m agentdojo_integration.run_agentdojo --trials 2 \
    2>&1 | tee agentdojo_integration/sweep.log
```

Defaults to: 6 defenses × 3 attacks × 3 user_tasks × 2 injection_tasks × 2 trials = **216 cells**.

The driver appends to `results_agentdojo.jsonl` after every trial, so a Ctrl-C
or crash mid-sweep doesn't lose data — partial JSONL can be re-aggregated.

### Step 3 — Aggregate and write the paper
After the sweep, the markdown is already at `agentdojo_integration/results_agentdojo.md`.

Paper edits needed in `experiments.tex`:
- Add §5.3 *Adaptive Attacks and the Adaptivity Gap*: present the gap table
  per-defense, interpret the asymmetry (tool_permission gap small, regex
  detection gap large).
- Add §5.4 *Realistic-Environment Validation (AgentDojo)*: present TSR × ASR
  joint table, contrast with the midterm's text-simulation numbers.
- Update §6 *Limitations*: simulated indirect retrieval, single suite, single
  model, 2 trials/cell, no GCG/multi-turn/hybrid.
- Update §7 *Future Work*: shrink to what's actually still open.

Per-task breakdown is available from `results_agentdojo.jsonl` if needed —
each line is one trial with `(defense, attack, user_task, injection_task, trial,
utility, security)`. The current markdown aggregates across user_tasks; if you
want per-task rows, extend `write_markdown()` in `run_agentdojo.py`.

### Step 4 — Optional polish
- Update `README.md` to document `agentdojo_integration/` and the new commands.
- Add a `--per-task` flag to `run_agentdojo.py` for per-`(user_task, injection_task)`
  markdown rows (~20 lines).
- Add AgentDojo's built-in `transformers_pi_detector` as a 7th defense config
  for an external comparison row in the table.

---

## Known issues and gotchas

### 1. Legacy `--adaptive` results are structurally weird
On the simulated pipeline, adaptive ASR comes out *lower* than baseline ASR.
Why: `SimulatedAgent._parse_tool_intent` uses regex to decide which tool the
agent will call. When we rephrased attacks to evade *defense* regexes, we also
dodged the *intent parser's* regexes — so the simulated agent never even
triggers the target tool. **The legacy pipeline structurally cannot evaluate
adaptive attacks.** This is itself a defensible finding in the paper:
"rule-based agent simulators are unsuited for adaptive-attack evaluation,
motivating the move to a real LLM in a stateful environment." Don't try to
fix the simulator — frame it instead.

### 2. AgentDojo circular import on direct module import
Don't `from agentdojo.default_suites.v1.banking import banking_task_suite`
directly — circular import in 0.1.35. Use the loader:
```python
from agentdojo.task_suite.load_suites import get_suite
suite = get_suite("v1.2.2", "banking")
```

### 3. Ollama lag during sweep
Qwen2.5 7B uses ~5-6 GB RAM during inference; on a 16 GB Mac with browser +
editor open, the laptop becomes nearly unusable. Run overnight with apps closed.
Don't use the laptop for anything else during the sweep.

### 4. Token-format quirks
Some Ollama models emit tool calls in slightly off-spec formats. The
`feasibility_check.py` was the GO/NO-GO gate for this — Qwen2.5 7B passed.
If you swap models later, re-run feasibility before assuming results are valid.

### 5. AgentDojo "not injectable" errors
Not every (user_task, injection_task) pair is reachable — AgentDojo flags
non-injectable pairs with `ValueError`. The default sweep uses
`(user_task_1, user_task_3, user_task_7) × (injection_task_1, injection_task_5)`
which were chosen because they're known-injectable. If you swap task IDs, expect
to see some "ValueError: not injectable" in the log; the driver swallows them
into `error` field, so the sweep continues.

---

## Files that need updating *after* the sweep

These were intentionally left for after the sweep so they reflect real numbers:

- `experiments.tex` — final paper draft, needs new §5.3, §5.4 with the actual tables
- `README.md` — currently only describes the legacy pipeline; add AgentDojo flow
- `experiments/results.md` — append a section pointing to the new AgentDojo table
- `agentdojo_integration/results_agentdojo.md` — auto-generated by the driver

---

## What the paper will claim (based on planned analysis)

Concrete contributions, scoped strictly to prompt injection:

1. **Adaptivity gap** as a reporting metric. Defenses claiming 5-25% ASR
   under hand-crafted attacks should also report ASR under attacker-aware
   rephrasing.
2. **Per-defense gap measurement** showing surface-level text defenses
   (isolation, provenance, regex detection) collapse under adaptive attacks
   while execution-layer defenses (tool_permission) remain stable.
3. **Realistic-environment validation** in AgentDojo's stateful banking suite,
   with TSR × ASR jointly reported.
4. **Ground-truth TMR** — small methodology fix showing standard TMR
   undercounts under adaptive attacks.
5. **Negative finding on rule-based simulators** — they cannot model
   adaptive-attack evaluation because their intent parsers share the same
   regex fragility as the defenses being tested.

Honest limitations to flag in the paper: single suite, single model,
2 trials/cell, simulated indirect retrieval (not real external content),
no GCG/multi-turn/hybrid defense.

---

## References on disk

- `Midterm_report.pdf` — what shipped at the midterm
- `FINAL_PROJECT_PLAN.md` — the full 4-week aspirational plan (we executed a 3-day subset)
- `ATTACKS.md` — plain-English attack guide for non-coders
- `paper/` — gitignored. Original LaTeX assets if needed locally.
