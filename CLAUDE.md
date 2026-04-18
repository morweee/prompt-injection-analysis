# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project purpose

Research project studying prompt injection in tool-using LLM agents. Tests direct and indirect injection attacks against two agent implementations (rule-based simulator, local LLM via Ollama) and evaluates four defenses.

## Commands

Install deps:
```bash
pip install langchain-core requests
```

Run simulation experiments (fast, default 50 trials):
```bash
python -m experiments.run_all
python -m experiments.run_all --trials 100 --vulnerability 0.5 --seed 7
```

Run LLM experiments (slow; requires `ollama serve` and `ollama pull llama3.2:3b`, default 5 trials):
```bash
python -m experiments.llm_agent
python -m experiments.llm_agent --model mistral --trials 10
```

Standalone toy demo (no deps):
```bash
python toy_tool_description.py
```

There is no test suite, linter, or build step. Modules **must** be run with `python -m experiments.<name>` because imports are package-qualified (`from experiments.foo import …`).

## Architecture

The repo now has **two parallel evaluation tracks**:

1. **Legacy track** (`experiments/`) — text-only simulation, kept from the midterm. Two agents (rule-based + Llama 3.2 3B), 8 hardcoded attacks, 4 defenses, four metrics. Run via `python -m experiments.run_all` (sim) or `python -m experiments.llm_agent` (LLM). Use `--adaptive` flag with `run_all` to also run the new adaptive attacks and print adaptivity-gap tables.

2. **AgentDojo track** (`agentdojo_integration/`) — stateful banking environment, real LLM (Qwen2.5 7B via Ollama), TSR × ASR joint reporting, two new adaptive attack templates registered with AgentDojo. Run via `python -m agentdojo_integration.run_agentdojo`. Always run `python -m agentdojo_integration.feasibility_check` first when changing the model — it's the GO/NO-GO gate.

The legacy track is preserved for the midterm comparison and is no longer the primary evaluation surface; the AgentDojo track is what the final paper's headline numbers come from. **Don't try to evaluate adaptive attacks on the legacy `SimulatedAgent`** — its `_parse_tool_intent` regex shares fragility with the regex defenses, so adaptive attacks dodge intent parsing as a side-effect and produce structurally misleading numbers (this is itself documented as a finding in `PROGRESS.md`).

### Legacy track shared scaffolding

The two legacy agents (`experiments/simulated_agent.py`, `experiments/llm_agent.py`) deliberately share the same surrounding scaffolding so results are comparable:

- `experiments/agent_env.py` — the shared simulated world: four LangChain `@tool`s (`search_web`, `read_database`, `send_email`, `run_code`), a `TOOL_MAP` both agents dispatch through, and `CANARY_TOKENS` (SSN, API key, password) seeded into `read_database` records. Adding or renaming a tool requires updates in both agents' intent parsers/prompts.
- `experiments/attacks.py` — `DIRECT_ATTACKS` and `INDIRECT_ATTACKS` dicts. Each entry bundles the attack payload **with** a success predicate (`target_arg_check` / `hijack_check`) used by the runner to compute ASR. Attack and detection logic are intentionally coupled to these payloads.
- `experiments/defenses.py` — four independent defenses (prompt isolation, provenance marking, tool permission allowlist with regex arg filters, regex-based injection detection). Runners combine them via `DEFENSE_CONFIGS`; the `"all_combined"` key stacks all four.
- `experiments/metrics.py` — `compute_asr`, `compute_tmr`, `compute_sdlr`, `compute_task_utility`. Utility degradation is computed relative to the `"none"` defense baseline, so the runners always execute `"none"` first and pass its traces back in.
- `experiments/run_all.py` / `experiments/llm_agent.py` — sweep the cartesian product of (attacks × defense configs × trials), print a results table per experiment.

Key behavioral contract of the simulator: `SimulatedAgent.vulnerability` (0–1) is the probability the agent follows an injected instruction. Each detection flag subtracts 0.25 from the effective value; `prompt_isolation` multiplies it by 0.5; `provenance` by 0.65. This is a model of LLM behavior, not a reproduction — keep that in mind when interpreting results.

LLM agent specifics: talks to Ollama at `http://localhost:11434/api/generate`, uses a JSON tool-call protocol defined in `SYSTEM_PROMPT`, and parses responses with regex (`parse_tool_call`). Temperature is 0.3, so runs are not deterministic.

## AgentDojo track scaffolding

`agentdojo_integration/` is a thin layer on top of `agentdojo[transformers]>=0.1.35` (installed via `requirements.txt`). The integration pattern is "subclass, don't fork":

- **Defenses** in `defenses_agentdojo.py` subclass `BasePipelineElement` and transform the `messages` list. Three of the four (isolation, provenance, prompt_detection) operate at the tool-output boundary; `ToolPermissionDefense` subclasses `ToolsExecutor` to gate calls before execution.
- **Adaptive attacks** in `attacks_adaptive_agentdojo.py` subclass `FixedJailbreakAttack` and use `@register_attack` so AgentDojo's registry can find them by name (`reworded_important_instructions`, `blended_task_context`).
- **Driver** (`run_agentdojo.py`) loads the banking suite via `get_suite("v1.2.2", "banking")` (do **not** import the suite module directly — circular import in 0.1.35), builds a fresh `AgentPipeline` per defense config, and sweeps `(defense × attack × user_task × injection_task × trial)`. Results stream to JSONL after every cell so partial sweeps are recoverable.
- **Ollama LLM**: AgentDojo's `OpenAILLM` accepts a pre-configured `openai.OpenAI` client; we point its `base_url` at `http://localhost:11434/v1` (Ollama's OpenAI-compatible endpoint). No custom `BasePipelineElement` wrapper needed.

Hand-off and resume state for the AgentDojo work lives in `PROGRESS.md`. The full 4-week aspirational plan that we executed a 3-day subset of is in `FINAL_PROJECT_PLAN.md`. Plain-English attack guide: `ATTACKS.md`.

## Repo layout notes

- `experiments/results.md` — saved sample outputs from legacy runners.
- `agentdojo_integration/results_agentdojo.{jsonl,md}` — generated by the AgentDojo driver; gitignored.
- `experiment_*.tex`, `experiments.tex`, `paper/` — write-up materials, not code. The `paper/` directory is gitignored (see `.gitignore`).
- `toy_tool_description.py` — self-contained demo of tool-description injection; unrelated to either evaluation track.
