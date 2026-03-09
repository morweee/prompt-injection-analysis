# Prompt Injection Analysis

Research project investigating prompt injection attack vulnerabilities in LLM agents. We test direct and indirect injection attacks against both a rule-based simulated agent and a real local LLM (Llama 3.2 via Ollama), and evaluate four defensive strategies.

## Code Overview

- `experiments/` — main experiment code (attacks, defenses, metrics, agents)
- `experiments/run_all.py` — runs the rule-based simulation experiments
- `experiments/llm_agent.py` — runs the same experiments but with a real LLM
- `experiments/results.md` — saved experiment results so you don't have to re-run everything
- `toy_tool_description.py` — standalone toy example for tool-description injection

## Setup

Require Python 3.10+ and a few langchain packages.

```bash
pip install langchain-core requests
```

### For the LLM experiments (optional)

Require Ollama installed locally to run the LLM-based experiments. Download available from https://ollama.com

Then pull the model used in the experiment:

```bash
ollama pull llama3.2:3b
```

Make sure the Ollama server is running before starting:

```bash
ollama serve
```

## Running experiments

### Rule-based simulation

```bash
python -m experiments.run_all
```

This runs 50 trials by default.

### LLM-based experiments

```bash
python -m experiments.llm_agent
```

It is slower since it's doing actual inference. Defaults to 5 trials.

### Toy example

```bash
python toy_tool_description.py
```

A quick and simple standalone demo, no dependencies needed.

## Notes

- Experiements results are in `experiments/results.md`
- The simulation uses a configurable vulnerability parameter (default 0.7) that controls how likely the agent is to follow injected instructions. It's not meant to be a perfect model of real LLM behavior, just a fast way to test defense logic.
- LLM results will vary between runs since model output isn't fully deterministic even at low temperature.
