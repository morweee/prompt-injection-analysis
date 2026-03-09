# Prompt Injection Analysis

Research project investigating prompt injection vulnerabilities in tool-using LLM agents. We test direct and indirect injection attacks against both a rule-based simulated agent and a real local LLM (Llama 3.2 via Ollama), and evaluate four defensive strategies.

## What's in here

- `experiments/` — main experiment code (attacks, defenses, metrics, agents)
- `experiments/run_all.py` — runs the rule-based simulation experiments
- `experiments/llm_agent.py` — runs the same experiments but with a real LLM
- `experiments/results.md` — saved experiment results so you don't have to re-run everything
- `toy_tool_description.py` — standalone toy example for tool-description injection

## Setup

You'll need Python 3.10+ and a few packages. Nothing crazy.

```bash
pip install langchain-core requests
```

That should be enough for the simulation side of things.

### For the LLM experiments (optional)

If you want to run the LLM-based experiments you need Ollama installed locally. Grab it from https://ollama.com or on Mac:

```bash
brew install ollama
```

Then pull the model we used:

```bash
ollama pull llama3.2:3b
```

Make sure the Ollama server is running before you start:

```bash
ollama serve
```

(If you installed the Mac app it might already be running in the background.)

## Running experiments

### Rule-based simulation

```bash
python -m experiments.run_all
```

This runs 50 trials by default. You can tweak it:

```bash
python -m experiments.run_all --trials 100 --vulnerability 0.8 --seed 123
```

### LLM-based experiments

```bash
python -m experiments.llm_agent
```

This is slower since it's doing actual inference. Defaults to 5 trials. You can change the model if you have others pulled in Ollama:

```bash
python -m experiments.llm_agent --model mistral --trials 3
```

### Toy example

```bash
python toy_tool_description.py
```

Just a quick standalone demo, no dependencies needed beyond the standard library.

## Notes

- The simulation uses a configurable vulnerability parameter (default 0.7) that controls how likely the agent is to follow injected instructions. It's not meant to be a perfect model of real LLM behavior, just a fast way to test defense logic.
- LLM results will vary between runs since model output isn't fully deterministic even at low temperature.
- Pre-recorded results are in `experiments/results.md` if you just want to see the numbers without running anything.
