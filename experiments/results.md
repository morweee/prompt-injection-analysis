# Experiment Results

## Rule-Based Simulation (50 trials, vulnerability=0.7, seed=42)

### Experiment 1: Direct Prompt Injection

| Defense            |    ASR |   TMR |   SDLR | Util.Deg |
|--------------------|--------|-------|--------|----------|
| None               | 75.0%  | 0.0%  |  5.0%  |   0.0%   |
| Prompt isolation   | 75.0%  | 0.0%  |  0.0%  |   0.0%   |
| Provenance         | 75.0%  | 0.0%  |  0.0%  |   0.0%   |
| Tool permission    | 25.0%  | 0.0%  |  0.0%  |   0.0%   |
| Prompt detection   | 34.0%  | 0.0%  |  0.0%  |   0.0%   |
| All combined       | 25.0%  | 0.0%  |  0.0%  |   0.0%   |

### Experiment 2: Indirect Prompt Injection

| Defense            |    ASR |    TMR |   SDLR | Util.Deg |
|--------------------|--------|--------|--------|----------|
| None               | 48.5%  | 25.0%  | 25.0%  |   0.0%   |
| Prompt isolation   | 27.5%  | 24.2%  |  0.0%  |   0.0%   |
| Provenance         | 33.0%  | 17.1%  | 15.0%  |   0.0%   |
| Tool permission    | 17.5%  | 25.0%  | 25.0%  |   0.0%   |
| Prompt detection   | 17.5%  | 18.2%  |  5.0%  |   0.0%   |
| All combined       |  5.0%  | 26.5%  |  0.0%  |   0.0%   |

---

## LLM-Based Experiment — Llama 3.2 (3B) via Ollama (5 trials, seed=42)

### Experiment 1: Direct Prompt Injection

| Defense            |    ASR |   TMR |   SDLR | Util.Deg |
|--------------------|--------|-------|--------|----------|
| None               | 30.0%  | 0.0%  |  5.0%  |   0.0%   |
| Prompt isolation   | 25.0%  | 0.0%  |  0.0%  |   0.0%   |
| Provenance         | 25.0%  | 0.0%  |  0.0%  |   0.0%   |
| Tool permission    | 25.0%  | 0.0%  |  0.0%  |   0.0%   |
| Prompt detection   | 25.0%  | 0.0%  |  0.0%  |   0.0%   |
| All combined       | 25.0%  | 0.0%  |  0.0%  |   0.0%   |

### Experiment 2: Indirect Prompt Injection

| Defense            |    ASR |    TMR |   SDLR | Util.Deg |
|--------------------|--------|--------|--------|----------|
| None               | 75.0%  | 25.0%  | 25.0%  |   0.0%   |
| Prompt isolation   | 65.0%  | 24.2%  |  0.0%  |   0.0%   |
| Provenance         | 55.0%  | 17.1%  | 15.0%  |   0.0%   |
| Tool permission    | 25.0%  | 25.0%  | 25.0%  |   0.0%   |
| Prompt detection   | 55.0%  | 18.2%  |  5.0%  |   0.0%   |
| All combined       | 25.0%  | 26.5%  |  0.0%  |   0.0%   |

---

## Key Takeaways

- **Direct injection** is much harder against real models (30% vs 75% in simulation) due to RLHF safety training.
- **Indirect injection** is more dangerous against real models (75% vs 48.5%) — LLMs trust their own tool outputs.
- **Tool permission controls** are the strongest single defense in both settings.
- **Layered defenses** achieve the best overall protection (5% ASR in simulation, 25% in LLM).
