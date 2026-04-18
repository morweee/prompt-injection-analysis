# Final-Phase Project Plan

**Project:** Investigating Prompt Injection Vulnerabilities and Defensive Strategies in Tool-Using Agentic Systems
**Team:** Zongchi Xie, Mu-Wei Hsieh, Hao Deng
**Written:** April 17, 2026 (post-midterm, pre-final)

---

## 1. Where we are, in one paragraph

At the midterm we shipped a controlled testbed: a rule-based `SimulatedAgent` (for fast iteration, tunable vulnerability) and a real `LLMAgent` using Llama 3.2 3B via Ollama, against which we measured 4 direct and 4 indirect hand-crafted injection attacks under 4 defenses (prompt isolation, provenance marking, tool permission, regex detection) plus the "all combined" stack. We report ASR / TMR / SDLR / TUD for every cell, and a toy tool-description-injection demo. The headline findings: (a) simulation overestimates direct ASR because it doesn't model RLHF refusal; (b) real LLMs are *more* vulnerable to indirect injection than simulation predicts because they trust their own tool outputs; (c) tool-permission control is the single strongest defense; (d) no single defense is sufficient. The paper's own `future_work.tex` is blunt about the remaining gaps — which is exactly the roadmap for the final.

## 2. What "more complete for the final" means

A graduate-level security paper at the final needs three things the midterm lacks:

1. **Stronger attacks.** Hand-crafted strings overstate how robust our defenses look. Even one optimization-based or multi-turn result would move the paper from "defense comparison" to "stress-tested defense comparison."
2. **A defensive contribution of our own.** Benchmarking existing defenses is a solid midterm; the final should propose and evaluate *one* novel (or novel-ish) defense that addresses a weakness we identified. The hybrid architecture in §6.3 of the midterm is the obvious candidate.
3. **External-benchmark validation.** Comparing numbers against AgentDojo — a standardized prompt-injection benchmark — makes our claims comparable to the rest of the literature.

Everything below is organized around delivering those three pillars without blowing the timeline.

---

## 3. Phased work plan (≈4 weeks)

The plan assumes the final is ~4 weeks out. Each phase ends with a concrete, checkable deliverable so we can slip individual tasks without losing the whole milestone.

### Phase 1 — Attack suite expansion (Week 1)

**Goal:** Replace static hand-crafted prompts as the *only* attacks with a richer and stronger attack suite, so defense robustness is not measured against a straw man.

Three attack additions, in priority order:

**1.1 Optimization-based attack (nanoGCG)**
- Library: `nanogcg` from Gray Swan AI (pip-installable, PyTorch, supports HuggingFace causal LMs). Works on Llama 3.2 3B on a single GPU; CPU-only will be slow but feasible for a handful of suffixes.
- Pick 2 of our existing attacks (say `override_system` and `data_exfil_via_email`) and optimize an adversarial suffix against Llama 3.2 3B's chat template. Report ASR with and without the GCG suffix.
- Budget: one afternoon of compute for a demonstrative result. We do **not** need to reproduce Zou et al.'s numbers — we need one plot showing that hand-crafted ASR underestimates worst-case ASR.
- Code: new file `experiments/attacks_gcg.py` that (a) loads Llama 3.2 via transformers, (b) calls `nanogcg.run`, (c) emits a list of `(base_prompt, suffix)` tuples that can be fed back into the existing `LLMAgent` pipeline.

**1.2 Multi-turn decomposition attack**
- Motivated by Li et al. (cited in §3.2.2 of midterm: +16% ASR when harmful tasks decomposed across turns). Our current pipeline is single-turn.
- Pick 2 scenarios, decompose each into 3 benign-looking turns that cumulatively reach the harmful goal. Example: turn 1 asks agent to look up PROJ-10; turn 2 asks it to summarize; turn 3 uses the established rapport to ask it to "also forward to the audit team."
- Code change: extend `LLMAgent` with `run_multi_turn_attack(turns: list[str])` that preserves conversation history between `query_ollama` calls.

**1.3 Encoding/obfuscation attacks**
- Three variants that trivially evade our regex detector, demonstrating the detector's brittleness:
  - Base64-encoded payload with a "decode and follow" prefix.
  - Unicode homoglyph substitution (e.g. `ignore` → Cyrillic `іgnore`).
  - Token-splitting with zero-width joiners.
- Adds `experiments/attacks_obfuscated.py`. Each is a drop-in replacement for the existing `INDIRECT_ATTACKS` entries, so we can re-run the same experiment matrix.

**Deliverable at end of Phase 1:** a 4th results table — `results_stronger_attacks.md` — showing our 4 baseline defenses (no changes) against this stronger suite. Expectation (and this is fine): our current defenses look worse, especially regex detection. That's the *motivation* for Phase 2.

### Phase 2 — Hybrid defense implementation (Weeks 2)

**Goal:** Ship the hybrid architecture the midterm's §6.3 already promises, and show it beats the existing "all_combined" configuration against the stronger attacks from Phase 1.

The hybrid has four components; we implement each as a new module under `experiments/defenses_hybrid/` and compose them in a new `HybridAgent` (or as an additional entry in `DEFENSE_CONFIGS`):

**2.1 Taint tracker (`taint.py`)**
- Wrap `AgentAction.observation` in a `TaintedString` class that tracks an `is_untrusted: bool` flag.
- Hook into `_execute_tool`: every tool output is tainted.
- Hook into `_check_permission`: if an argument to a security-sensitive tool (`send_email` recipient, `run_code` body, outbound URLs in `search_web`) originates from (or contains a substring of) tainted data, block-and-prompt instead of block-outright. Keep a small list of "sensitive sinks" per tool.
- This is *not* full CaMeL — no custom interpreter, no dependency graph. It's the 80% solution described in §6.3.

**2.2 LLM-based injection detector (`llm_detector.py`)**
- Use `protectai/deberta-v3-base-prompt-injection-v2` (86M params, CPU-runnable) or Meta's `Llama-Prompt-Guard-2-86M`.
- `detect(text) → (label, confidence)` where `label ∈ {benign, injection, jailbreak}`.
- Replaces the 11-regex detector at the tool-output boundary. Keep the regex detector available as a baseline so we can A/B in results.
- Model downloads once on first run; cache to disk.

**2.3 Spotlighting-style datamarking (`spotlighting.py`)**
- Implement Microsoft's datamarking mode (cited above): insert a randomized marker token every few words of untrusted tool output, and instruct the agent in the system prompt that instructions within marked text must be ignored.
- This is cheap, needs no fine-tuning, and has reported near-0% ASR on summarization-style tasks — worth a row in our final table even if it only substitutes for one layer.

**2.4 Human-in-the-loop gate (`hitl.py`)**
- When the taint tracker *or* the detector flags a pending sensitive tool call, emit a `ConfirmationRequired` event with a summary of what's about to happen. For batch evaluation we simulate HITL with an oracle: the oracle approves the call iff the call matches the original task's legitimate goal; it denies otherwise. This gives us an upper bound on what HITL could achieve without an actual human in the loop.
- Report TUD with HITL separately — this matters for the security/utility trade-off discussion.

**Deliverable at end of Phase 2:** `results_hybrid.md` with a new row, `hybrid`, compared against `none`, each individual defense, `all_combined`, **on both the original attack suite and the Phase-1 stronger attack suite**. Target: hybrid ASR noticeably below `all_combined` against stronger attacks, with TUD no worse than the `all_combined` row.

### Phase 3 — Scaling, validation, and external benchmarks (Week 3)

**Goal:** Make the numbers trustworthy and comparable.

**3.1 Bootstrap confidence intervals**
- 5 trials per cell is too few to claim differences. Bump LLM trials to 20–30 per cell; 50 if GPU permits. Add a small bootstrap-resampling helper in `metrics.py` that returns `(mean, 95% CI)` for every rate. Keep the simulation at 50 trials but report the same CI format.
- This is pure plumbing, no new science, but referees notice when there aren't any.

**3.2 Model-size sweep**
- Add Llama 3.1 8B and Qwen2.5 7B as secondary models, behind the same Ollama interface. One or two extra runs per model; report only baseline + hybrid for the sweep. This shows our hybrid works beyond the 3B model and lets us comment on how safety-training strength varies with scale.

**3.3 AgentDojo integration (stretch, ship if Phase 2 lands on time)**
- `pip install "agentdojo[transformers]"`. AgentDojo's `AgentPipeline` and `BasePipelineElement` let us plug in our defenses as pipeline elements. The stated install path is well documented in their README.
- We do **not** try to run the full 629 test cases against every defense — AgentDojo is expensive. Select a minimal-but-defensible subset: one suite per domain (email, banking, travel) × injections-on × our 4 defenses + hybrid. That's enough to produce a single table that says "our hybrid gets X% on AgentDojo email-suite vs. tool_filtering's reported 7.5%."
- If AgentDojo integration slips, descope to reporting our numbers *next to* AgentDojo's published defense numbers as a non-apples-to-apples comparison. Still valuable.

**Deliverable at end of Phase 3:** the final results tables, all with CIs, plus the cross-model sweep and (ideally) an AgentDojo row.

### Phase 4 — Paper, presentation, and reproducibility (Week 4)

**Goal:** Turn everything above into final deliverables.

**4.1 Paper revisions** (`experiments.tex`, `paper/future_work.tex`, new section)
- Add §4: *Stronger Attacks* (Phase 1 results). The current §5 becomes §5 *Baseline Defense Evaluation*.
- Add §6: *Hybrid Defense Architecture* (Phase 2). This is the paper's novel contribution.
- Add §7: *External Validation* (Phase 3, AgentDojo + model sweep).
- Rewrite §6 Future Plan as *Limitations and Future Work* — now that many of its items are done, what remains (e.g. full CaMeL dependency-graph, StruQ fine-tuning, adaptive attack co-evolution).
- Tighten the intro and related-work sections; the midterm version has some grammar slips ("both experiments using a real LLM" → "all experiments"; "Experiements" typo in README).

**4.2 Presentation deck**
- 10–12 slides: motivation (1–2), threat model (1), attack taxonomy (1), defense taxonomy (1), midterm results quick (1), stronger attacks (1), hybrid architecture diagram (1–2), hybrid results (1), AgentDojo / cross-model (1), limitations + takeaways (1).
- One demo video: record `run_all.py` or the LLM agent responding to a poisoned tool output both with and without the hybrid on — concrete, visual, memorable.

**4.3 Reproducibility**
- Pin dependency versions in a `requirements.txt` (currently the README lists only two packages).
- Add a `make all` or `scripts/reproduce.sh` that runs every experiment end-to-end with a fixed seed and writes the tables used in the paper.
- Update `README.md` to document the new attack files, hybrid agent, and AgentDojo integration.

---

## 4. Risk register and fallbacks

| Risk | Likelihood | Mitigation |
|---|---|---|
| nanoGCG too slow on our hardware | Medium | Fall back to AmpleGCG's pre-trained suffixes or use GCG transfer from a larger model. Even a single successful suffix makes the point. |
| AgentDojo integration eats a week | Medium | Ship Phase 2 first. If AgentDojo slips past Week 3, descope to a qualitative comparison against their published numbers. |
| Hybrid isn't meaningfully better than all_combined | Low-medium | It should be, against *stronger* attacks. If not, that's itself a paper-worthy finding — "surface-level layering is already near the ceiling at this model size." Frame honestly. |
| LLM detector adds unacceptable latency | Low | DeBERTa-small-v2 runs in <50ms on CPU. Benchmark this early. |
| Scope creep (team wants to add more attacks) | High | Hold the line: no new attack classes after Phase 1 is closed. Stretch material goes in §8 Future Work. |

---

## 5. Quick wins we should do this week regardless

These are ~1 day of work and pay off immediately:

1. **Add confidence intervals to existing tables.** 5 trials with point estimates is the weakest part of the midterm as it stands.
2. **Fix typos in README.** `Experiements` → `Experiments`, `Ollama` vs `Ollama` consistency, the truncated hanging line in §6 of the midterm PDF (page 8).
3. **Add a `--seed-sweep` flag** to `run_all.py` so we can already start producing multi-seed results while Phase 1 is being built.
4. **Version-pin** `langchain-core`, `requests`, `ollama` in `requirements.txt` so runs stay reproducible as the semester closes out.

---

## 6. What this plan deliberately does *not* include

Worth naming so we don't keep second-guessing:

- **StruQ-style fine-tuning.** Requires training infra and a fine-tuning dataset. Keep as Future Work. Our §6.2 already concedes this.
- **Full CaMeL reproduction.** Google's reference implementation requires a custom Python interpreter and two parallel LLM services. Way out of scope. Our taint tracker is deliberately the 80% solution.
- **Training our own injection classifier.** Off-the-shelf PromptGuard / deberta-v3-prompt-injection are strong enough, and using them is faster and easier to cite.
- **Worming / self-propagation attacks (Greshake).** Genuinely hard to set up in our environment and tangential to the defenses we're evaluating. Mention in Future Work.

---

## 7. One-week-by-week summary

| Week | Focus | Key code | Key artifact |
|---|---|---|---|
| 1 | Stronger attacks | `experiments/attacks_gcg.py`, `attacks_obfuscated.py`, multi-turn pipeline | `results_stronger_attacks.md` |
| 2 | Hybrid defense | `experiments/defenses_hybrid/{taint,llm_detector,spotlighting,hitl}.py` | `results_hybrid.md` |
| 3 | Scaling + validation | `metrics.py` (CIs), model sweep runs, AgentDojo glue | Final results tables with CIs |
| 4 | Paper + deck + repro | `experiments.tex` rewrites, slides, `scripts/reproduce.sh` | Final PDF, deck, reproducible repo |

If any week slips, cut from that week's *scope* rather than push the week — the paper needs to be written while we still have running code.
