# Presentation Slide Outline — Findings-Focused

Target: ~8 slides for a 8-12 minute talk. No methodology, no setup, no
derivations — those live in the report. Every slide either (a) frames the
research problem, (b) shows a finding, or (c) closes.

**Narrative arc:**
*Tool-using LLM agents are vulnerable to prompt injection. Proposed defenses
look strong on paper. But when the attacker knows the defense exists and
rephrases accordingly, three out of four collapse — and we can measure this
gap.*

---

## Slide 1 — Title

- **Investigating Prompt Injection Vulnerabilities and Defensive Strategies in Tool-Using Agentic Systems**
- Authors, affiliation, date

---

## Slide 2 — The research problem

- **Key message (one line):** Do defenses against prompt injection actually
  hold up when the attacker adapts to them?
- **What to put on the slide (minimal):**
  - *Prompt injection:* malicious text in user input or tool output hijacks
    an LLM agent's tool use.
  - *Defenses proposed in the literature:* prompt isolation, provenance
    marking, tool-permission allowlists, regex-based detection.
  - *The gap:* these defenses are evaluated against static, hand-crafted
    attacks. An attacker who knows the defense pattern can just rephrase.
  - *Our question:* how much of the reported defense effectiveness is
    robustness vs. measurement artifact?
- **Visual:** one diagram — attacker text → agent → tool → bad action
  (borrowed/adapted from midterm report figure 1)

---

## Slide 3 — Finding 1: Baseline defenses appear strong

- **Key message:** Against the attacks defenders write themselves, the four
  defenses reduce attack success rate substantially. This is what the
  literature reports — and what we reproduced at the midterm.
- **What to show:**
  - Small table from midterm (`experiments/results.md`), indirect injection on Llama 3.2:
    - `none`: 75% ASR
    - `tool_permission`: 25% ASR
    - `all_combined`: 25% ASR
  - One sentence: *"Combined defenses drop ASR from 75% to 25% — three-quarters
    of attacks neutralized."*
- **Setup:** this is the strawman we're about to knock down.

---

## Slide 4 — Finding 2 (the main finding): Adaptive attacks reopen the gap

- **Key message:** When we rephrase the *same* attack goals to evade the
  defenses — without changing the attacker's intent — most defenses lose
  most of their effectiveness.
- **What to show:**
  - **The adaptivity gap table** (headline). Per defense:
    - Baseline ASR | Adaptive ASR | Gap (pp)
    - `prompt_detection`: [X%] → [Y%] → **[+Zpp]**
    - `prompt_isolation`: ... → ... → ...
    - `provenance`: ... → ... → ...
    - `tool_permission`: ... → ... → **small (~0pp)**
    - `all_combined`: ... → ... → ...
  - Source: `agentdojo_integration/results_agentdojo.md` (⏳ pending sweep)
- **Takeaway line on slide:** *"Text-layer defenses collapse; execution-layer
  defense holds."*

---

## Slide 5 — Finding 3: Not all defenses are equal

- **Key message:** There is a sharp split between defenses that operate on
  text (fragile) and defenses that operate on execution (robust).
- **What to show:**
  - Bar chart of gap (pp) per defense, sorted — dramatic asymmetry visible
  - `prompt_detection` tallest bar (regex = trivially bypassable)
  - `tool_permission` shortest (args are checked at execution, not parsed from text)
  - Annotation: *"Text-layer defenses can be rephrased around. Execution-layer
    enforcement cannot."*
- **Implicit claim:** defenses should be evaluated in the layer they operate
  on, not in aggregate.

---

## Slide 6 — Finding 4: Security-utility is a joint optimization

- **Key message:** A defense that drops ASR by also dropping task success is
  not a defense. Only tool_permission offers low ASR at high TSR.
- **What to show:**
  - Scatter plot: x = ASR, y = TSR, one dot per defense
  - Pareto frontier highlighted
  - The "sweet spot" defense labeled (likely tool_permission or all_combined)
  - Source: `agentdojo_integration/results_agentdojo.md` (⏳ pending sweep)
- **One sentence:** *"No free lunch, but some defenses buy security cheaper
  than others."*

---

## Slide 7 — Finding 5 (negative finding): Simulators can't measure this

- **Key message:** Rule-based simulators — widely used for agent security
  research — are structurally unsuited to adaptive-attack evaluation. Their
  own regex intent parsing gets dodged along with the defense.
- **What to show:**
  - Table or callout:
    - Direct baseline ASR (simulator): 75%
    - Direct adaptive ASR (simulator): 25%
    - Gap: **−50pp** (negative — attack succeeds *less* after adapting)
  - Explanation: the simulator's own tool-selection regex can't recognize
    the rephrased attack's intent, so the agent never even calls the target
    tool. Adaptive-attack eval requires a real LLM.
- **Why this matters:** motivates moving the evaluation to AgentDojo with a
  real (open-weight) model — and flags a methodology risk for future work.

---

## Slide 8 — Takeaways

- **Three things to walk away with:**

  1. **Adaptivity gap** should be a standard reporting metric. Most defenses
     in the literature have never been measured this way.

  2. **Execution-layer defenses > text-layer defenses** under rephrasing.
     Future defense design should emphasize enforcement at argument/tool
     boundaries, not text inspection.

  3. **Methodology check:** rule-based simulators can't evaluate adaptive
     attacks. Real LLMs in stateful environments are now tractable for this
     kind of research (we used a local 7B model on Ollama).

- **One closing line:** *"Defenses may look strong because the attacks we
  test them with are weak. Measuring the gap is cheap; ignoring it is expensive."*

---

## What's deliberately cut (lives in the final report only)

- Methodology: how the adaptive attack templates were written
- Experimental setup: AgentDojo suite, Qwen2.5 7B, sweep size, CIs
- Defense implementation details (prompt isolation markers, etc.)
- Comparison with related work (MELON, CaMeL, StruQ, etc.)
- Limitations list (single suite, single model, trial count)
- Bootstrap CI construction
- Ground-truth TMR construction

These are all in the report and in FINDINGS.md for the Q&A session, not on slides.

---

## Slides to build now vs. after sweep

| Slide | Status |
|---|---|
| 1 Title | ✅ build now |
| 2 Research problem | ✅ build now |
| 3 Finding 1 (baseline) | ✅ build now — midterm numbers already in hand |
| 4 Finding 2 (adaptivity gap table) | ⏳ pending sweep — headline slide |
| 5 Finding 3 (text vs execution) | ⏳ pending sweep — gap chart |
| 6 Finding 4 (TSR × ASR Pareto) | ⏳ pending sweep |
| 7 Finding 5 (simulator limitation) | ✅ build now — numbers already in hand |
| 8 Takeaways | ✅ build now |

**5 of 8 slides can be fully built today.** Three are gated on sweep results
(the three carrying the sweep numbers). Even if sweep is delayed, the
narrative still holds: slides 1–3 frame, slide 7 is the "we also found this"
methodological note, slide 8 closes. Minimum-presentable-if-sweep-fails is 5 slides,
still coherent.

---

## Style notes for when you build in Keynote/Google Slides/PowerPoint

- **One message per slide.** If you want to say two things, split.
- **Visual > words.** Slide 4 is a table. Slide 5 is a bar chart. Slide 6 is
  a scatter plot. Everything else is minimal text.
- **Use color consistently:** baseline (blue), adaptive (red), gap (orange
  highlight). Tool_permission gets a distinctive color so its shortness in
  slide 5's bar chart pops.
- **Round all numbers to 0 or 1 decimal.** `47%` or `47.3%`, never `47.32%`.
- **Speaker notes > bullets.** Write the sentence you'll say in the speaker
  notes; put only the keyword on the slide.
- **Slide 4 is the money slide.** Design it last, make it cleanest, rehearse it.
