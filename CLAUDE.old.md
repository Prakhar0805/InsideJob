# InsideJob

**Adaptive red-teaming of deterministic agent defenses, using only authorized-action attacks — zero GPU, zero fine-tuning, API-only.**

This file is the standing context for this project. Read it fully before writing any code. If anything in a task conflicts with this file, this file wins unless the user explicitly overrides it in that conversation.

---

## 1. What this project is

We are testing whether **Progent** — an open-source, deterministic, code-level policy engine for LLM agents — still blocks prompt-injection-driven misbehavior when the attacker is allowed to *adapt* over many rounds, is confined to tools the agent is *already authorized to use*, and the agent is a real frontier model rather than a small self-hosted one.

We are **not** building a new defense. Progent already exists and is not being modified except through its own supported policy/config interface. We are the red team, not the architects.

Only one prior study (LaunchSafe, June 2026) has adaptively tested a deterministic agent defense at all, and it explicitly named this exact scenario as its own unanswered next question. That's the gap this project fills.

---

## 2. Research questions

**Primary:**
> Does Progent's deterministic policy check still hold when the attacker (a) adapts over many rounds instead of trying once, (b) is tested against a real frontier model accessed via API rather than a small self-hosted one, (c) is evaluated across AgentDojo's full task suite rather than a slice, and (d) is constrained to actions the agent is already authorized to perform, rather than trying to defeat the policy layer directly?

**Secondary (pre-registered, not an afterthought):**
> Is that answer consistent across model families, or does it depend on which model is doing the acting? Run the identical pipeline on at least two agent models from different providers (e.g. a Groq-hosted open-weight model and a Gemini-hosted closed model) and report whether they land in the same place.

Both questions get answered and reported, regardless of which way either one comes out.

---

## 3. Pre-registered success criteria

Decide these **before Phase 2 (the full adaptive sweep) begins**, and timestamp the decision. This exists so results can't be reframed after the fact to fit whatever we find. If there's a genuine reason to revise a threshold later, log it explicitly as a dated deviation with a stated reason — never quietly move the goalposts after seeing results.

**Primary finding — is Progent's adaptive robustness real at scale?**
- **"Defense holds"** — adaptive ASR stays within roughly the 2.6%–4.2% band Progent has shown in every prior test (allow natural variance; use judgment, but the number needs to visibly overlap that band, not just be "still low-ish").
- **"Defense cracked"** — adaptive ASR clearly and repeatably lands outside that band. A single outlier task doesn't count; it needs to hold up across a meaningful share of cases and domains.
- Both outcomes are written up with equal seriousness. Neither is the hoped-for result — do not design the attacker, tune the round count, or pick reporting cutoffs in a way that nudges toward one answer.

**Secondary finding — is the result model-dependent?**
State in advance: "consistent" means both agent models land in the same band (hold or crack) within a reasonable margin; "model-dependent" means they diverge meaningfully. This resolves cleanly no matter what the primary finding is, and is genuinely useful on its own — a defense that only holds for one model family is a materially weaker claim than one that holds for both.

**Deliverable-level success — independent of either number:**
Even if both models land cleanly in "defense holds" and nothing dramatic turns up, the project is still a success if it produces all four of:
1. This written, timestamped threshold decision, committed *before* Phase 2 ran.
2. A working, documented, reusable evaluation harness — someone else should be able to clone the repo, swap in a different AgentDojo-wrapped defense, and get a comparable adaptive-ASR result without rewriting the attack loop.
3. A clear, reported answer to the cross-model question above.
4. An honest write-up reporting whichever combination of the above actually happened.

Do not begin Phase 2 until this section is finalized.

---

## 4. Scope

### In scope
- A black-box, API-only, evolutionary adaptive attacker (generate attempt → observe blocked/executed → mutate → repeat)
- Reusing Progent's existing open-source policy engine, in its proxy mode, unmodified
- Testing on real models reached via free API tiers — both an open-weight model (via Groq) and a closed frontier model (via Gemini's free tier)
- The full AgentDojo benchmark: all 4 domains, all ~629 test cases
- Attacks confined to tools already present in the agent's authorized action set for that task
- Honest reporting of Utility alongside ASR, in every result, no exceptions

### Explicitly out of scope — do not implement these without a direct instruction from the user
- White-box / gradient-based attacks (GCG or similar) — requires model internals and a GPU we don't have
- Self-hosting any open-weight model — no local GPU inference of any kind
- Fine-tuning, LoRA, or any weight modification of any model
- Designing a new defense architecture — Progent is used as-is
- Confidentiality/data-leak attacks (system prompt extraction, secret leakage) — this project is about hijacked *actions*, not leaked *text*
- Any claim, in code comments or write-ups, that this "solves" prompt injection generally

If a task seems to require any of the above, stop and flag it rather than working around it.

---

## 5. Architecture

```
        ┌─────────────────────┐
        │  Frontier agent      │   (Groq or Gemini free tier — no self-hosting)
        └──────────┬───────────┘
                   │ wants to call a tool
        ┌──────────▼───────────┐
        │  Progent proxy        │   (deterministic policy check — unmodified,
        │  (policy engine)       │    no model access needed)
        └──────────┬───────────┘
              allow │  │ deny
        ┌──────────▼┐ ┌▼──────────┐
        │  execute   │ │  blocked   │
        └────────────┘ └─────┬──────┘
                              │ feedback
        ┌─────────────────────▼───────┐
        │  Black-box attacker (LLM)     │   (different provider/model family
        │  evolutionary loop:            │    than the agent, to avoid
        │  generate → test → mutate →    │    correlated failure)
        │  repeat for N rounds           │
        └────────────────────────────────┘
```

**Components:**
1. **Agent** — a frontier model called via API. No self-hosting.
2. **Defense** — Progent, proxy mode, wrapping the agent's tool calls. Pure code, no GPU.
3. **Attacker** — a separate model, different provider/family than the agent, running an evolutionary black-box loop (per Swept AI's proven zero-compute methodology): craft injected content → observe whether the resulting action was blocked or executed → keep what worked, mutate, try a new angle → repeat for many rounds per test case.
4. **Harness** — AgentDojo's own environments, tasks, and scoring (formal utility functions checking environment state — do not replace this with an LLM judge).
5. **Constraint enforcement** — every attack attempt must be checked to confirm it stays within the agent's already-authorized tool set for that task before counting as a valid "authorized-action attack." Attempts that only succeed by escaping the policy boundary itself are a different experiment and must be logged separately, not folded into the headline number.

---

## 6. Tech stack & hard constraints

- **Language:** Python 3.11+
- **Benchmark:** AgentDojo (forked from the official open-source repo — reuse its tasks, environments, and scoring as-is; do not reimplement scoring logic)
- **Defense:** Progent (official open-source repo, proxy mode)
- **Model access:** Groq API (free tier — open-weight models, e.g. Llama 3.3 70B) and Google AI Studio (free tier — Gemini, closed model). Use different providers/model families for the agent role vs. the attacker role.
- **Compute:** none. No GPU, no local model hosting, no fine-tuning, anywhere in this pipeline. If a step seems to need a GPU, that step is out of scope — flag it, don't route around it.
- **Cost ceiling:** $0. All API usage stays within free tiers. Batch and rate-limit requests; add retry/backoff for free-tier throttling.
- **Secrets:** API keys live in a `.env` file (gitignored), loaded via `python-dotenv`. Never hardcode keys, never log full keys, never commit `.env`.

---

## 7. Repository structure

```
insidejob/
├── CLAUDE.md                  # this file
├── .env.example
├── requirements.txt
├── agentdojo/                 # forked benchmark harness (submodule or vendored)
├── progent/                   # forked defense engine (submodule or vendored)
├── src/
│   ├── agent.py                # agent wrapper (Groq / Gemini backends)
│   ├── attacker.py             # evolutionary black-box attack loop
│   ├── scope_check.py          # verifies attacks stay within authorized-action bounds
│   ├── runner.py                # orchestrates a full benchmark sweep
│   └── logging_schema.py       # structured result logging (see §9)
├── experiments/
│   ├── phase0_baseline_repro/  # reproducing published numbers before anything new
│   ├── phase1_static/           # our own static-attack baseline, per model
│   ├── phase2_adaptive/         # the actual adaptive sweep
│   └── phase3_ablations/        # includes the cross-model comparison (§2, §3)
├── results/                    # raw logs + aggregated CSVs, per experiment
└── writeup/                    # the eventual report/preprint
```

---

## 8. Development phases

Do not begin Phase 2 until §3 (pre-registered success criteria) is finalized and timestamped.

| Phase | Goal | Definition of done |
|---|---|---|
| 0. Baseline reproduction | Reproduce Progent's and/or LaunchSafe's published numbers on our own setup | Our numbers land within a reasonable margin of published ones, on the same or comparable conditions; discrepancies are investigated and explained, not ignored |
| 1. Static baseline (ours) | Establish undefended and Progent-defended static ASR/Utility, per model we use | Clean numbers logged for both Groq and Gemini agents, all 4 domains |
| 2. Adaptive attacker | Build and validate the evolutionary attack loop, run the full sweep per §3's criteria | Attacker demonstrably improves over rounds on a held-out sample before the full run; complete results for all ~629 cases, both models, with authorized-action-scope check applied to every successful attack |
| 3. Ablations + cross-model comparison | Round count, attacker model strength, per-domain breakdown, and the pre-registered secondary hypothesis (§2) | Ablation table complete; cross-model consistency question explicitly answered, not just implied by the numbers |
| 4. Write-up | Honest report of findings | Both possible primary outcomes and the cross-model outcome reported plainly; the deliverable checklist in §3 is fully checked off |

---

## 9. Metrics & logging

Every single test case run must log at minimum:

```
timestamp, model_provider, model_name (agent), attacker_model,
domain, task_id, defense_state (none | static | adaptive),
rounds_used, blocked (bool), final_action_taken,
within_authorized_scope (bool), utility_score, attack_succeeded (bool),
notes / transcript_path
```

Rules:
- **Never report ASR without Utility next to it.** A defense that blocks everything but also breaks every real task is not a result worth reporting as a win.
- **Never average away per-domain or per-model numbers silently.** Report per-domain and per-model-provider breakdowns; an aggregate hiding one domain's or one model's collapse is misleading.
- **Log blocked attempts too, not just successes.** The shape of what got blocked is as informative as what got through.
- **Keep raw transcripts.** Aggregated numbers get double-checked against them before anything goes in the write-up.

---

## 10. On comparing to prior baselines — important correction

**Do not directly compare our ASR numbers to LaunchSafe's or Progent's published numbers as if they're on the same scale.** ASR is a function of *model + defense + attack* jointly — a different model has its own native susceptibility to injection, independent of how good our attack is. Directly claiming "we beat their 2.6%" using a different model would be comparing apples to oranges.

**The correct comparison is internal, per model:**
1. Undefended ASR (Progent off) — our own model
2. Static-attack ASR, Progent on — our own model
3. Adaptive-attack ASR, Progent on — our own model

The finding that matters is **(3) vs (2), on the same model** — did adapting the attack meaningfully raise ASR over our own static baseline? Prior published numbers (2.6%–4.2% for Progent's own tests) are *context* to cite in the write-up, and the reference band used in §3 — not a target number to literally beat with a different model.

---

## 11. Coding conventions

- Type hints on all function signatures.
- Docstrings explaining *why*, not just *what*, especially in `scope_check.py` and `attacker.py` where the research validity depends on correct logic.
- Design `attacker.py` and `runner.py` so a different AgentDojo-wrapped defense could be swapped in without rewriting the attack loop — this reusability is itself a project deliverable (§3).
- Do not modify AgentDojo's core scoring functions. If a bug is suspected in them, flag it — don't silently patch around it, since that undermines comparability to published numbers.
- Do not modify Progent's policy engine itself — configure it through its supported interface only.
- Write tests for anything that touches scoring, scope-checking, or result aggregation. LLM call correctness can't be unit-tested the same way, but the logic wrapped around it can be.
- All API calls need retry/backoff and should log rate-limit hits, not fail silently.

---

## 12. Safety and responsible-research guardrails

- All execution stays inside AgentDojo's simulated environment. No real email accounts, no real banking APIs, no real production tools of any kind, ever.
- Attacker-generated content is only ever tested against our own sandboxed setup — never against real, deployed third-party agents or services.
- If anything resembling a genuinely novel, exploitable weakness in a real (non-sandboxed) system turns up unexpectedly, pause and raise it with the user before including specifics in any public write-up — default to responsible disclosure norms.

---

## 13. Reference reading (in priority order)

1. AgentDojo — https://arxiv.org/abs/2406.13352 — the benchmark itself
2. Zhan et al., 2025 — https://arxiv.org/abs/2503.00061 — why static testing lies
3. Nasr et al., "The Attacker Moves Second" — https://arxiv.org/abs/2510.09023 — the field's landmark result
4. Progent — https://arxiv.org/abs/2504.11703 — the defense under test
5. LaunchSafe — https://arxiv.org/abs/2606.26479 — the paper whose open question this project answers
6. Swept AI — https://arxiv.org/abs/2604.23887 — the attack-loop methodology this project reuses

---

## 14. Bottom line

Success is not one number landing a certain way. Success is §3's four deliverables being checked off, honestly, whatever the numbers turn out to say.
