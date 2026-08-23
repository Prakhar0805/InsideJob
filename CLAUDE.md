# InsideJob

**"Deterministic" LLM-agent guardrails are evaluated on whether the *agent* can be fooled. That measures the wrong thing. We measure what the *enforcer admits* — and show the admitted set is systematically larger than the policy appears to describe. Zero GPU, zero fine-tuning, and the core result needs zero API calls.**

This file is the standing context for the project. Read it fully before writing code. If a task conflicts with this file, this file wins unless the user overrides it in that conversation.

> **Pivot note (2026-08-24).** This project began as an adaptive-attack study against Progent (the old brief is preserved in `CLAUDE.old.md`). That framing was abandoned because it required a full LLM agent rollout per data point — months of free-tier budget for an underpowered result. The security-critical component of a deterministic defense is not the agent, it is the **matcher**, which is pure code. Auditing the matcher is free, exact, model-independent, and reproducible in seconds. The old goal — does the defense actually hold — is answered more sharply this way.

---

## 1. What this project is

Progent, Janus, and the wider "policy-as-code for agents" family all work the same way:

> an **LLM writes** a least-privilege policy → **code enforces** it on every tool call.

The field's security argument is *"the enforcer is code, so it can't be prompt-injected."* That protects the wrong boundary. The policy **describes** an intended set of permitted argument values; the matcher **admits** a different, larger set. The gap between them is a **parser differential** — a vulnerability class with a 20-year CVE history (CouchDB CVE-2017-12635, GitLab SAML 2025, the Tekton `VerificationPolicy` substring bypass) that no one had applied to LLM-agent guardrails.

We characterize that gap, prove it reaches real harm on AgentDojo's own tasks, show it generalizes across two independently-built engines, and ship a linter that closes the half of it a policy rewrite can reach — measuring the utility cost of the other half.

We are the red team and the tool-builders, **not** the defense's authors. Progent and Janus are used unmodified.

---

## 2. Research questions

**Primary:**
> For a deterministic, code-level policy engine that enforces LLM-generated JSON-Schema policies, does the set of tool calls the matcher **admits** coincide with the set the policy **intends**? Where they diverge, can an attacker reach the benchmark's own harm objectives with a call that is fully policy-compliant?

**Secondary (generalization):**
> Is this a property of one implementation or of the architecture? The same taxonomy is run against a second, independently-built engine (Janus, `janus-guard` on PyPI) that adopted the same policy shape. If both exhibit the same gaps, the finding is architectural.

**Tertiary (mitigation):**
> How much of the gap is closable by rewriting the policy (engine unmodified), how much requires the engine to change, and what does each cost in legitimate-task utility?

---

## 3. The verified taxonomy

Every row was executed against the installed `jsonschema` 4.26.0 / `z3-solver` 5.1.0 and is pinned by a regression test in `tests/test_enforcement_gaps.py`. Codes are shared by the code, the tests, the logs, and the write-up.

**A — matcher semantics (admitted set larger than written):**
- **A1 unanchored** — `re.match` is prefix-only; JSON Schema `pattern` is `re.search`. `pattern:"IBAN"` admits `IBAN-ATTACKER`.
- **A2 raw regex** — restrictions compile as regex, so `.` in `"a@b.com"` is a wildcard.
- **A3 type-scoped no-op** — schema keywords are silently ignored off-type; `{"type":"array","pattern":…}` constrains nothing.
- **A4 format unenforced** — `format` is recommended to the policy LLM but validated with no checker, so it is a pure annotation (and `uri` has no checker even when one is enabled).
- **A5 unconstrained siblings** — only named args are checked; no `required`, no `additionalProperties:false`.

**B — control flow (allows where it should deny):**
- **B1 absent-arg skip** — a restriction on an argument that wasn't passed is skipped.
- **B2 fallback leak** — the fall-through default-deny is governed by the *last rule's* fallback field; out-of-range ⇒ allow.
- **B3 deny fails open** — a bare `except: continue` deletes any forbid rule that errors.
- **B4 precedence inversion** — priority-100 (every LLM rule) is *lowest* precedence; a broad low-numbered allow pre-empts it.
- **B5 no-policy-allows** — an unset policy permits everything.

**C — boundary disclosure:** every Progent denial hands the agent the schema fragment and the user query verbatim (`'DE89…' is not one of ['GB29…']`). The engine is an oracle for its own boundary — which is why the *original* adaptive-attack question is cheap: the defense quotes the answer back.

**Out of scope (by choice, to keep the thesis clean):** the policy-*update* path where untrusted tool output is spliced into the policy LLM's prompt. Real and serious, but it is a *synthesis* finding, needs API budget, and dilutes a clean enforcement story. Noted as adjacent future work only.

---

## 4. Scope

### In scope
- Offline, zero-LLM differential analysis of the enforcement matcher vs a sound reference.
- Reachable-harm validation using AgentDojo's own state-based `security()` predicates (never an LLM judge).
- Cross-engine generalization (Progent + Janus), through a shared adapter interface.
- A policy-hardening linter and a free, formal measurement of its utility cost.
- A small optional LLM-generated-policy study (the only thing that spends budget) to show the gaps occur in *real* generated policies, not just constructed ones.

### Explicitly out of scope — do not implement without a direct instruction
- Modifying Progent's or Janus's engine code (they are the systems under test; configure/observe only).
- Modifying AgentDojo's scoring (`security()` / `utility`). If a bug is suspected, flag it — see the `banking any()` precedence bug, which we report but do **not** patch.
- Any white-box/gradient work, model hosting, or fine-tuning.
- The policy-update injection path (above).
- Claiming this "solves" prompt injection. It characterizes one enforcement-layer weakness and fixes part of it.

---

## 5. Architecture

```
        LLM  ──writes──►  policy  (JSON-Schema conditions per tool arg)
                             │
                    ┌────────┴─────────┐
                    │                  │
              enforcer matcher    strict reference      ← same rules, sound semantics
              (Progent / Janus)   (StrictEnforcer)
                    │                  │
                    └──── differ? ─────┘  every disagreement = a labelled gap instance
                             │
                    admitted-but-unintended call
                             │
                    ┌────────▼─────────┐
                    │   harm oracle    │  execute in a fresh AgentDojo sandbox,
                    │ (AgentDojo state)│  then ask the injection task's security()
                    └────────┬─────────┘
                    admitted AND reference-rejected AND achieves attacker goal
                             │
                        validated bypass
                             │
                    ┌────────▼─────────┐
                    │   policy_lint    │  harden → re-run → gap closes; utility cost measured
                    └──────────────────┘
```

**Components (all in `src/`):**
1. **`enforcers/`** — `EnforcerAdapter` protocol; `progent.py`, `janus.py` (adapters over the real engines, unmodified), and `strict.py`, the sound reference. `strict.py` is parameterised by *which* gaps it fixes, so a differential run attributes each disagreement to exactly one class.
2. **`gapfuzz/`** — mutation operators (one family per gap class), the bypass search (admitted ∧ reference-rejected ∧ harmful), the differential sweep, and the reachable-harm sweep. CLI: `python -m gapfuzz`.
3. **`harm_oracle.py`** — the zero-LLM oracle over AgentDojo's `security()` predicates.
4. **`policy_lint.py` / `utility_cost.py`** — the mitigation and its measured cost.
5. **`policy_corpus.py`** — the only API-spending step (generate real policies; cached, resumable).

---

## 6. Tech stack & hard constraints

- **Python 3.11+** (dev env is 3.13, venv at `.venv`).
- **Benchmark:** AgentDojo (vendored, unmodified — `agentdojo/`). We reuse its tasks, environments, and `security()`/`utility` scoring as-is.
- **Systems under test:** Progent (vendored as `progent/`, package `secagent`) and Janus (`pip install janus-guard`). Both unmodified.
- **Compute:** none. No GPU, no model hosting, no fine-tuning.
- **Cost ceiling: $0.** The core result (Phases A/B/E) makes **zero** API calls. Only the optional generated-policy study (`policy_corpus.py`) calls an API, on a free tier, batched and cached. Groq free tier has no card attached: over-limit returns HTTP 429, never a charge.
- **Secrets:** API keys live in `.env` (gitignored), loaded via `python-dotenv`. Never hardcode, never log, never commit.

---

## 7. Repository structure

```
InsideJob/
├── CLAUDE.md                  # this file          CLAUDE.old.md  # the abandoned ASR brief
├── README.md  VENDOR.md  requirements.txt  pytest.ini
├── agentdojo/  progent/       # vendored, unmodified (see VENDOR.md)
├── src/
│   ├── enforcers/             # base.py, strict.py, progent.py, janus.py
│   ├── gapfuzz/               # operators, search, sweep, harm_sweep, corpus, __main__
│   ├── harm_oracle.py         # zero-LLM AgentDojo harm oracle
│   ├── policy_lint.py         # detect + repair gaps
│   ├── utility_cost.py        # free false-positive measurement of hardening
│   ├── policy_corpus.py       # the only API-spending step (Phase C)
│   ├── config.py llm_clients.py  # kept for Phase C; token-aware free-tier pacing
│   └── agent.py case_runner.py runner.py  # retained for the Phase-D end-to-end proof
├── gapfuzz/                   # thin shim so `python -m gapfuzz` works
├── tests/                     # 106+ tests; the taxonomy is pinned here
├── experiments/  results/  writeup/
```

---

## 8. Development phases

| Phase | Goal | Status |
|---|---|---|
| A. Differential harness | Matcher vs strict reference; every flawed idiom's bypass rate, per gap class | **done** — 100% of flawed idioms, 0% of exact enum; 760 instances; free |
| B. Reachable harm | Admitted-and-harmful validated by AgentDojo `security()` | **done** — oracle calibrated 25/25; validated bypasses demonstrated |
| C. Generated policies | Show the gaps occur in *real* LLM-written policies (only API spend) | ready to run when a key is present; cached + resumable |
| D. Cross-engine + e2e | Janus adapter; a handful of real agent rollouts as an existence proof | Janus adapter + small rollout budget |
| E. Mitigation | `policy_lint` closes A1–A4 free; measure the A5/B engine-level cost | **done** — 100% utility for policy-level fixes, ~88% with A5 |
| F. Deliverables | Repo + tool + interactive artifact + write-up + responsible disclosure | in progress |

---

## 9. Metrics & logging

- **Never report an admittance number without its harm and utility context.** A matcher admitting a superset only matters if some admitted call is harmful; a fix only matters if legitimate tasks survive it. Both travel with every claim.
- **Attribute every gap to one class**, by isolating which single reference-fix flips the verdict — not by which operator produced the candidate.
- **A reported bypass clears three gates:** admitted by the engine, rejected by the strict reference, and scored harmful by AgentDojo. Never fewer.
- **The reference-soundness invariant is asserted in every sweep:** the strict reference must never admit what the engine denies. A violation means our reference is wrong, not that we found a gap.
- **Handle AgentDojo's confounds explicitly, never silently:** the `banking/user_task_15` attacker-IBAN confound (excluded), the `slack/injection_task_5` trace-scoring, the stateful policy replay, and the `banking any()` precedence bug (flagged, not patched).

---

## 10. Coding conventions

- Type hints on all signatures. Docstrings explain *why*, especially in `enforcers/strict.py`, `harm_oracle.py`, and `policy_lint.py`, where research validity depends on correct logic.
- `gapfuzz` must never import `secagent` or `janus` directly — everything engine-specific lives behind `EnforcerAdapter`. This is what makes the cross-engine claim a config change, and it is a deliverable in its own right.
- Do not modify AgentDojo scoring or the engines under test. Configure/observe only.
- Test anything touching matching, harm-scoring, attribution, or aggregation. The taxonomy is pinned as "engine allows X, reference denies X," so a test starting to fail is the signal that a gap was fixed upstream.
- API calls (Phase C only) need retry/backoff and must log rate-limit hits, never fail silently.

---

## 11. Responsible research & disclosure

- Everything runs in AgentDojo's sandbox. No real accounts, services, or production tools, ever.
- Both engines are real, installable open-source projects. **Disclosure precedes publication.** Notify maintainers with the findings and the hardening patch, state a window, then publish. Janus first (it is on PyPI advertising production use, and its fail-open behaviours are the most dangerous). Keep building meanwhile.
- The write-up includes a Responsible Disclosure section. Working exploit strings against a real deployed instance are never published; the taxonomy, rates, and sandboxed reproductions are.

---

## 12. Bottom line

Success is the taxonomy proven and pinned, the harm validated on the benchmark's own oracle, the generalization shown across two engines, the fix shipped with its cost measured, and all of it reproducible by a reviewer in seconds with no API key — plus an honest write-up and responsible disclosure. Not one number landing a certain way.
