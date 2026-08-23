# InsideJob — Paper Guardrails

**"Deterministic" LLM-agent guardrails are audited on whether the *agent* can be fooled. That's the wrong test. We audit what the *enforcer admits* — and the admitted set is systematically larger than the policy appears to describe. The core result runs in seconds, with no GPU, no model, and no API key.**

---

## The one-paragraph version

Progent (UC Berkeley), Janus, and the whole "policy-as-code for agents" family share a design: **an LLM writes a least-privilege policy, and deterministic code enforces it** on every tool call. The pitch is "the enforcer is code, so it can't be prompt-injected." But that guards the wrong boundary. The policy *describes* an intended set of allowed argument values; the matcher *admits* a different, larger set. That gap is a **parser differential** — the same bug class behind CouchDB CVE-2017-12635 and the GitLab SAML 2025 auth bypass — and nobody had pointed it at agent guardrails. We characterize it, prove it reaches real harm on AgentDojo's own tasks, show it holds across two independently-built engines, and ship a linter that closes the part a policy rewrite can reach.

## What we found (all reproducible offline)

- **The matcher admits a strict superset of the policy.** Across 95 policy fragments per suite, every flawed-but-natural policy idiom is **100% bypassable**; the one sound idiom (an exact `enum`) is **0%**. 760 labelled gap instances.
- **`pattern` is unanchored** (`re.search`): `pattern:"GB29NWBK…"` also admits `GB29NWBK…-ATTACKER`. Progent's bare-string branch uses `re.match` — prefix-only.
- **Schema keywords are silently ignored off-type**: `{"type":"array","pattern":"^emma@corp.com$"}` enforces *nothing* — and Progent's own prompt warns the LLM about this, which means they know the model gets it wrong.
- **`format` is recommended to the policy LLM and never enforced.** **Deny rules fail open** — any error evaluating a forbid rule deletes it. **"Default deny" isn't even a construct** — it's governed by the last rule's fallback field.
- **The engine leaks its own boundary**: every denial hands the agent the exact allowed-value set (`'DE89…' is not one of ['GB29…']`).
- **Validated harm, not just theory.** An admitted call only counts when AgentDojo's own state-based `security()` predicate confirms it achieves the attacker's objective. The oracle is calibrated on all 25/25 injection tasks.
- **A fix, with its cost measured for free.** The taxonomy splits: **A1–A4 close by rewriting the policy alone — 100% of legitimate tasks preserved.** A5 and the control-flow gaps are matcher behaviors that need the engine to adopt strict semantics; closing A5 by denying unnamed arguments costs ~12% utility. Every number is computed with zero API calls.

## Reproduce it in seconds

```bash
python -m venv .venv && . .venv/Scripts/activate     # ../bin/activate on POSIX
pip install -e ./agentdojo -e ./progent && pip install -r requirements.txt

python -m gapfuzz audit --enforcer progent           # the differential result
python -m gapfuzz audit --enforcer strict            # self-consistency: 0 gaps
python -m gapfuzz harm  --enforcer progent           # reachable-harm sweep
python -m pytest                                     # 106 tests; the taxonomy is pinned here
```

No `.env`, no API key, no cost. Every gap in `tests/test_enforcement_gaps.py` is written as *"the real engine allows X, a sound matcher denies X"* — so the day one starts failing is the day the gap was fixed upstream.

## How it's built

| Path | What |
|---|---|
| `src/enforcers/base.py` | the `EnforcerAdapter` protocol + the `GapClass` taxonomy (A1–A5, B1–B5) |
| `src/enforcers/strict.py` | the sound reference matcher, parameterized by which gaps it fixes (so each disagreement attributes to one class) |
| `src/enforcers/progent.py` | adapter over the real `secagent` engine, unmodified |
| `src/enforcers/janus.py` | adapter over `janus-guard` — the cross-engine check |
| `src/gapfuzz/` | mutation operators, the bypass search, and the two sweeps; `python -m gapfuzz` |
| `src/harm_oracle.py` | zero-LLM oracle over AgentDojo's own `security()` state predicates |
| `src/policy_lint.py` | detect + repair gaps; splits policy-fixable (A1–A4) from engine-level (A5, B*) |
| `src/utility_cost.py` | free false-positive measurement of the hardening |
| `agentdojo/`, `progent/` | vendored upstream, **unmodified** (see `VENDOR.md`) |

The design rule that makes the cross-engine claim cheap: **`gapfuzz` never imports `secagent` or `janus`** — everything engine-specific is behind `EnforcerAdapter`. Swapping the engine under test is a one-line change.

## What a reported bypass has to clear

Three gates, never fewer:

1. **Admitted** by the real engine's matcher.
2. **Rejected** by the strict reference (else it's a too-broad policy, not an enforcement gap).
3. **Harmful** — AgentDojo's `security()` predicate confirms the call achieves the injection task's objective in a freshly-executed sandbox.

And a global invariant, asserted in every run: the strict reference never admits what the engine denies. If it did, the reference would be wrong — so this guards the validity of every number.

## Honest scope

This characterizes **one** enforcement-layer weakness and fixes part of it. It does not "solve" prompt injection. The reachable-harm rate on *LLM-generated* (rather than constructed) policies is the one measurement that costs a little API budget — it is built, cached, and resumable, and is the only step that needs a key. The systems under test are real open-source projects; **maintainers are notified before publication** (see `CLAUDE.md` §11).

## Origins

This began as an adaptive-attack study against Progent; that brief is preserved in `CLAUDE.old.md`. It was abandoned because it needed a full agent rollout per data point — months of free-tier budget for an underpowered result. Auditing the matcher instead answers the same question ("does the defense actually hold?") more sharply, for free.
