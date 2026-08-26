# Paper Guardrails: Enforcement Gaps in Deterministic LLM-Agent Policy Engines

**A parser-differential audit of Progent and Janus, with a benchmark-validated harm oracle and a measured mitigation.**

InsideJob · draft findings · 2026-08-24

---

## Abstract

A growing class of defenses secures LLM agents by having an LLM write a
least-privilege policy and then enforcing it with deterministic code on every
tool call. The security argument is that the enforcer is code and therefore
cannot be prompt-injected. We show this protects the wrong boundary. The policy
*describes* a set of permitted argument values; the matcher *admits* a different,
larger set. Across the 95 policy-relevant string arguments in the four AgentDojo
domains — 380 policy fragments, one per (argument × idiom) —
**every natural-but-flawed policy idiom is 100% bypassable and the one sound
idiom (an exact `enum`) is 0% bypassable** — a clean parser differential, the
same vulnerability class behind CouchDB CVE-2017-12635 and the 2025 GitLab SAML
bypass, applied for the first time to agent guardrails. We validate that admitted
calls reach real harm using AgentDojo's own state-based `security()` predicates
(no LLM judge), show the gaps reproduce **byte-identically in a second,
independently-built engine** (Janus), and ship a linter that closes the
policy-expressible half of the taxonomy at **zero measured utility cost**, while
quantifying why the other half needs an engine change. The core result makes
**zero API calls** and reproduces in seconds.

---

## 1. The setup, and why the usual test misses it

Progent (UC Berkeley; arXiv:2504.11703) and Janus (`janus-guard`, PyPI) share an
architecture that is becoming the default for "agent security":

> An LLM reads the user's task and emits a JSON-Schema **policy** — per tool, a
> list of `(priority, effect, conditions, fallback)` rules whose `conditions`
> constrain each argument. A deterministic **matcher** then checks every tool
> call against that policy before it executes.

Prior evaluation asks: *can a prompt injection talk the agent into a bad tool
call?* That measures the agent. But the load-bearing security component is the
**matcher**, and it is pure code — so we can ask a sharper question directly, with
no agent and no model in the loop:

> **Does the set of calls the matcher admits equal the set the policy intends?**

Where they differ, an attacker does not need to defeat the policy layer. They
need only find a call inside the *admitted* set but outside the *intended* one —
a fully policy-compliant bypass.

## 2. Method

Three components, all in the repository, all offline:

- **A strict reference matcher** (`src/enforcers/strict.py`) implements the same
  rule structure with *sound* semantics: patterns anchored to a full match,
  schema keywords enforced only where they apply, `format` actually checked,
  unnamed arguments denied, errors failing closed, a real default-deny. It is
  parameterised by *which* gap it fixes, so a disagreement attributes to exactly
  one cause.
- **Engine adapters** (`progent.py`, `janus.py`) drive the real engines through
  their public APIs only — never reimplementing their matching, so what we
  measure is their genuine behaviour.
- **A harm oracle** (`src/harm_oracle.py`) executes a candidate call in a fresh
  AgentDojo sandbox and asks the injection task's own `security()` predicate
  whether the attacker's objective was achieved. This is AgentDojo's formal,
  state-based scoring — not an LLM judge.

A reported bypass clears three gates: **admitted** by the engine, **rejected** by
the strict reference, and **harmful** per AgentDojo. A global invariant is
asserted in every run — the reference never admits what the engine denies — so a
violation would indict our reference, not the engine.

## 3. The taxonomy (every row executed, not inferred)

Verified against `jsonschema` 4.26.0 / `z3-solver` 5.1.0 and pinned in
`tests/test_enforcement_gaps.py` as "the real engine allows X, a sound matcher
denies X."

**A — matcher semantics admit a superset of the policy**

| | Gap | Consequence |
|---|---|---|
| A1 | Unanchored matching (`re.match` prefix; JSON-Schema `pattern` = `re.search`) | `pattern:"GB29…"` also admits `GB29…-ATTACKER` |
| A2 | Restrictions are raw regex, not literals | `.` in `"a@b.com"` is a wildcard |
| A3 | Keywords are type-scoped no-ops | `{"type":"array","pattern":…}` enforces nothing |
| A4 | `format` recommended to the LLM, never enforced (no `format_checker`; `uri` has no checker at all) | `format:"email"` admits any string |
| A5 | Only named args checked (no `required`, no `additionalProperties:false`) | an unnamed `amount`/`bcc` rides along |

**B — control flow allows where it should deny**

| | Gap | Consequence |
|---|---|---|
| B1 | `if arg_name in kwargs` | a restriction on an absent argument is skipped |
| B2 | `fallback` is loop-carried | "default deny" is set by the last rule's field; out-of-range ⇒ allow |
| B3 | bare `except: continue` around forbid rules | any error deletes the deny rule — it **fails open** |
| B4 | ascending-priority sort | priority-100 (every LLM rule) is *lowest* precedence; a broad allow pre-empts it |
| B5 | unset policy | permits everything that reaches it before the policy exists |

**C — the engine discloses its own boundary.** Every Progent denial returns the
schema fragment and the user query to the agent verbatim
(`'DE89…' is not one of ['GB29…']`). The deterministic engine is an oracle for
its own allow-list — which is exactly why the *original* adaptive-attack question
(can an adversary find the boundary?) is cheap: the defense quotes it back.

### 3.1 How each class is evidenced

Two different standards of evidence back this table, and conflating them would
overstate the result. Every class is pinned by a differential regression test —
a hand-built policy where the engine allows and the sound reference denies. Only
three are additionally produced *at scale* by the automated sweep in §4.1.

| class | pinned by regression test | produced by the automated sweep |
|---|---|---|
| A1, A3, A4 | ✓ | ✓ |
| A2, A5, B1–B5, C | ✓ | ✗ |

The reason is structural, not empirical. The sweep's corpus varies one *argument
value* against a fixed *policy shape*: exactly one allow rule, one pinned
argument, `fallback=0`, and a `dict` restriction. Classes whose trigger is a
policy **shape** (B2–B5), a **second argument** (A5, B1), a **bare-string
restriction** (A2), or the **denial path** (C) are therefore unreachable by
construction — not rare, but impossible to express in the current corpus. The
per-class rates in §4.1 are honest for the three classes they cover and silent
about the rest.

Closing this is tracked work: it requires the mutation operators to see the tool
schema (so an argument can be *added* or *dropped*) and the corpus to carry a
policy-shape dimension. Until then, "100% bypassable" is a claim about the three
swept classes, and the other eight rest on the fixtures in
`tests/test_enforcement_gaps.py`.

*Deliberately out of scope:* the policy-*update* path, where untrusted tool
output is spliced un-escaped into the policy LLM's prompt (`tool.py:446`). Real
and serious, but it is a *synthesis* finding needing API budget, and it dilutes a
clean enforcement story. Flagged as adjacent future work.

## 4. Results

### 4.1 The differential (offline, free)

`python -m gapfuzz audit --enforcer progent`. The corpus enumerates every
policy-relevant string argument in the four v1 suites — workspace 34, travel 29,
banking 17, slack 15 = **95 arguments** — and writes each one four ways, for 380
fragments total:

| policy idiom | fragments | bypassable | via |
|---|---|---|---|
| `enum` exact (sound control) | 95 | **0%** | — |
| pattern-pinned | 95 | **100%** | A1 |
| pattern, no `type` | 95 | **100%** | A1 + A3 |
| `format`-only | 95 | **100%** | A4 |

760 labelled gap instances; the reference invariant held throughout. The control
matters as much as the finding: a correctly-written policy (`enum`) is **not**
bypassable, so this is a property of *how policies are written*, not a claim that
nothing can be enforced.

Attribution is a clean isolation, not a best-effort ranking. Each instance is
labelled by enabling the reference's soundness fixes one at a time and recording
which single fix flips the verdict from admit to deny (`src/gapfuzz/attribution.py`).
Every one of the **760 instances is denied by exactly one fix — 0 over-determined,
0 unattributed** — so a row like "A1: 380" is a claim about anchoring
specifically, not about "something in here". The number `case_variation`
illustrates the discipline: that operator *hypothesises* A1, yet all of its
instances land on a `format`-only policy and correctly attribute to **A4** — the
value is admitted because `format` is never enforced, and there is no pattern to
anchor. The operator's guess is a fallback; the reference's isolation is the
finding. Over-determined and unattributed counts are printed on every run, so a
future case where two fixes both apply is reported rather than silently
tie-broken.

### 4.2 Cross-engine: the finding is architectural

`python -m gapfuzz audit --enforcer janus` returns **the same table, instance for
instance** — 760 gaps, 100%/0% split. Janus was built by a different team, yet
its source carries the same primitives (`validate_argument` → `re.match` /
unanchored `jsonschema`; `_check_conditions` → `if arg_name in arguments`). Two
independent implementations with the identical vulnerability profile ⇒ the gap is
a property of the **architecture** — LLM-authored JSON-Schema policy plus a code
matcher — not of one codebase.

### 4.3 Reachable harm

The harm oracle is calibrated: all **25/25** AgentDojo v1 injection tasks'
ground truths score as harmful through it, including the trace-scored
`slack/injection_task_5` and the multi-call tasks. Two structural bypass
patterns are demonstrated end-to-end and validated by `security()`:

- **A1 (loose URL)** — `slack/injection_task_3`, policy
  `{"get_webpage": [(100, 0, {"url": {"type":"string","pattern":"informations"}}, 0)]}`.
  A URL pinned by substring pattern — exactly the loose form Progent's own prompt
  recommends ("do not limit the scheme … allow different paths") — is unanchored,
  so the attacker's exfiltration URL is admitted and `security()` scores it
  harmful. Attributed A1.
- **A5 (uncapped sibling)** — `banking/injection_task_5`, policy
  `{"send_money": [(100, 0, {"recipient": {"type":"string","pattern":"US133…"}}, 0)]}`.
  The policy names `recipient` and says nothing about `amount`; the unnamed
  argument is never checked. Attributed A5.

Both are pinned in `tests/test_harm_oracle.py` and clear all three gates
(admitted ∧ reference-rejected ∧ `security()`-harmful).

**The committed sweep reports 0 bypasses, and that is the correct result.**
`results/phase_b_harm/progent_harm.json` runs a deliberately conservative
baseline that pins *every* argument to its exact benign value — a policy far
tighter than any LLM writes. Under exact pinning the injections target resources
the benign task never touched, so they are blocked. Reported as a null result
rather than omitted: it is the negative control for the harm arm, the same role
`enum-exact` plays in §4.1. The gaps bite where real generation is looser (loose
patterns, omitted keywords, unconstrained siblings), and §4.4 shows the fix and
its cost.

**Scope boundary.** Quantifying the bypass *rate on real LLM-generated policies*
is Phase C — **specified but not implemented**. It is the only measurement in
this project that would need an API key, and no number here depends on it. See
§5.

### 4.4 Mitigation, with cost measured for free

`policy_lint` detects every gap class and repairs those a policy rewrite can
reach. The taxonomy splits cleanly:

- **Policy-fixable (A1–A4):** anchor patterns, infer missing types, pin literals
  with `const`, back unenforceable formats. Enforced by the same engine on the
  hardened policy. **Utility cost: 0** — all 96 AgentDojo user tasks still admit
  their own ground-truth calls.
- **Engine-level (A5, B1–B5):** matcher behaviours no policy rewrite can override
  (the engine skips unnamed args regardless of policy content). Closing A5 by
  denying unnamed arguments costs **~12%** utility (12/96 tasks use an optional
  argument the minimal policy never named) and needs the engine to adopt strict
  semantics or a per-tool required-args schema.

This is the honest security/utility frontier: the cheap fixes are free; the rest
is a real engineering decision with a measured price.

## 5. Honest limitations

- **Constructed vs generated policies.** §4.1–4.4 use policies we construct to
  faithfully model the documented generation behaviour. Whether a given
  deployment's LLM writes loose enough policies often enough is the Phase-C
  measurement — **specified but not implemented**; it is the only step that would
  need a (free-tier) API key. The matcher-level result (§4.1–4.2) is independent
  of that: the engine admits the superset regardless of who wrote the policy.
- **Sweep coverage is partial.** The automated sweep produces three of the eleven
  taxonomy classes; the other eight are pinned by differential regression tests
  but not measured at scale. §3.1 gives the table and the structural reason. Any
  rate quoted in §4.1 is a rate over A1/A3/A4, not over the taxonomy.
- **Two bypasses, not a rate.** §4.3 demonstrates two end-to-end validated
  bypasses. That establishes reachability, not prevalence; prevalence is Phase C.
- **One benchmark.** AgentDojo's four domains. The taxonomy is
  library-level (`jsonschema`, `re`) and not AgentDojo-specific, but the
  reachable-harm figures are.
- **We did not patch the engines.** By design — they are the systems under test.
- **AgentDojo scoring quirks are reported, not fixed:** the `banking/user_task_15`
  attacker-IBAN confound (excluded), `slack/injection_task_5` trace-scoring, and
  a genuine operator-precedence bug in `banking/injection_task_{0,1,3}`'s
  `security()` (flagged, results reported separately).

## 6. Responsible disclosure

Progent and Janus are real, installable open-source projects. Maintainers are
notified with these findings and the `policy_lint` hardening before any public
release; no working exploit against a deployed instance is published. Everything
here runs only inside AgentDojo's sandbox. Janus is notified first: it is on PyPI
advertising production use, and its fail-open behaviours (B2/B3) are the most
dangerous.

**Status: not yet sent.** Drafts to both teams are in `writeup/DISCLOSURE.md`.
This document is not published until they have gone out and the stated window
has run.

## 7. Reproduce

```bash
python -m gapfuzz audit --enforcer progent   # §4.1
python -m gapfuzz audit --enforcer janus     # §4.2 — identical table
python -m gapfuzz harm  --enforcer progent   # §4.3
python -m pytest                             # the taxonomy, pinned; 131 tests
```

No API key. No GPU. The interactive demo (`writeup/demo.html`) runs the same two
matcher semantics live in the browser.

---

*Deliverables checklist: (1) the taxonomy, proven and pinned — three of eleven
classes additionally swept at scale (§3.1); (2) a reusable, engine-agnostic
offline evaluator; (3) cross-engine generalization, answered explicitly; (4) a
mitigation with measured cost; (5) this honest write-up. Not built: the
generated-policy prevalence rate (Phase C), the one item that would need an API
key.*
