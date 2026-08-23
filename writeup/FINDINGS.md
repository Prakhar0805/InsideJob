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
larger set. Across the four AgentDojo domains and 95 policy fragments per suite,
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

*Deliberately out of scope:* the policy-*update* path, where untrusted tool
output is spliced un-escaped into the policy LLM's prompt (`tool.py:446`). Real
and serious, but it is a *synthesis* finding needing API budget, and it dilutes a
clean enforcement story. Flagged as adjacent future work.

## 4. Results

### 4.1 The differential (offline, free)

`python -m gapfuzz audit --enforcer progent`, over 95 fragments/suite × 4 suites:

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

- **A1 (loose URL).** A policy pinning a URL by pattern — exactly the loose form
  Progent's own prompt recommends ("do not limit the scheme … allow different
  paths") — admits `https://docs.company.com.evil.tld/steal`, achieving the
  exfiltration objective.
- **A5 (uncapped amount).** A policy that pins `recipient` but not `amount` admits
  a $1,000,000 transfer to a payee a benign task legitimately used.

A conservative baseline that pins *every* argument to its exact benign value
holds at 0% — which is the point: the gaps bite where real generation is looser
(loose patterns, omitted keywords, unconstrained siblings), and §4.4 shows the
fix and its cost. Quantifying the bypass *rate on real LLM-generated policies* is
the one measurement that costs API budget; it is built (`policy_corpus.py`),
cached, and resumable, and is the sole step awaiting a key.

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
  measurement, which needs a (free-tier) API key we did not spend here. The
  matcher-level result (§4.1–4.2) is independent of that: the engine admits the
  superset regardless of who wrote the policy.
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

## 7. Reproduce

```bash
python -m gapfuzz audit --enforcer progent   # §4.1
python -m gapfuzz audit --enforcer janus     # §4.2 — identical table
python -m gapfuzz harm  --enforcer progent   # §4.3
python -m pytest                             # the taxonomy, pinned; 114 tests
```

No API key. No GPU. The interactive demo (`writeup/demo.html`) runs the same two
matcher semantics live in the browser.

---

*Deliverables checklist: (1) the taxonomy, proven and pinned; (2) a reusable,
engine-agnostic offline evaluator; (3) cross-engine generalization, answered
explicitly; (4) a mitigation with measured cost; (5) this honest write-up. The
one item gated on an API key — the generated-policy prevalence rate — is built
and awaiting credentials.*
