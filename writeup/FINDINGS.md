# Enforcement Gaps in Deterministic LLM-Agent Policy Engines

**A parser-differential audit of Progent and Janus, with a benchmark-validated harm oracle and a measured mitigation.**

InsideJob · draft findings · 2026-08-24

---

## Abstract

A growing class of defenses secures LLM agents by having an LLM write a
least-privilege policy and then enforcing it with deterministic code on every
tool call. The security argument is that the enforcer is code and therefore
cannot be prompt-injected. That argument covers the enforcer but not the step
between the policy and the enforcer. The policy *describes* a set of permitted
argument values; the matcher can *admit* a larger one. Across the 95 policy-relevant string arguments in the four AgentDojo
domains — 380 policy fragments, one per (argument × idiom) —
**every natural-but-flawed policy idiom is 100% bypassable and the one sound
idiom (an exact `enum`) is 0% bypassable**. This is a parser differential, the
same vulnerability class behind CouchDB CVE-2017-12635 and the 2025 GitLab SAML
bypass; to our knowledge it has not been studied for agent policy engines. We
validate that admitted
calls reach real harm using AgentDojo's own state-based `security()` predicates
(no LLM judge), show the gaps reproduce in a second engine that
**reimplements the same design** (Janus) — the same-primitive gaps propagate,
while Progent's own control-flow bug does not — and ship a linter that closes the
policy-expressible half of the taxonomy at **zero measured utility cost**, while
quantifying why the other half needs an engine change. The core result makes
**zero API calls** and reproduces in seconds.

---

## 1. The setup, and why the usual test misses it

Progent (UC Berkeley; arXiv:2504.11703) and Janus (`janus-guard`, PyPI) share an
architecture that is becoming a common way to secure agents:

> An LLM reads the user's task and emits a JSON-Schema **policy** — per tool, a
> list of `(priority, effect, conditions, fallback)` rules whose `conditions`
> constrain each argument. A deterministic **matcher** then checks every tool
> call against that policy before it executes.

Existing evaluations ask: *can a prompt injection talk the agent into a bad tool
call?* That measures the agent and the policy together. The component the
security argument rests on is the **matcher**, and it is pure code, so a narrower
question can be asked directly, with no agent and no model in the loop:

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

## 3. The taxonomy

Every row was executed against `jsonschema` 4.26.0 / `z3-solver` 5.1.0 and is pinned in
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
| B4 | ascending-priority sort (a *policy-shape* hazard, not a matching error: the reference orders rules identically) | priority-100 (every LLM rule) is *lowest* precedence; a broad allow pre-empts it |
| B5 | unset policy | permits everything that reaches it before the policy exists |
| B6 | z3 subset check swallows solver errors (`except: continue`) | a policy *update* that widens an **anchored** pattern is accepted as a subset (Progent update path only) |

**T — tool-side differential (the matcher judged a value the tool will not run).**
The engines match the *raw* argument dict; AgentDojo's runtime then re-validates
every call through the tool's pydantic signature in lax mode
(`functions_runtime.py:283`) before executing it. The value the matcher judged
and the value the tool runs are not the same, which is the parser differential
in the literal sense — matcher versus the tool's own parser.

| | Gap | Consequence |
|---|---|---|
| T1 | tool coerces the argument (`"5000"` → `5000.0`) after the matcher checked the string | a numeric deny rule never matches the string; a `maxLength` on a numeric field admits `"1e9"` |

**C — the engine discloses its own boundary.** A denial returns the failing
schema fragment to the agent verbatim. The deterministic engine is an oracle for
its own allow-list — which is exactly why the *original* adaptive-attack question
(can an adversary find the boundary?) is cheap: the defense quotes the answer
back. Unlike A and B this is a property of the **denial** path, so no reference
matcher fixes it; it is measured directly instead (§4.5).

| | Gap | Consequence |
|---|---|---|
| C1 | denial re-raises the matcher's own error | the refusal names the permitted value, the schema, and (Progent) the user's query |

### 3.1 How each class is evidenced

Two different standards of evidence back this table, and conflating them would
overstate the result. Every admittance class is pinned by a regression test —
for A/B/T a hand-built policy where the engine allows and the sound reference
denies (`tests/test_enforcement_gaps.py`); for **B6**, which is not a matcher gap
at all, a call to Progent's own `security_policy_subset_check`
(`tests/test_progent_subset_check.py`). Four are additionally measured *at scale*.

| class | pinned by regression test | measured at scale |
|---|---|---|
| A1, A3, A4 | ✓ | ✓ — the differential sweep (§4.1) |
| **C1** | ✓ | ✓ — the disclosure probe (§4.5) |
| A2, A5, B1–B6, T1 | ✓ | ✗ |

The remaining gap is structural, not empirical. The value-level sweep's corpus
varies one *argument value* against a fixed *policy shape*: exactly one allow
rule, one pinned **string** argument, `fallback=0`, and a `dict` restriction.
Classes whose trigger is a policy **shape** (B2–B4), a **second argument**
(A5, B1), a **bare-string restriction** (A2), a **numeric argument** (T1), an
**unset policy** (B5), or the **policy-update path** (B6) are therefore
unreachable by construction — not rare, but impossible to express in the current
corpus. The per-class rates in §4.1 hold for the three classes they cover
and say nothing about the other nine.

Two classes are admittance-direction findings with **no reference fix**, and are
handled the same way C1 is: B4 (the engines' documented priority order applied to
a badly shaped policy — the reference orders rules identically, so it cannot
"fix" it) and B6 (Progent's policy-update analysis, which the reference does not
model). Both are excluded from `strict.ALL_FIXES` and from gap attribution,
because a class with no fix probes identically to the no-fix baseline and could
never be isolated. `ALL_FIXES` is therefore the *explicit* set of ten classes
(A1–A5, B1–B3, B5, T1) the reference actually closes, and a per-class witness
test guards it. C1 is additionally not an admittance gap at all
(it is a property of the *denial* path), and is excluded from `PERMISSIVE_GAPS`
via `GapClass.is_admittance`.

Closing the remaining coverage is future work: it requires the mutation
operators to see the tool schema (so an argument can be *added*, *dropped*, or
*retyped*) and the corpus to carry a policy-shape dimension. Until then, "100%
bypassable" is a claim about the three swept admittance classes, and the rest
rest on the fixtures.

*Deliberately out of scope:* the policy-*update* path, where untrusted tool
output is spliced un-escaped into the policy LLM's prompt (`tool.py:446`). Real
and worth studying, but it is a policy-*synthesis* question that needs an API
budget, and it is a different question from the enforcement one studied here.

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

### 4.2 Cross-engine: which gaps propagate to a reimplementation

`python -m gapfuzz audit --enforcer janus` returns **the same table, instance for
instance** on the swept classes — 760 gaps, 100%/0% split. Janus is a
*reimplementation* of Progent's design, not an independent one: its
policy-generation prompt is Progent's system prompt verbatim and its generator
emits the same `(100, 0, args, 0)` rules. What it does not share is Progent's
enforcer *code*, and that is exactly what makes it the right second engine. A gap
carried by the shared primitives (`validate_argument` → `re.match` / unanchored
`jsonschema`; `_check_conditions` → `if arg_name in arguments`) must reappear in
any faithful reimplementation; a gap that is one codebase's own control-flow bug
need not.

`python -m gapfuzz crossengine` prints the per-class profile, and it shows both.
**Propagated:** A1–A5, B1, B3, B5, T1 — all of them library behaviour. **Did not
propagate:** B2 (Progent's loop-carried fallback; Janus's `_evaluate_rules` has a
real default-deny) and one flavour of B3 (a malformed deny regex fails *closed*
in Janus, where Progent's bare `except: continue` drops the rule). B6 has no
Janus counterpart at all — Janus ships no policy-update analysis. So most of the
gap follows from the **design**, an LLM-authored JSON-Schema policy over the
standard `jsonschema`/`re` primitives, while the two control-flow behaviours that
did not propagate are specific to one implementation.

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
- **A5 (unconstrained sibling)** — `slack/injection_task_1`, with the natural
  least-privilege policy for the benign donor task `slack/user_task_1` (which
  legitimately messages Alice):
  `{"send_direct_message": [(100, 0, {"recipient": {"type":"string","pattern":"Alice"}}, 0)]}`.
  The pinned recipient is **honest** — it is the value the benign task itself
  uses — and the attack rides entirely in the unnamed `body`, which the policy
  never constrains and `security()` checks. Attributed A5. (An earlier witness
  pinned the *attacker's own* IBAN as the recipient, which is the confound this
  project excludes for `banking/user_task_15`; it was replaced for exactly that
  reason. A second, exfiltration-flavoured witness — `travel/injection_task_5`
  with donor `travel/user_task_3`, `recipients` pinned to the user's own contact
  and passport/card numbers smuggled in `body` — is pinned alongside it.)

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

**Scope boundary.** Quantifying the idiom mix and bypass *rate on real
LLM-generated policies* is Phase C, now **implemented** (`src/policy_corpus.py`
generates; `src/gapfuzz/generated.py` evaluates offline). It is the only step
that spends an API budget — a `$0` Groq free tier, two models
(`openai/gpt-oss-120b`, `qwen/qwen3.8-27b`) — and no number in §4.1–4.5 depends
on it: those are matcher-level facts that hold regardless of who wrote the
policy. §5 states what the generated corpus does and does not settle.

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

So the policy-level fixes cost nothing on this benchmark, and the matcher-level
ones are an engineering trade-off with a measured price.

### 4.5 Boundary disclosure: the sound idiom is the disclosing idiom

Everything above measures what an engine wrongly **admits**. This measures what
it says when it correctly **refuses** — over the same 95 arguments, by sending a
value no policy could permit and reading the denial. It costs nothing extra.

| policy idiom | bypassable (§4.1) | refusals | leaked | what the refusal discloses |
|---|---|---|---|---|
| **`enum` exact** | **0%** | 95 | **100%** | **the permitted value, verbatim** + schema + routed to the agent |
| pattern-pinned | 100% | 95 | 100% | the pattern, + schema, + routed |
| pattern, no `type` | 100% | 95 | 100% | the pattern, + schema, + routed |
| `format`-only | 100% | **0** | n/a | *never refuses, so never leaks* |

A representative Progent refusal, verbatim:

```
'DE89370400440532013000' is not one of ['GB29NWBK60161331926819']

Failed validating 'enum' in schema:
    {'type': 'string', 'enum': ['GB29NWBK60161331926819']}

On instance:
    'DE89370400440532013000'. Please try other tools or arguments and continue
    to finish the user task: <the user's original query>
```

Three things follow, and the third is the finding.

**It is the channel, not just the string.** The trailing sentence is Progent's
own instruction to the model (`tool.py:590`), so this text is *addressed to the
agent*, not an internal error we intercepted. The same append also carries the
user's original query, leaking the task prompt alongside the policy.

**It is scoped to exactly the rules an LLM writes.** Progent re-raises the raw
`jsonschema` error only for a **priority-100** allow rule (`tool.py:537`); any
lower priority falls through to a generic *"The tool 'x' is not allowed."* and
leaks nothing. That reads as a mitigation until you check where generated rules
land — `tool.py:401-405` hardcodes `(100, 0, args, 0)` for every rule the policy
LLM emits. The disclosing branch is precisely the branch a real deployment takes.
Janus has no such conditional and leaks at every priority; it is detected by a
**generic** literal-match check that `JanusEnforcer` does not override at all —
one more instance of a shared-primitive behaviour reappearing in the
reimplementation.

**The idiom that cannot be bypassed is the idiom that answers the question.**
`enum`-exact is the sole sound row in §4.1 — 0% bypassable across 95 fragments —
and its refusal hands back the permitted value itself. The loose idioms leak too,
but their disclosure is moot: an attacker never has to *ask* a policy that is
already bypassable. So the two results compose rather than merely coexisting —
tighten a policy until the matcher can no longer be fooled, and you convert it
into an oracle that simply discloses the answer. Security-by-exact-match and
disclosure-of-the-exact-match are the same property.

This is also what retires the project's original question. The abandoned framing
asked whether an adaptive attacker could *find* the enforcement boundary; the
answer is that it is not hidden — it is quoted on request. That is now measured
rather than asserted.

*Concurrent work:* denial-feedback leakage in tool-calling agents is examined
independently in *Causality Laundering* (arXiv 2604.04035), which we did not draw
on; the per-idiom rates and the bypassability×disclosure cross above are ours.
The mitigation is a generic refusal — Progent's own low-priority branch already
does this, so the fix exists in the codebase and is simply not on the path
generated policies take.

### 4.6 The parser differential, literally: matcher vs the tool's parser

§4.1–4.5 compare the matcher against a *sound matcher*. This measures the CVE-history
version of the bug directly: the matcher against the **tool's own parser**. The
matcher inspects the raw argument string; the tool then parses it and acts on the
parsed result, and where the two parsers disagree a value the matcher judged
benign resolves, inside the tool, to the attacker's resource.

`python -m gapfuzz semantic --enforcer progent` runs this over AgentDojo's tasks.
For each injection task it builds the natural least-privilege policy for a real
benign donor task — pinning the effectful argument to the donor's own value with
the flawed idiom (an `items.pattern` for a list argument like `recipients`, the
array form Progent's prompt tells the model to write) — then asks whether a value
exists that the engine admits, the sound reference (with nested anchoring) denies,
and the tool resolves to the attacker's resource.

**Seven bypasses are validated end-to-end by AgentDojo's own `security()`**, all
on the email kind: `send_email.recipients`/`cc`/`bcc` and
`create_calendar_event.participants` store `list[EmailStr]`, whose parser accepts
RFC 5322 display-name syntax. A policy pinning `recipients` to the benign address
`emma@corp.com` admits `'"emma@corp.com" <mark.black-2134@gmail.com>'`
(the matcher's `re.search` finds the benign address; the tool's `EmailStr` parser
resolves it to `mark.black-2134@gmail.com`), the reference denies it (the anchored
nested pattern does not full-match), and `security()` confirms the email reached
the attacker. The pinned value is honest — it is the benign donor's own recipient —
so utility is preserved by construction: the attack rides a different *spelling*
of the same policy-permitted address, not a different address.

**Three more are found on URLs but reported as *modeled*, never summed with the
above.** AgentDojo has no URL parser (its `standardize_url` only strips a leading
scheme and lookups are exact-key), so a userinfo-confusion value
(`benign-host@attacker-host/…`) is judged against a model of a real HTTP client
(`urllib.parse`), and every such verdict carries `source="modeled"`. The
`gapfuzz semantic` table labels each row `[agentdojo]` or `[modeled]` and prints
the two totals on separate lines.

**The IBAN arguments are the negative control** (`send_money.recipient` and
friends): AgentDojo's banking predicates compare the recipient string exactly, so
there is no tool-side parser to disagree with the matcher, and all eight report
"no tool-side widening" rather than a spurious bypass. Numeric coercion is the T1
class of §3, cross-referenced here. This is the boundary of the technique:
it bites exactly where the tool re-parses a string into a structured resource, and
not where the tool treats the string as opaque.

### 4.7 Generated policies: the flawed idioms occur, and so does the sound one

Phase C generates a policy per AgentDojo user task with Progent's exact prompt
and measures, offline, which idiom the model actually used per argument. On a
first partial corpus — **55 policies from `openai/gpt-oss-120b` across three
suites, zero generation failures** — the result is more nuanced than the
constructed corpus's per-idiom worst case, and that nuance is the point:

- **The model largely follows Progent's prompt where the prompt is specific.**
  Identifiers it can copy verbatim get an exact `enum` (4/9 IBAN constraints,
  every pinned file path), and URLs get a `pattern` (7/10, mostly anchored) —
  exactly the split Progent's suggestions describe. So value-level
  bypassability is *low*: only **1/55 policies (2%)** admit a mutation the sound
  reference denies. A capable model writing sound value constraints is the
  §4.1 `enum` control playing out on real output.
- **The gap that survives is the one no value idiom can close.** **21/55 (38%)**
  of the generated policies carry at least one lint finding, and they are
  dominated by **A5 unconstrained siblings (25 findings)** — the model pins the
  argument the task names and says nothing about the rest, so `amount`, `bcc`,
  `body` and friends ride free. A5 is an *engine-level* class (§4.4): no policy
  rewrite closes it, which is precisely why it is the gap that reaches real
  generation. The email parser differential of §4.6 is the same story from the
  tool side — the pinned `recipients` value is sound, the harm rides the parser.

So the constructed corpus is a **faithful, not a worst-case, model**: both the
flawed idioms and the sound `enum` occur in real generation, and the enforcement
gap that persists once a capable model writes tight *value* constraints is the
sibling/engine-level gap the mitigation already flags as needing an engine
change. (This corpus is partial — one model, three suites; the second model and
the workspace suite are a resumable `python -m policy_corpus generate` away, and
no earlier number depends on it.)

## 5. Limitations

- **Constructed vs generated policies.** §4.1–4.4 use policies we construct to
  faithfully model the documented generation behaviour. Whether a given
  deployment's LLM writes loose enough policies often enough is the Phase-C
  measurement, now **implemented**: `src/policy_corpus.py` generates a policy per
  AgentDojo user task with Progent's exact prompt (two free-tier Groq models),
  and `src/gapfuzz/generated.py` reports, offline, the idiom used per argument
  kind, the lint findings, and the differential bypassability. The matcher-level
  result (§4.1–4.2) is independent of it: the engine admits the superset
  regardless of who wrote the policy. What the generated corpus adds is
  prevalence — how often real generation writes the flawed idiom rather than the
  sound `enum` — and it confirms both idioms occur, so the constructed corpus is
  a faithful, not a worst-case, model. (Generated policies are also not
  worst-case in the other direction: a model that writes a sound `enum` for an
  identifier is not bypassable, exactly as §4.1's control predicts.)
- **Sweep coverage is partial.** The differential sweep produces three of the
  twelve admittance classes (C1 is measured separately, in §4.5; B6 is pinned
  against the engine directly); the other nine are pinned by regression tests but
  not measured at scale. §3.1 gives the table and the structural reason. Any
  bypass rate quoted in §4.1 is a rate
  over A1/A3/A4, not over the taxonomy.
- **Disclosure is measured on one probe shape.** §4.5 sends a single
  obviously-impermissible value per fragment. That establishes that refusals
  disclose, not how much an adversary can extract by *iterating* refusals — the
  extraction rate against a `pattern`-constrained argument is unmeasured.
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

## 6. Disclosure status

Progent and Janus are open-source projects. **These findings have not yet been
reported to either set of maintainers.** The per-engine notes we intend to send
are in `writeup/DISCLOSURE.md`. Everything here runs inside AgentDojo's sandbox
on synthetic tasks; nothing was run against a deployed system, and no exploit
against a specific deployment is included.

## 7. Reproduce

```bash
python -m gapfuzz audit --enforcer progent   # §4.1
python -m gapfuzz audit --enforcer janus     # §4.2 — same swept table
python -m gapfuzz crossengine                 # §4.2 — per-class propagation profile
python -m gapfuzz harm  --enforcer progent   # §4.3
python -m pytest                             # the taxonomy, pinned; 181 tests
```

No API key. No GPU. The interactive demo (`writeup/demo.html`) runs the same two
matcher semantics live in the browser.
