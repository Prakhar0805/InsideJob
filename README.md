# InsideJob

An offline audit of what "policy-as-code" guardrails for LLM agents actually enforce.

Progent and Janus secure an agent by having an LLM write a least-privilege policy and then checking every tool call against it in deterministic code. Most evaluations of this design ask whether a prompt injection can talk the agent into a bad call. I ask a narrower question about the enforcement code itself: is the set of calls the matcher admits the same as the set the policy was meant to allow?

It is not always the same, and the difference can be measured without running an agent. The core result needs no GPU, no model and no API key, and reproduces in under a minute.

## Background

[Progent](https://arxiv.org/abs/2504.11703) (UC Berkeley) introduced programmable privilege control for agents: per tool, a list of rules whose conditions are JSON Schema fragments over the arguments. Janus (`janus-guard` on PyPI) reimplements the same design with its own enforcer code. I think this is the right architecture. Putting the security decision in code rather than in a model is what makes it possible to audit at all, and this project is an attempt to do that audit carefully.

The observation is that a policy passes through two readers. The LLM (or a human) writes `pattern: "GB29NWBK..."` and means "this IBAN". The matcher hands that to `jsonschema`, where `pattern` is an unanchored `re.search`, so `GB29NWBK...-ATTACKER` also passes. This is a parser differential, the same kind of bug behind CouchDB CVE-2017-12635: two components read the same input and disagree about what it means. I am not aware of earlier work that looks at agent policy engines this way, but I may have missed some.

## What I found

All of this is reproducible offline. The full write-up is in [`writeup/FINDINGS.md`](writeup/FINDINGS.md).

**The matcher admits more than the policy says, for common ways of writing a constraint.** The sweep covers the 95 policy-relevant string arguments in AgentDojo's four suites, each written four ways (380 policy fragments). The three loose idioms (a pinned `pattern`, a `pattern` with no `type`, a bare `format`) are bypassable in every case. The exact `enum` is never bypassable. So the result is about how constraints get written, not a claim that the engine cannot enforce anything.

**The gaps fall into a small taxonomy**, each class pinned by a regression test:

- A1 to A5, matcher semantics: unanchored patterns, restrictions compiled as regex (so `.` is a wildcard), schema keywords that are silently ignored on the wrong type, `format` never checked, and arguments the policy does not name left unconstrained.
- B1 to B6, control flow: a restriction on an absent argument is skipped, the default-deny is read from the last rule's fallback field, a forbid rule that raises is dropped, and a few more.
- T1, tool side: the matcher checks the raw argument, then the tool's pydantic signature coerces it, so the value that was judged is not the value that runs.
- C1, disclosure: a denial returns the failing schema fragment to the agent, including the permitted value.

**Some admitted calls reach real harm, scored by the benchmark.** A bypass only counts when AgentDojo's own `security()` predicate says the attacker's goal was achieved. Seven email cases pass that bar: a policy that pins `recipients` to a benign address also admits `"benign@corp.com" <attacker@evil.com>`, because the matcher finds the benign address by search while `send_email`'s `EmailStr` parser delivers to the other one. Two more structural cases (a loose URL pattern and an unconstrained sibling argument) are validated the same way. Three URL cases are reported separately as modeled, because AgentDojo has no URL parser to score them against.

**Most of it carries over to Janus.** The classes that come from shared primitives (`jsonschema.validate`, `re.match`, `if arg in kwargs`) appear in both engines. Progent's fallback behaviour (B2) does not appear in Janus, and one flavour of B3 fails closed there. `python -m gapfuzz crossengine` prints the per-class comparison.

**Part of it can be fixed without touching the engine.** `policy_lint` rewrites a policy to anchor patterns, add missing types and replace unenforced formats. That closes A1 to A4, and all 96 AgentDojo user tasks still pass their own ground-truth calls. Closing A5 (denying unnamed arguments) has to happen in the matcher and costs about 12% of tasks.

**On real generated policies the picture is milder.** I generated policies with Progent's own prompt on Groq's free tier. In the 55 `openai/gpt-oss-120b` policies evaluated so far, the model mostly writes exact `enum` constraints for identifiers, and only 1 of 55 is bypassable at the value level. What remains is A5: 21 of 55 policies leave sibling arguments unconstrained.

## Reproduce

```bash
python -m venv .venv && . .venv/Scripts/activate     # .venv/bin/activate on Linux/macOS
pip install -e ./agentdojo -e ./progent && pip install -r requirements.txt

python -m gapfuzz audit --enforcer progent     # the differential sweep
python -m gapfuzz audit --enforcer strict      # sanity check: the reference against itself, 0 gaps
python -m gapfuzz harm --enforcer progent      # reachable-harm sweep
python -m gapfuzz semantic --enforcer progent  # matcher vs the tool's own parser
python -m gapfuzz crossengine                  # Progent vs Janus, per class
python -m pytest                               # 181 tests
```

No `.env` is needed for any of these. Each test in `tests/test_enforcement_gaps.py` is written as "the real engine allows X, a sound matcher denies X", so if a gap is fixed upstream the matching test starts failing.

## How it works

| Path | What it does |
|---|---|
| `src/enforcers/base.py` | the `EnforcerAdapter` protocol and the gap taxonomy |
| `src/enforcers/strict.py` | a sound reference matcher; each fix can be switched on separately, which is how a gap gets attributed to one class |
| `src/enforcers/progent.py`, `janus.py` | thin adapters over the real engines, called through their public APIs |
| `src/gapfuzz/` | mutation operators, the bypass search and the sweeps (`python -m gapfuzz`) |
| `src/harm_oracle.py` | runs a call in a fresh AgentDojo sandbox and asks the task's `security()` predicate |
| `src/tool_semantics.py` | models how each tool parses its arguments (emails, URLs, IBANs) |
| `src/policy_lint.py` | detects the gaps and repairs the ones a policy rewrite can reach |
| `src/utility_cost.py` | measures how many legitimate tasks survive the hardening |
| `src/policy_corpus.py` | generates policies with Progent's prompt; the only code that calls an API |
| `agentdojo/`, `progent/` | vendored upstream, unmodified (see `VENDOR.md`) |

`gapfuzz` never imports `secagent` or `janus` directly. Everything engine-specific sits behind `EnforcerAdapter`, so adding a third engine means writing one adapter.

A reported bypass has to clear three checks:

1. The real engine admits the call.
2. The strict reference rejects it. Otherwise the policy is simply too broad, which is not an enforcement gap.
3. AgentDojo's `security()` predicate confirms the attacker's goal in a freshly executed sandbox.

Every run also asserts that the reference never admits a call the engine denies. If that ever fails, the reference is wrong and the numbers should not be trusted.

## Limitations

- The 100% and 0% rates come from policies I constructed to isolate each idiom. They show what the matcher does with a given idiom, not how often a model writes that idiom. The generated-policy study above is the first look at prevalence. It covers one model and three suites so far.
- Only A1, A3 and A4 are measured at scale by the sweep, and C1 by the disclosure probe. The other nine classes are each pinned by a hand-built regression test. The sweep varies one string argument against one policy shape, so it cannot express them yet.
- The harm results are existence proofs on AgentDojo, not prevalence estimates.
- The strict reference is my own reading of what a policy "means". Where that reading is debatable (B4, rule priority order, is the engine's documented behaviour), the class is reported as a policy-shape hazard and not counted as an engine bug.
- This looks at one layer of one design. It says nothing about prompt injection in general.

## Status

These findings have not been reported to the Progent or Janus maintainers yet. `writeup/DISCLOSURE.md` has the per-engine notes I intend to send. Everything here runs inside AgentDojo's sandbox against synthetic tasks. Nothing targets a deployed system.

The project started as an adaptive prompt-injection study against Progent. I dropped that framing because it needed a full agent rollout per data point, which a free-tier budget cannot support, and because auditing the matcher directly gives exact answers.
