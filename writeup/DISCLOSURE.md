# Responsible disclosure — working notes

Both systems under test are real open-source projects. These are the draft
notifications to send **before** any public release, with a stated response
window (proposed: 90 days, or on fix, whichever is first). No working exploit
against a deployed instance is included; the sandboxed reproduction and the
hardening patch are.

Order: **Janus first** — it is published on PyPI advertising production use, and
its fail-open behaviours (B2/B3) are the most dangerous. Progent is a research
artifact but widely referenced.

---

## Draft — to the Janus maintainers (`janus-guard`)

> **Subject: Enforcement-gap findings in janus-guard's policy matcher, with a patch**
>
> Hi — we've been studying the enforcement layer of code-level agent policy
> engines and ran a differential audit of `janus-guard` 0.0.5 against a sound
> reference matcher. We'd like to share the findings privately before we write
> anything up, and we've included a hardening approach you're free to use.
>
> The core issue is that the matcher admits a strict superset of what a policy
> appears to allow. Concretely, in `janus/policy/validator.py` and
> `janus/policy/enforcer.py`:
>
> - `validate_argument` sends a `dict` restriction to `jsonschema.validate` with
>   no `format_checker`, so `pattern` matches unanchored (`re.search`) and
>   `format` is a no-op; and a `str` restriction to `re.match`, which is
>   prefix-only. A value like `alice@corp.com` in a `pattern` also admits
>   `evil@x.com#alice@corp.com`.
> - Schema keywords are silently ignored off-type, so
>   `{"type":"array","pattern":"^x$"}` constrains nothing.
> - `_check_conditions` guards with `if arg_name in arguments`, so a restriction
>   on an argument the caller omits is skipped, and arguments the policy never
>   names are unconstrained.
>
> We measured every "natural" policy idiom (a pinned `pattern`, a `pattern`
> without `type`, a `format`) as fully bypassable, while an exact `enum` is not.
> The same profile appears in Progent, which suggests it's architectural rather
> than specific to your code.
>
> Suggested mitigations, in order of cost: anchor `pattern` to a full match and
> treat pasted literals as `const`; enable a `format_checker` (and reject
> `format` as a sole constraint for `uri`, which has no checker); reject a schema
> whose keyword doesn't apply to its declared type; and — the higher-cost one —
> deny arguments not named by the matching allow rule (`additionalProperties:
> false` semantics), which needs to live in the matcher, not the policy. We have
> a reference implementation and a utility-cost measurement we're happy to share.
>
> Timeline: we plan to publish in [90 days / on your fix]. Glad to coordinate.

---

## Draft — to the Progent maintainers (sunblaze-ucb/progent)

> **Subject: Enforcement-matcher findings in Progent (secagent), with a patch**
>
> Hi — following on from the Progent paper, we audited the `secagent` matcher
> against a sound reference and found that it admits a superset of what generated
> policies appear to allow. Sharing privately before write-up.
>
> In `secagent/tool.py`: `check_arg` matches `dict` restrictions via
> `jsonschema.validate` (no `format_checker` → `pattern` unanchored, `format`
> inert) and `str` restrictions via `re.match` (prefix-only). `_check_tool_call`
> skips restrictions on absent arguments (`if arg_name in kwargs`) and never
> constrains unnamed ones. Two control-flow issues compound it: a forbid rule
> that raises is dropped by a bare `except: continue` (fails open), and the
> fall-through default-deny reads the *last iterated rule's* `fallback`, so an
> out-of-range value there defeats it.
>
> Separately, two things worth a look: policy denials are returned to the model
> with the full schema fragment and the user query, which discloses the
> allow-list to a compromised agent; and `security_policy_subset_check`'s z3
> backend raises `NotImplementedError` on `^`/`$` anchors, swallowed as "subset
> holds" — so anchoring a pattern (the safe thing) currently disables that check.
>
> We have a linter that closes the policy-expressible gaps (anchoring, types,
> formats) at zero measured utility cost on AgentDojo, plus a measurement of the
> cost of the matcher-level fixes. Happy to share everything. Proposed timeline:
> [90 days / on fix].

---

## What we will and won't publish

- **Will:** the taxonomy, the differential rates, the cross-engine result, the
  sandboxed AgentDojo reproductions, and the `policy_lint` fix.
- **Won't (until fixed / window elapses):** step-by-step exploit strings aimed at
  any specific deployed agent; anything that only serves to weaponise rather than
  explain.
