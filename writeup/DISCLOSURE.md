# Notes for the maintainers

**Status: nothing has been sent yet.** These are the per-engine summaries I
intend to send to the Progent and Janus maintainers. They are kept here so the
repository says exactly what has and has not been reported.

Both engines are open-source research and library code. Everything in this
repository runs inside AgentDojo's sandbox on synthetic tasks; nothing was run
against a deployed system, and no exploit against a specific deployment is
included.

---

## Janus (`janus-guard` 0.0.5)

In `janus/policy/validator.py` and `janus/policy/enforcer.py`:

- `validate_argument` sends a `dict` restriction to `jsonschema.validate` with
  no `format_checker`, so `pattern` matches unanchored (`re.search`) and
  `format` is not checked. A `str` restriction goes to `re.match`, which is
  prefix-only. A `pattern` of `alice@corp.com` also admits
  `evil@x.com#alice@corp.com`.
- Schema keywords are ignored on the wrong type, so
  `{"type":"array","pattern":"^x$"}` constrains nothing.
- `_check_conditions` guards with `if arg_name in arguments`, so a restriction
  on an argument the caller omits is skipped, and arguments the policy never
  names are unconstrained.

In the sweep, every loose idiom (a pinned `pattern`, a `pattern` without
`type`, a `format`) is bypassable and an exact `enum` is not. Progent shows the
same profile on these classes, which points at the shared primitives and not at
Janus's own code.

Possible mitigations, cheapest first:

1. Anchor `pattern` to a full match and treat pasted literals as `const`.
2. Enable a `format_checker`, and do not accept `format` as the only constraint
   for `uri`, which has no checker.
3. Reject a schema whose keyword does not apply to its declared type.
4. Deny arguments not named by the matching allow rule
   (`additionalProperties: false` semantics). This one has to live in the
   matcher and has a utility cost (about 12% of AgentDojo tasks in my
   measurement).

---

## Progent (`secagent`, sunblaze-ucb/progent at `8a8eb89`)

In `secagent/tool.py`:

- `check_arg` matches `dict` restrictions via `jsonschema.validate` with no
  `format_checker` (so `pattern` is unanchored and `format` is not checked) and
  `str` restrictions via `re.match` (prefix-only).
- `_check_tool_call` skips restrictions on absent arguments
  (`if arg_name in kwargs`) and does not constrain unnamed ones.
- A forbid rule that raises during evaluation is dropped by a bare
  `except: continue`.
- The fall-through default reads the last iterated rule's `fallback`, so an
  out-of-range value there results in an allow.

Two further observations:

- A denial at priority 100 returns the failing schema fragment and the user
  query to the model, which tells a compromised agent what the allow-list is.
  The lower-priority branch already returns a generic refusal.
- `security_policy_subset_check`'s z3 backend raises on `^`/`$`/`\A`/`\Z`
  anchors, and `solve_schema` treats the swallowed error as "no counterexample".
  An update that widens an anchored pattern (`^GOOD$` to `^.*$`) is accepted as
  a narrowing. This interacts badly with my own `policy_lint`, which anchors
  every pattern (see `tests/test_progent_subset_check.py`).

`policy_lint` closes the policy-expressible gaps (anchoring, types, formats)
with no measured utility cost on AgentDojo. The matcher-level fixes and their
cost are in `FINDINGS.md` §4.4.

---

## What is and is not in this repository

- Included: the taxonomy, the differential rates, the cross-engine comparison,
  the sandboxed AgentDojo reproductions, and the `policy_lint` fix.
- Not included: anything aimed at a specific deployed agent.
