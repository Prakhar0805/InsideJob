"""The enforcer abstraction and the catalogue of enforcement gaps.

An *enforcer* answers exactly one question: given a policy, a tool name, and a
set of arguments, would this call be permitted? That single primitive is the
whole experiment. It needs no LLM, no agent, and no network, which is why the
core result of this project reproduces in seconds.

Policies use the format Progent defined and Janus reimplemented:

    {tool_name: [(priority, effect, conditions, fallback), ...]}

    priority   int   lower number = evaluated first = higher precedence
    effect     int   0 = allow, 1 = forbid
    conditions dict  {arg_name: json_schema_fragment}; {} matches everything
    fallback   int   0 = deny, 1 = terminate, 2 = ask the user

Janus is not an independent design: its policy-generation prompt is Progent's
system prompt verbatim and its generator emits the same ``(100, 0, args, 0)``
rules. What makes the findings a property of the *design* rather than one
codebase is which gaps propagated through that reimplementation and which did
not: every gap that lives in the shared primitives (``jsonschema.validate``,
``re.match``, ``if arg in kwargs``) reappears in Janus, while Progent's
code-level control-flow bug (B2) does not. See ``src/gapfuzz/crossengine.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

#: One rule: (priority, effect, conditions, fallback). Some engines append a
#: fifth element; adapters normalise that away.
Rule = tuple
#: ``None`` means *no policy configured* - distinct from ``{}`` (deny all).
Policy = dict[str, list[Rule]] | None


class GapClass(str, Enum):
    """Enforcement gaps, each independently verified against the real engine.

    Codes match the write-up's taxonomy so a finding in the logs, a test name,
    and a table row in the paper are all the same identifier.
    """

    # --- A: matcher semantics. The admitted set is larger than the policy reads.
    A1_UNANCHORED = "A1_unanchored"
    """`re.match` is prefix-only; JSON Schema `pattern` is `re.search`. A value
    whose *matching* part is benign and whose *effective* part is not passes."""

    A2_RAW_REGEX = "A2_raw_regex"
    """Restrictions are compiled as regex, not literals: the `.` in
    "agent@example.com" is a wildcard, so "agentXexample.com" matches."""

    A3_TYPE_SCOPED_NOOP = "A3_type_scoped_noop"
    """JSON Schema keywords are type-scoped and silently ignored off-type.
    `{"type":"array","pattern":"^x$"}` constrains nothing at all."""

    A4_FORMAT_UNENFORCED = "A4_format_unenforced"
    """`format` is recommended to the policy LLM but validated without a
    format_checker, so it is a pure annotation: `format:"email"` admits
    anything."""

    A5_UNCONSTRAINED_SIBLINGS = "A5_unconstrained_siblings"
    """Only arguments the policy names are checked. No `required`, no
    `additionalProperties:false`; every other argument is free."""

    # --- B: control flow. The engine allows where it should deny.
    B1_ABSENT_ARG_SKIP = "B1_absent_arg_skip"
    """`if arg_name in kwargs` — a restriction on an argument that was not
    passed is skipped entirely."""

    B2_FALLBACK_LEAK = "B2_fallback_leak"
    """`fallback` is loop-carried, so the fall-through default-deny is governed
    by whatever value the last rule happened to hold. Out-of-range = allow."""

    B3_DENY_FAILS_OPEN = "B3_deny_fails_open"
    """A bare `except: continue` around forbid-rule evaluation. Any error —
    type mismatch, malformed regex, throwing predicate — deletes the rule."""

    B4_PRECEDENCE_INVERSION = "B4_precedence_inversion"
    """Sorting by ascending priority makes priority-100 (all LLM-generated)
    rules *lowest* precedence, so a broad low-numbered allow pre-empts them."""

    B5_NO_POLICY_ALLOWS = "B5_no_policy_allows"
    """An *unset* policy permits everything (an empty one correctly denies). The
    hazard is ordering: a tool call arriving before the policy is established
    runs unprotected."""

    B6_SUBSET_CHECK_FAILS_OPEN = "B6_subset_check_fails_open"
    """Progent's z3 policy-narrowing check (`security_policy_subset_check`)
    swallows every solver exception as "no counterexample", so a policy update
    that *widens* an **anchored** pattern is accepted as a subset. Anchoring is
    exactly what a sound policy does, so hardening a policy silently disables
    the check. Progent-only (Janus has no update-path analysis); pinned, not
    swept; no reference fix, because the reference has no update path."""

    # --- T: tool-side differential. The tool parses the value differently
    # from the matcher, so a value the matcher judged is not the value the tool
    # acts on. This is the parser differential in the literal sense.
    T1_TOOL_COERCION = "T1_tool_coercion"
    """The matcher checks the raw argument dict; the tool's runtime re-validates
    it through the tool's own signature (pydantic, lax mode) before executing.
    A string "5000" reaches a `float` parameter as 5000.0, so a numeric deny
    rule never matches the string and a string-typed constraint (`maxLength`)
    admits "1e9". Fixed in the reference only when it is told the tool's
    declared parameter types (`StrictEnforcer.tool_schemas`)."""

    # --- C: the engine discloses its own boundary.
    C1_BOUNDARY_DISCLOSURE = "C1_boundary_disclosure"
    """A denial hands the agent the policy it just failed, so every refusal is a
    free query against the allow-list.

    Structurally unlike A and B: those describe the engine *admitting* more than
    the policy reads, and each is closed by a matcher fix. This one is a property
    of the **denial** path, which by construction admits nothing. No reference
    matcher "fixes" it, so it is excluded from `PERMISSIVE_GAPS` and never enters
    attribution - see :attr:`is_admittance`."""

    @property
    def summary(self) -> str:
        return (self.__doc__ or "").strip()

    @property
    def is_admittance(self) -> bool:
        """Does this class describe the engine ADMITTING more than written?

        The A and B families do; C does not. This one predicate is what keeps a
        disclosure finding out of `StrictEnforcer`'s fix set, out of gap
        attribution, and out of the bypass-rate table, while still letting it
        share the single taxonomy namespace - so a log line, a test name, and a
        row in the paper remain the same identifier.
        """
        return not self.value.startswith("C")


#: Gaps that make the enforcer *more* permissive than the policy reads. These
#: are the security-relevant direction: every one is a potential bypass.
#: Disclosure (C) is deliberately absent: it is real, but it is not an
#: admittance gap. NOTE: not every member has a reference fix. The subset the
#: strict matcher can actually close is `src.enforcers.strict.ALL_FIXES`; B4 is
#: a policy-shape hazard the linter detects, and B6 lives in Progent's policy
#: *update* path, which the reference does not model. Keeping the two sets
#: distinct is what stops a no-op "fix" from hiding in the attribution loop.
PERMISSIVE_GAPS: frozenset[GapClass] = frozenset(g for g in GapClass if g.is_admittance)


@dataclass(frozen=True)
class Verdict:
    """The outcome of one policy check."""

    allowed: bool
    reason: str = ""
    #: What the engine would hand back to the agent on a denial. Captured
    #: because Progent's denial messages disclose the policy itself (finding
    #: C1) — the text is evidence, not just a log line.
    agent_visible_error: str = ""

    def __bool__(self) -> bool:
        return self.allowed


ALLOW = Verdict(allowed=True, reason="permitted")


def policy_literals(policy: Policy, tool_name: str) -> set[str]:
    """Every concrete value a policy names for one tool.

    This is the set a denial must not echo. It is what an attacker would
    otherwise have to *search* for: the permitted IBAN, the allowed URL, the
    pinned recipient. `enum` members and `const` values are literals outright; a
    `pattern` is included because in this family patterns are routinely pasted
    literals rather than generalising regexes (Progent's own prompt tells the
    model to pin explicit identifiers), so leaking the pattern usually leaks the
    value. Bare-string restrictions are literals by definition.

    Recurses into `properties` and `items` so a nested object schema does not
    hide its literals from the check.
    """
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, str):
            if node:
                found.add(node)
            return
        if not isinstance(node, dict):
            return
        for key in ("pattern", "const"):
            value = node.get(key)
            if isinstance(value, str) and value:
                found.add(value)
        for value in node.get("enum", []) or []:
            if isinstance(value, str) and value:
                found.add(value)
        for nested in (node.get("properties") or {}).values():
            walk(nested)
        if isinstance(node.get("items"), dict):
            walk(node["items"])
        for branch in node.get("anyOf", []) or []:
            walk(branch)

    for rule in (policy or {}).get(tool_name, []):
        if len(rule) < 4:
            continue
        for restriction in (rule[2] or {}).values():
            walk(restriction)
    return found


@dataclass
class DisclosureInstance:
    """Evidence that a *denial* handed the policy back to the agent (C1).

    The dual of :class:`GapInstance`, and deliberately a separate type. A
    `GapInstance` requires ``enforcer_verdict.allowed`` to be True - that
    invariant is what makes it evidence of a permissive gap. Disclosure is only
    ever observable on the opposite branch, so folding it into `GapInstance`
    would either bend that invariant or (as the code did before) serialize a
    denial-only field on records that can never carry one. Same currency,
    opposite verdict, two record types.
    """

    enforcer: str
    tool_name: str
    policy: Policy
    args: dict[str, Any]
    #: Verbatim text the engine would hand back to the agent.
    denial_text: str
    #: Policy literals found verbatim inside `denial_text`.
    leaked_literals: list[str]
    #: How many literals the policy named for this tool, leaked or not.
    total_literals: int = 0
    #: True when the engine additionally dumps the schema fragment itself, i.e.
    #: discloses the *structure* of the constraint and not just its values.
    discloses_schema: bool = False
    #: True when the leaked text carries the engine's own agent-facing marker,
    #: proving it is routed to the model rather than only to a log.
    agent_routed: bool = False
    note: str = ""
    gap_class: GapClass = GapClass.C1_BOUNDARY_DISCLOSURE

    @property
    def leaked(self) -> bool:
        return bool(self.leaked_literals) or self.discloses_schema

    @property
    def leak_fraction(self) -> float:
        """Share of the policy's literals for this tool that the denial echoed."""
        if not self.total_literals:
            return 0.0
        return len(self.leaked_literals) / self.total_literals

    def as_dict(self) -> dict[str, Any]:
        return {
            "gap_class": self.gap_class.value,
            "enforcer": self.enforcer,
            "tool_name": self.tool_name,
            "policy": _jsonable_policy(self.policy),
            "args": self.args,
            "denial_text": self.denial_text,
            "leaked_literals": sorted(self.leaked_literals),
            "total_literals": self.total_literals,
            "leak_fraction": round(self.leak_fraction, 4),
            "discloses_schema": self.discloses_schema,
            "agent_routed": self.agent_routed,
            "note": self.note,
        }


class BaseEnforcer:
    """Shared, engine-agnostic disclosure detection.

    Adapters inherit this and override nothing unless their engine has an
    engine-specific tell. That is the point: the check asks only "does the text
    the agent receives contain the policy's own literals?", which is true of any
    engine that surfaces its matcher's error - i.e. every engine in this family.
    Janus is covered by this class with zero Janus-specific code, which is the
    cross-engine claim made structurally rather than asserted.
    """

    #: Set by an adapter whose engine also dumps the failing schema fragment.
    def _discloses_schema(self, text: str) -> bool:
        return False

    #: Set by an adapter that can prove the text is routed to the agent.
    def _agent_routed(self, text: str) -> bool:
        return False

    def discloses_policy(
        self,
        verdict: Verdict,
        policy: Policy,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
    ) -> DisclosureInstance | None:
        """Did this denial leak the policy? Returns the evidence, or None.

        An *allow* is never a disclosure - there is no denial text - so this
        returns None rather than an empty instance, keeping "no leak" and "not
        applicable" from being confused in the aggregate.
        """
        if verdict.allowed:
            return None
        text = verdict.agent_visible_error
        if not text:
            return None
        literals = policy_literals(policy, tool_name)
        leaked = sorted(value for value in literals if value in text)
        schema = self._discloses_schema(text)
        if not leaked and not schema:
            return None
        return DisclosureInstance(
            enforcer=getattr(self, "name", "unknown"),
            tool_name=tool_name,
            policy=policy,
            args=dict(args or {}),
            denial_text=text,
            leaked_literals=leaked,
            total_literals=len(literals),
            discloses_schema=schema,
            agent_routed=self._agent_routed(text),
        )


@runtime_checkable
class EnforcerAdapter(Protocol):
    """What every policy engine under test must provide.

    Deliberately tiny. `gapfuzz` talks only to this, and never imports
    `secagent` or `janus` directly — that is what makes adding a second engine
    a config change instead of a rewrite.
    """

    name: str

    def would_allow(self, policy: Policy, tool_name: str, args: Mapping[str, Any]) -> Verdict:
        """Would this call be permitted under this policy? Must not mutate state."""
        ...

    def discloses_policy(
        self,
        verdict: Verdict,
        policy: Policy,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
    ) -> DisclosureInstance | None:
        """Did this denial hand the policy back to the agent (C1)? Evidence or None."""
        ...


@dataclass
class GapInstance:
    """One concrete disagreement between an engine and the strict reference.

    A `GapInstance` is the atomic unit of evidence: it names the gap class, the
    exact policy and call that trigger it, and what each side decided. Every
    number in the write-up aggregates these, and every one can be replayed.
    """

    gap_class: GapClass
    enforcer: str
    tool_name: str
    policy: Policy
    args: dict[str, Any]
    enforcer_verdict: Verdict
    strict_verdict: Verdict
    note: str = ""
    #: How :mod:`src.gapfuzz.attribution` reached ``gap_class`` (``isolated``,
    #: ``over-determined``, ``leave-one-out``, ``unattributed``). Recorded so an
    #: aggregate can report *how cleanly* the taxonomy separated, not just the
    #: per-class counts.
    attribution_method: str = "isolated"
    #: When more than one fix independently denies the call, every contender.
    #: ``gap_class`` is the enum-lowest of these; this set keeps the rest visible
    #: instead of silently dropping them.
    co_attributed: frozenset[GapClass] = frozenset()

    @property
    def is_permissive(self) -> bool:
        """True when the engine allowed something the reference would deny.

        The only direction that matters for security. The reverse (engine
        stricter than reference) means our reference is wrong and is asserted
        against, not reported.
        """
        return self.enforcer_verdict.allowed and not self.strict_verdict.allowed

    def as_dict(self) -> dict[str, Any]:
        return {
            "gap_class": self.gap_class.value,
            "enforcer": self.enforcer,
            "tool_name": self.tool_name,
            "policy": _jsonable_policy(self.policy),
            "args": self.args,
            "enforcer_allowed": self.enforcer_verdict.allowed,
            "strict_allowed": self.strict_verdict.allowed,
            "enforcer_reason": self.enforcer_verdict.reason,
            "strict_reason": self.strict_verdict.reason,
            # `agent_visible_error` is deliberately NOT serialized here. A
            # GapInstance requires the engine to have ALLOWED, and adapters only
            # populate that field on the deny branch - so it was empty on every
            # row ever written, implying "nothing leaked" when the real answer
            # was "this record cannot observe a leak". Disclosure evidence lives
            # on DisclosureInstance, whose verdict is a denial.
            "attribution_method": self.attribution_method,
            "co_attributed": sorted(g.value for g in self.co_attributed),
            "note": self.note,
        }


def _jsonable_policy(policy: Policy) -> dict[str, Any]:
    """Policies can hold callables and tuples; make them loggable."""
    out: dict[str, Any] = {}
    for tool, rules in (policy or {}).items():
        out[tool] = [
            {
                "priority": r[0],
                "effect": r[1],
                "conditions": _jsonable(r[2]),
                "fallback": r[3],
            }
            for r in rules
            if len(r) >= 4
        ]
    return out


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def normalise_rule(rule: Sequence) -> tuple[int, int, dict, int]:
    """Coerce a rule of any supported arity to `(priority, effect, conditions, fallback)`.

    Progent supports a 5-tuple whose extra element carries a policy *rewrite*
    to install on match. The strict reference deliberately ignores it: silently
    swapping the policy mid-check is the behaviour under test, not a semantic
    the reference should reproduce.
    """
    priority, effect, conditions, fallback = rule[0], rule[1], rule[2], rule[3]
    return int(priority), int(effect), dict(conditions or {}), int(fallback)
