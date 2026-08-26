"""The enforcer abstraction and the catalogue of enforcement gaps.

An *enforcer* answers exactly one question: given a policy, a tool name, and a
set of arguments, would this call be permitted? That single primitive is the
whole experiment. It needs no LLM, no agent, and no network, which is why the
core result of this project reproduces in seconds.

Policies use the format both Progent and Janus adopted independently:

    {tool_name: [(priority, effect, conditions, fallback), ...]}

    priority   int   lower number = evaluated first = higher precedence
    effect     int   0 = allow, 1 = forbid
    conditions dict  {arg_name: json_schema_fragment}; {} matches everything
    fallback   int   0 = deny, 1 = terminate, 2 = ask the user

Two independent projects converging on the same tuple is the reason this
project's findings are architectural rather than one team's bug.
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

    @property
    def summary(self) -> str:
        return (self.__doc__ or "").strip()


#: Gaps that make the enforcer *more* permissive than the policy reads. These
#: are the security-relevant direction: every one is a potential bypass.
PERMISSIVE_GAPS: frozenset[GapClass] = frozenset(GapClass)


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
            "agent_visible_error": self.enforcer_verdict.agent_visible_error,
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
