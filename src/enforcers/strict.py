"""The strict reference matcher: what the policy author meant.

This is the differential baseline. It implements the *same* rule structure as
Progent and Janus — same tuples, same allow/deny precedence — but with sound
matching semantics. Every place the two disagree is an enforcement gap.

The design point that makes this scientific rather than a lump comparison:
:class:`StrictEnforcer` is parameterised by *which* gaps it fixes. Running with
a single fix enabled isolates one gap class, so every disagreement attributes
to exactly one cause instead of "somewhere in here". With all fixes on, it is
the reference semantics and doubles as the specification for
`src/policy_lint.py`'s hardening pass.

The reference must be *at least as strict* as any engine under test. That
invariant is asserted in the sweep: if the reference ever allows something an
engine denies, the reference is wrong, not the engine.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema import ValidationError as SchemaValidationError
from pydantic import TypeAdapter
from pydantic import ValidationError as PydanticValidationError

from src.enforcers.base import (
    ALLOW,
    PERMISSIVE_GAPS,
    DisclosureInstance,
    GapClass,
    Policy,
    Verdict,
    normalise_rule,
)

#: JSON Schema keywords that only bite on one instance type. When a policy
#: applies one of these to a value of a different type, the real validators
#: ignore it silently (finding A3) — the restriction reads as a constraint and
#: enforces nothing. The strict matcher treats that as a policy-authoring error
#: and denies.
TYPE_SCOPED_KEYWORDS: dict[str, tuple[type, ...]] = {
    "pattern": (str,),
    "minLength": (str,),
    "maxLength": (str,),
    "format": (str,),
    "minimum": (int, float),
    "maximum": (int, float),
    "exclusiveMinimum": (int, float),
    "exclusiveMaximum": (int, float),
    "multipleOf": (int, float),
    "minItems": (list, tuple),
    "maxItems": (list, tuple),
    "uniqueItems": (list, tuple),
    "items": (list, tuple),
    "minProperties": (dict,),
    "maxProperties": (dict,),
    "required": (dict,),
    "properties": (dict,),
    "additionalProperties": (dict,),
}

_FORMAT_CHECKER = FormatChecker()

#: Fixes on by default: the full reference semantics.
#:
#: Listed explicitly, not derived from `PERMISSIVE_GAPS`, because membership
#: here is a *promise*: every class in this set has a `fixes_gap(...)` site
#: below that changes a verdict, and `tests/test_enforcement_gaps.py` holds a
#: witness for each. Two admittance classes are deliberately absent:
#:
#: * **B4** (precedence inversion) is the engines' documented priority
#:   semantics, not a matching error. The reference orders rules exactly as
#:   they do; the hazard is a *policy shape* and `policy_lint` detects it.
#:   It used to sit in this set with no fix behind it, which made every
#:   single-fix probe for it identical to the no-fix baseline.
#: * **B6** (subset check fails open) lives in Progent's policy *update* path,
#:   which the reference does not model. It is pinned against the engine
#:   directly (`tests/test_progent_subset_check.py`).
#:
#: A disclosure class (C) describes the denial path and cannot be "fixed" by a
#: matcher, so it is absent for the same reason it is absent from
#: `PERMISSIVE_GAPS`.
ALL_FIXES: frozenset[GapClass] = frozenset(
    {
        GapClass.A1_UNANCHORED,
        GapClass.A2_RAW_REGEX,
        GapClass.A3_TYPE_SCOPED_NOOP,
        GapClass.A4_FORMAT_UNENFORCED,
        GapClass.A5_UNCONSTRAINED_SIBLINGS,
        GapClass.B1_ABSENT_ARG_SKIP,
        GapClass.B2_FALLBACK_LEAK,
        GapClass.B3_DENY_FAILS_OPEN,
        GapClass.B5_NO_POLICY_ALLOWS,
        GapClass.T1_TOOL_COERCION,
    }
)
assert ALL_FIXES <= PERMISSIVE_GAPS

#: JSON Schema scalar types the tool runtime coerces a string *into*. These are
#: the pydantic lax-mode conversions AgentDojo's `FunctionsRuntime` applies
#: (`functions_runtime.py:283`); `str` is absent because pydantic does not
#: coerce int -> str, and the differential only exists where the tool changes
#: the value's type.
_COERCERS: dict[str, TypeAdapter] = {
    "number": TypeAdapter(float),
    "integer": TypeAdapter(int),
    "boolean": TypeAdapter(bool),
}


@dataclass(frozen=True)
class ToolSchemas:
    """Declared parameter types per tool, as the tool's runtime validates them.

    Why the reference needs this: the matcher checks the *raw* argument dict,
    but AgentDojo's runtime re-validates every call through the tool's pydantic
    signature model (lax mode) before executing it. A string "5000" arrives at
    a `float` parameter as 5000.0. A restriction evaluated against the raw
    string therefore judges a value the tool never sees - gap T1. This object
    carries only the declared types, so the reference can evaluate restrictions
    against the value the tool will actually receive.

    Frozen and tuple-backed so it is hashable *by value*: attribution memoises
    reference probes on `(fixes, schemas)`, and two equal schema sets must share
    one cache entry rather than defeating the memo.
    """

    #: (tool_name, arg_name, json_schema_type) triples.
    declared: tuple[tuple[str, str, str], ...]
    _index: dict[tuple[str, str], str] = field(
        init=False, repr=False, compare=False, hash=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        index = {(tool, arg): kind for tool, arg, kind in self.declared}
        object.__setattr__(self, "_index", index)

    @classmethod
    def from_properties(cls, tools: Mapping[str, Mapping[str, Any]]) -> "ToolSchemas":
        """Build from `{tool_name: {arg_name: json_schema_fragment}}`.

        The fragment is what `Function.parameters.model_json_schema()` emits
        per property; an `anyOf` (Optional[...]) maps to its first non-null
        branch, which is the type the runtime coerces toward.
        """
        triples: list[tuple[str, str, str]] = []
        for tool_name, props in tools.items():
            for arg_name, spec in (props or {}).items():
                kind = _declared_json_type(spec)
                if kind is not None:
                    triples.append((str(tool_name), str(arg_name), kind))
        return cls(tuple(sorted(triples)))

    @classmethod
    def from_suite(cls, suite: Any) -> "ToolSchemas":
        """Build from an AgentDojo `TaskSuite` - the same schema its runtime validates with."""
        return cls.from_properties(
            {
                tool.name: tool.parameters.model_json_schema().get("properties", {})
                for tool in suite.tools
            }
        )

    def declared_type(self, tool_name: str, arg_name: str) -> str | None:
        return self._index.get((tool_name, arg_name))


def _declared_json_type(spec: Any) -> str | None:
    if not isinstance(spec, dict):
        return None
    kind = spec.get("type")
    if isinstance(kind, str):
        return kind
    if isinstance(kind, list):
        non_null = [k for k in kind if k != "null"]
        return non_null[0] if non_null else None
    for branch in spec.get("anyOf", []) or []:
        found = _declared_json_type(branch)
        if found is not None and found != "null":
            return found
    return None


def _is_bool(value: Any) -> bool:
    # bool is a subclass of int in Python; numeric keywords must not silently
    # accept True/False as 1/0 when deciding type applicability.
    return isinstance(value, bool)


def _type_matches(value: Any, types: tuple[type, ...]) -> bool:
    if _is_bool(value):
        return bool in types
    return isinstance(value, types)


@dataclass
class StrictEnforcer:
    """A sound reimplementation of the shared policy semantics.

    Args:
        fixes: which gap classes to close. Defaults to all of them (the
            reference). Pass a single class to isolate it in a differential
            sweep.
        deny_unknown_args: whether an argument the policy never mentions is a
            denial (the `additionalProperties:false` posture, gap A5). Split
            out from `fixes` because it is the one fix with a real
            false-positive cost, and the write-up reports that cost separately.
        tool_schemas: the tools' declared parameter types. Needed only by the
            T1 fix, which evaluates each restriction against the value the tool
            will receive after its runtime coerces the argument. With no
            schemas the T1 fix is a no-op, so every existing caller that
            constructs `StrictEnforcer()` is unaffected.
    """

    fixes: frozenset[GapClass] = ALL_FIXES
    deny_unknown_args: bool = True
    name: str = "strict"
    tool_schemas: ToolSchemas | None = None

    def fixes_gap(self, gap: GapClass) -> bool:
        return gap in self.fixes

    def discloses_policy(
        self,
        verdict: Verdict,
        policy: Policy,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
    ) -> DisclosureInstance | None:
        """The reference never discloses: it has no agent-facing channel.

        `Verdict.reason` here does quote patterns and argument names, but that
        string is diagnostic output for *us* - it is never handed to a model.
        The disclosure gap is a property of the channel, not of the sentence, so
        the sound matcher's answer is None by construction rather than by
        careful wording. This is also what makes `--enforcer strict` a valid
        negative control for the leak metric.
        """
        return None

    # -- public API ---------------------------------------------------------

    def would_allow(self, policy: Policy, tool_name: str, args: Mapping[str, Any]) -> Verdict:
        if policy is None:
            # B5: an unset policy is a configuration failure, not a licence.
            if self.fixes_gap(GapClass.B5_NO_POLICY_ALLOWS):
                return Verdict(False, "no policy is configured; default deny")
            return ALLOW
        if not policy:
            return Verdict(False, "policy is empty; default deny")

        rules = policy.get(tool_name)
        if not rules:
            return Verdict(False, f"no rule covers tool {tool_name!r}; default deny")

        ordered = self._order(rules)
        for rule in ordered:
            priority, effect, conditions, fallback = normalise_rule(rule)

            if effect not in (0, 1):
                # Unknown effect: the real engine skips it. An unrecognised
                # directive in a security policy must never be a no-op.
                return Verdict(False, f"unrecognised effect {effect!r} in rule; default deny")

            matched, why = self._conditions_match(conditions, args, effect=effect, tool_name=tool_name)

            if effect == 0 and matched:
                if self.deny_unknown_args and self.fixes_gap(GapClass.A5_UNCONSTRAINED_SIBLINGS):
                    unknown = [a for a in args if a not in conditions]
                    # An empty condition dict is the deliberate "allow this
                    # tool outright" idiom; it is permissive by intent, not by
                    # accident, so it is not treated as an A5 gap.
                    if unknown and conditions:
                        return Verdict(
                            False,
                            f"argument(s) {sorted(unknown)} are unconstrained by the matching "
                            f"allow rule; default deny",
                        )
                return Verdict(True, f"allowed by rule (priority={priority}): {why}")

            if effect == 1 and matched:
                return Verdict(False, f"forbidden by rule (priority={priority}): {why}")

        # B2: the default is deny, always, and is not a property of the last
        # rule's fallback field.
        if self.fixes_gap(GapClass.B2_FALLBACK_LEAK):
            return Verdict(False, "no allow rule matched; default deny")
        last_fallback = normalise_rule(ordered[-1])[3] if ordered else 0
        if last_fallback == 0:
            return Verdict(False, "no allow rule matched; default deny")
        return ALLOW

    # -- internals ----------------------------------------------------------

    def _order(self, rules: Iterable) -> list:
        """Order rules by precedence.

        Matches the engines' `(priority, -effect)` sort so the differential
        isolates *matching* semantics rather than ordering. B4 (a broad
        low-numbered allow pre-empting a specific high-numbered deny) is the
        engines' documented priority semantics applied to a badly shaped
        policy, so it is a *policy-shape hazard*: `policy_lint` detects it,
        the reference does not "fix" it, and it is deliberately absent from
        `ALL_FIXES`.
        """
        return sorted(rules, key=lambda r: (r[0], -r[1]))

    def _conditions_match(
        self,
        conditions: Mapping[str, Any],
        args: Mapping[str, Any],
        *,
        effect: int,
        tool_name: str = "",
    ) -> tuple[bool, str]:
        """Do all of a rule's conditions hold for these arguments?

        Returns (matched, explanation). Errors are *never* swallowed: gap B3 is
        precisely that the real engine treats an erroring forbid rule as
        non-matching and drops it. Here an error is a match failure for allow
        rules (fail closed) and a match for forbid rules (fail closed again).
        """
        if not conditions:
            return True, "unconditional rule"

        for arg_name, restriction in conditions.items():
            if arg_name not in args:
                # B1: the real engine skips the restriction. A constraint on an
                # argument that was not supplied cannot be satisfied.
                if self.fixes_gap(GapClass.B1_ABSENT_ARG_SKIP):
                    return False, f"argument {arg_name!r} is constrained but was not supplied"
                continue

            try:
                value = self._tool_view(tool_name, arg_name, args[arg_name])
                ok, why = self._check_value(arg_name, value, restriction)
            except Exception as exc:  # noqa: BLE001
                # B3: fail closed on either polarity.
                if self.fixes_gap(GapClass.B3_DENY_FAILS_OPEN):
                    return (effect == 1), f"error evaluating {arg_name!r} ({exc}); failing closed"
                return False, f"error evaluating {arg_name!r}: {exc}"

            if not ok:
                return False, why

        return True, "all conditions satisfied"

    def _tool_view(self, tool_name: str, arg_name: str, value: Any) -> Any:
        """The value as the tool's runtime will see it (T1).

        The engines match the raw argument; the tool then re-validates it
        through its pydantic signature in lax mode, which turns "5000" into
        5000.0 for a `float` parameter. A restriction is only meaningful
        against the value that will actually execute, so with the T1 fix on
        and the declared type known, the reference coerces first - using
        pydantic itself, so this mirrors the runtime rather than reimplementing
        it. Anything pydantic would reject is left as-is; the tool would reject
        it too.
        """
        if not self.fixes_gap(GapClass.T1_TOOL_COERCION) or self.tool_schemas is None:
            return value
        if not isinstance(value, str):
            return value
        adapter = _COERCERS.get(self.tool_schemas.declared_type(tool_name, arg_name) or "")
        if adapter is None:
            return value
        try:
            return adapter.validate_python(value)
        except PydanticValidationError:
            return value

    def _check_value(self, arg_name: str, value: Any, restriction: Any) -> tuple[bool, str]:
        if isinstance(restriction, str):
            return self._check_string_restriction(arg_name, value, restriction)
        if isinstance(restriction, dict):
            return self._check_schema(arg_name, value, restriction)
        if callable(restriction):
            return bool(restriction(value)), f"{arg_name}: predicate"
        raise NotImplementedError(f"unsupported restriction type {type(restriction)!r}")

    def _check_string_restriction(self, arg_name: str, value: Any, pattern: str) -> tuple[bool, str]:
        if not isinstance(value, str):
            # A3, string flavour: a string restriction against a non-string is
            # meaningless. The real engine raises TypeError here, which the
            # forbid branch then swallows (B3).
            return False, f"{arg_name}: string restriction applied to {type(value).__name__}"

        if self.fixes_gap(GapClass.A2_RAW_REGEX):
            # Treat a bare restriction as a literal unless it is obviously
            # intended as a pattern. A policy author writing "agent@example.com"
            # means that address, not a regex whose dots are wildcards.
            if not _looks_like_regex(pattern):
                return value == pattern, f"{arg_name}: literal comparison to {pattern!r}"

        matcher = re.fullmatch if self.fixes_gap(GapClass.A1_UNANCHORED) else re.match
        return bool(matcher(pattern, value)), f"{arg_name}: {matcher.__name__} against {pattern!r}"

    def _check_schema(self, arg_name: str, value: Any, schema: Mapping[str, Any]) -> tuple[bool, str]:
        effective = dict(schema)

        if self.fixes_gap(GapClass.A3_TYPE_SCOPED_NOOP):
            problem = _type_scoped_violation(value, effective)
            if problem is not None:
                return False, f"{arg_name}: {problem}"

        if self.fixes_gap(GapClass.A1_UNANCHORED):
            # Anchoring must reach *nested* patterns too. A policy that pins an
            # array argument writes its pattern under `items`; the sound idiom
            # for an object writes it under `properties`. An anchoring fix that
            # stopped at the top level would leave exactly the array case - the
            # one Progent's own prompt tells the model to write - unanchored,
            # and the reference would admit what the engine admits.
            effective = _anchor_nested(effective)

        if self.fixes_gap(GapClass.A5_UNCONSTRAINED_SIBLINGS) and effective.get("type") == "object":
            effective.setdefault("additionalProperties", False)

        checker = _FORMAT_CHECKER if self.fixes_gap(GapClass.A4_FORMAT_UNENFORCED) else None
        validator = Draft202012Validator(effective, format_checker=checker)
        try:
            validator.validate(value)
        except SchemaValidationError as exc:
            return False, f"{arg_name}: {exc.message}"
        return True, f"{arg_name}: satisfies schema"


#: Markers of *deliberate* regex structure. A lone `.`, `?`, or `+` inside prose
#: (e.g. "...in DM?") is almost never regex intent — treating it as one is the
#: A2 trap in reverse. Anchors, character classes, groups, and escape sequences
#: are strong signals the author meant a pattern.
_REGEX_STRUCTURE = (
    "[", "]", "(", ")", "^", "$", "|",
    r"\d", r"\w", r"\s", r"\b", r"\.", r"\A", r"\Z",
    ".*", ".+", "\\",
)


def _looks_like_regex(pattern: str) -> bool:
    """Does this restriction carry deliberate regex structure, or is it a literal?

    Used to decide whether to treat a restriction as a pattern or an exact value
    (gap A2). Conservative on purpose: prose containing an incidental `?` or `.`
    is a literal, so it is matched and hardened as one, while anything with
    anchors, classes, groups, or escapes is kept as a genuine pattern.
    """
    return any(marker in pattern for marker in _REGEX_STRUCTURE)


def _anchor(pattern: str) -> str:
    """Make a pattern match the whole value.

    `\\A`/`\\Z` rather than `^`/`$` because `$` also matches before a trailing
    newline — a value of "GOOD\\nEVIL" would otherwise satisfy an apparently
    anchored pattern.
    """
    if pattern.startswith(r"\A") and pattern.endswith(r"\Z"):
        return pattern
    body = pattern
    if body.startswith("^"):
        body = body[1:]
    if body.endswith("$") and not body.endswith(r"\$"):
        body = body[:-1]
    return rf"\A(?:{body})\Z"


_NESTED_SCHEMA_LISTS = ("anyOf", "allOf", "oneOf")


def _anchor_nested(schema: Mapping[str, Any]) -> dict[str, Any]:
    """A deep copy of `schema` with every `pattern` anchored, at any depth.

    Recurses through `items`, `properties`, `additionalProperties` (when it is
    a schema) and the `anyOf`/`allOf`/`oneOf` branch lists - the places a
    policy for a list or object argument puts its string constraints.
    """
    out = copy.deepcopy(dict(schema))

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if isinstance(node.get("pattern"), str):
            node["pattern"] = _anchor(node["pattern"])
        if isinstance(node.get("items"), dict):
            walk(node["items"])
        elif isinstance(node.get("items"), list):
            for item in node["items"]:
                walk(item)
        for nested in (node.get("properties") or {}).values():
            walk(nested)
        if isinstance(node.get("additionalProperties"), dict):
            walk(node["additionalProperties"])
        for key in _NESTED_SCHEMA_LISTS:
            for branch in node.get(key, []) or []:
                walk(branch)

    walk(out)
    return out


def _type_scoped_violation(value: Any, schema: Mapping[str, Any]) -> str | None:
    """Name the first type-scoped keyword that cannot apply to `value` (A3).

    Recurses into `items` for list values and `properties` for dict values, so
    a pattern written under `items` against a list of non-strings is caught
    the same way a top-level one is. Alternation branches (`anyOf` etc.) are
    not descended: a keyword that fails to apply in one branch may be the
    reason another branch was written, so flagging it would be a guess.
    """
    for keyword, applicable in TYPE_SCOPED_KEYWORDS.items():
        if keyword in schema and not _type_matches(value, applicable):
            return (
                f"schema uses {keyword!r} (applies to "
                f"{'/'.join(t.__name__ for t in applicable)}) against a "
                f"{type(value).__name__}; the constraint would be silently ignored"
            )
    items = schema.get("items")
    if isinstance(items, dict) and isinstance(value, (list, tuple)):
        for element in value:
            problem = _type_scoped_violation(element, items)
            if problem is not None:
                return f"items: {problem}"
    props = schema.get("properties")
    if isinstance(props, dict) and isinstance(value, dict):
        for key, sub in props.items():
            if key in value and isinstance(sub, dict):
                problem = _type_scoped_violation(value[key], sub)
                if problem is not None:
                    return f"properties.{key}: {problem}"
    return None
