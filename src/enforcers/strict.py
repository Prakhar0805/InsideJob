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

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema import ValidationError as SchemaValidationError

from src.enforcers.base import ALLOW, GapClass, Policy, Verdict, normalise_rule

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
ALL_FIXES: frozenset[GapClass] = frozenset(GapClass)


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
    """

    fixes: frozenset[GapClass] = ALL_FIXES
    deny_unknown_args: bool = True
    name: str = "strict"

    def fixes_gap(self, gap: GapClass) -> bool:
        return gap in self.fixes

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

            matched, why = self._conditions_match(conditions, args, effect=effect)

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
        low-priority allow pre-empting a specific high-numbered deny) is a
        property of the policy, so it is detected by the sweep as a
        policy-shape finding rather than reimplemented here.
        """
        return sorted(rules, key=lambda r: (r[0], -r[1]))

    def _conditions_match(
        self, conditions: Mapping[str, Any], args: Mapping[str, Any], *, effect: int
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
                ok, why = self._check_value(arg_name, args[arg_name], restriction)
            except Exception as exc:  # noqa: BLE001
                # B3: fail closed on either polarity.
                if self.fixes_gap(GapClass.B3_DENY_FAILS_OPEN):
                    return (effect == 1), f"error evaluating {arg_name!r} ({exc}); failing closed"
                return False, f"error evaluating {arg_name!r}: {exc}"

            if not ok:
                return False, why

        return True, "all conditions satisfied"

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
            for keyword, applicable in TYPE_SCOPED_KEYWORDS.items():
                if keyword in effective and not _type_matches(value, applicable):
                    return (
                        False,
                        f"{arg_name}: schema uses {keyword!r} (applies to "
                        f"{'/'.join(t.__name__ for t in applicable)}) against a "
                        f"{type(value).__name__}; the constraint would be silently ignored",
                    )

        if self.fixes_gap(GapClass.A1_UNANCHORED) and isinstance(effective.get("pattern"), str):
            effective["pattern"] = _anchor(effective["pattern"])

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
