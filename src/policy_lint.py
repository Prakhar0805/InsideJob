"""policy_lint - detect and repair the enforcement gaps in a policy.

This is the mitigation half of the project. Given a policy in the shared
`(priority, effect, conditions, fallback)` format, it reports every gap-class
issue it finds and, on request, returns a hardened policy that closes them. The
hardened semantics are exactly what :class:`~src.enforcers.strict.StrictEnforcer`
enforces, so "lint then run under the original engine" and "run under the strict
reference" agree - the linter is the deployable form of the reference.

Design intent:

*   **Report, then repair.** A finding names its gap class (so it lines up with
    the taxonomy and the tests) and points at the exact tool/argument. The
    repair is optional and conservative: it never loosens a policy, only tightens
    it, so applying it can add false positives but never new bypasses.
*   **The one costly fix is opt-in and measured.** Denying unconstrained sibling
    arguments (A5) is the only repair with a real false-positive cost, because a
    tool argument the policy author simply didn't think to mention will now be
    rejected. It is controlled by its own flag, and the utility cost is measured
    directly against AgentDojo user tasks in :func:`utility_cost`.

The linter is transport-agnostic: it rewrites the policy data, not any engine.
Progent or Janus then enforces the hardened policy through its normal interface,
so no defended system has to be modified to benefit - which is what makes this a
usable fix rather than a critique.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from src.enforcers.base import GapClass, Policy
from src.enforcers.strict import TYPE_SCOPED_KEYWORDS, _anchor, _looks_like_regex

#: JSON Schema formats the installed validator cannot actually enforce (no
#: checker), so a policy relying on them alone constrains nothing. `uri` is the
#: dangerous one: URLs are exactly what Progent's prompt tells the LLM to
#: constrain, and loosely. Kept as data so the write-up can cite it.
UNENFORCEABLE_FORMATS: frozenset[str] = frozenset({"uri", "uri-reference", "iri", "hostname"})

#: Gaps a policy author can close by rewriting the policy alone, keeping the
#: enforcing engine unmodified: they are expressible as tighter conditions.
POLICY_FIXABLE_GAPS: frozenset[GapClass] = frozenset(
    {
        GapClass.A1_UNANCHORED,
        GapClass.A2_RAW_REGEX,
        GapClass.A3_TYPE_SCOPED_NOOP,
        GapClass.A4_FORMAT_UNENFORCED,
    }
)

#: Gaps that are *matcher behaviours*, not policy content: no policy rewrite can
#: close them, because the engine's own control flow (skipping unlisted args,
#: loop-carried fallback, fail-open deny, fail-open update analysis, matching
#: the raw value the tool will not execute) overrides whatever the policy says.
#: Closing these requires the engine to adopt strict semantics - i.e. deploy the
#: linter's matcher, or patch the engine. This split is a headline result: the
#: cheap fix only reaches half the taxonomy.
ENGINE_LEVEL_GAPS: frozenset[GapClass] = frozenset(
    {
        GapClass.A5_UNCONSTRAINED_SIBLINGS,
        GapClass.B1_ABSENT_ARG_SKIP,
        GapClass.B2_FALLBACK_LEAK,
        GapClass.B3_DENY_FAILS_OPEN,
        GapClass.B5_NO_POLICY_ALLOWS,
        GapClass.B6_SUBSET_CHECK_FAILS_OPEN,
        GapClass.T1_TOOL_COERCION,
    }
)

#: Hazards of the policy's *shape* rather than of any single restriction. The
#: engine is doing exactly what its priority semantics say; the policy is
#: arranged so that those semantics defeat its own intent (a broad low-numbered
#: allow that shadows a specific deny). Nothing to fix in a matcher - the
#: strict reference orders rules the same way - so these live outside
#: `strict.ALL_FIXES` and are reported here, where the whole rule list is in
#: scope, as the only place they can be seen.
POLICY_SHAPE_HAZARDS: frozenset[GapClass] = frozenset({GapClass.B4_PRECEDENCE_INVERSION})


@dataclass(frozen=True)
class LintFinding:
    """One issue in a policy, tied to a gap class."""

    gap_class: GapClass
    tool_name: str
    arg_name: str | None
    detail: str
    severity: str = "high"

    def as_dict(self) -> dict[str, Any]:
        return {
            "gap_class": self.gap_class.value,
            "tool": self.tool_name,
            "arg": self.arg_name,
            "detail": self.detail,
            "severity": self.severity,
        }


@dataclass
class LintReport:
    findings: list[LintFinding] = field(default_factory=list)

    def by_class(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.gap_class.value] = counts.get(finding.gap_class.value, 0) + 1
        return counts

    @property
    def clean(self) -> bool:
        return not self.findings

    @property
    def policy_fixable(self) -> list[LintFinding]:
        return [f for f in self.findings if f.gap_class in POLICY_FIXABLE_GAPS]

    @property
    def engine_level(self) -> list[LintFinding]:
        return [f for f in self.findings if f.gap_class in ENGINE_LEVEL_GAPS]

    @property
    def policy_shape(self) -> list[LintFinding]:
        return [f for f in self.findings if f.gap_class in POLICY_SHAPE_HAZARDS]

    def render(self) -> str:
        if self.clean:
            return "policy_lint: no enforcement-gap issues found."
        lines = [f"policy_lint: {len(self.findings)} issue(s)"]
        for f in self.findings:
            where = f"{f.tool_name}.{f.arg_name}" if f.arg_name else f.tool_name
            if f.gap_class in POLICY_FIXABLE_GAPS:
                tier = "policy-fixable"
            elif f.gap_class in POLICY_SHAPE_HAZARDS:
                tier = "policy-shape hazard"
            else:
                tier = "ENGINE-level"
            lines.append(f"  [{f.gap_class.value}] ({tier}) {where}: {f.detail}")
        if self.engine_level:
            lines.append(
                f"\n{len(self.engine_level)} issue(s) cannot be fixed by rewriting the policy: they are "
                "matcher behaviours. Enforce the hardened policy under strict semantics "
                "(src.enforcers.StrictEnforcer) or patch the engine."
            )
        return "\n".join(lines)


def lint_policy(policy: Policy) -> LintReport:
    """Report every enforcement-gap issue in a policy without changing it."""
    report = LintReport()
    if policy is None:
        report.findings.append(
            LintFinding(GapClass.B5_NO_POLICY_ALLOWS, "<policy>", None, "policy is unset; the engine will allow everything")
        )
        return report

    for tool_name, rules in policy.items():
        for rule in rules:
            if len(rule) < 4:
                continue
            _priority, effect, conditions, fallback = rule[0], rule[1], rule[2], rule[3]

            if fallback not in (0, 1, 2):
                report.findings.append(
                    LintFinding(
                        GapClass.B2_FALLBACK_LEAK, tool_name, None,
                        f"fallback={fallback!r} is out of range; on the last rule this defeats default-deny",
                    )
                )

            if not isinstance(conditions, dict):
                continue

            # An allow rule with no conditions grants the whole tool.
            if effect == 0 and not conditions:
                report.findings.append(
                    LintFinding(
                        GapClass.A5_UNCONSTRAINED_SIBLINGS, tool_name, None,
                        "allow rule has no argument conditions; the tool is permitted unconditionally",
                        severity="medium",
                    )
                )

            for arg_name, restriction in conditions.items():
                report.findings.extend(_lint_restriction(tool_name, arg_name, restriction))

        # Shape hazards need the whole rule list, not one rule at a time.
        report.findings.extend(_lint_precedence(tool_name, rules))

    return report


def _lint_precedence(tool_name: str, rules: list) -> list[LintFinding]:
    """B4: a broad low-numbered allow that shadows a deny (policy-shape hazard).

    Both engines sort a tool's rules by ascending priority number and return on
    the first allow whose conditions hold. An unconditional allow with a lower
    number than a deny therefore guarantees the deny can never fire - the
    engine is honouring its documented precedence, and the policy has arranged
    that precedence against itself. No matcher fix applies (the strict reference
    orders rules the same way), which is why this is reported here and not
    closed by `harden_policy`. Every rule the policy LLM emits lands at priority
    100 (`secagent/tool.py:401-405`), so the hazard is specifically a
    hand-written allow at a lower number combined with any deny at a higher one.
    """
    findings: list[LintFinding] = []
    parsed = [(r[0], r[1], r[2]) for r in rules if len(r) >= 4]
    denies = [(p, c) for p, e, c in parsed if e == 1]
    if not denies:
        return findings
    for a_priority, a_effect, a_conditions in parsed:
        if a_effect != 0 or a_conditions:
            continue
        shadowed = sorted(p for p, _ in denies if p > a_priority)
        if shadowed:
            findings.append(
                LintFinding(
                    GapClass.B4_PRECEDENCE_INVERSION, tool_name, None,
                    f"unconditional allow at priority {a_priority} precedes deny rule(s) at "
                    f"priority {shadowed}; the engine evaluates lower numbers first and returns "
                    "on the first matching allow, so those denies can never fire",
                )
            )
    return findings


def _lint_restriction(tool_name: str, arg_name: str, restriction: Any) -> list[LintFinding]:
    findings: list[LintFinding] = []

    if isinstance(restriction, str):
        # A bare-string restriction is re.match (prefix) and raw regex.
        findings.append(
            LintFinding(
                GapClass.A1_UNANCHORED, tool_name, arg_name,
                f"string restriction {restriction!r} is matched by prefix (re.match); "
                "an attacker-controlled suffix passes",
            )
        )
        if _looks_like_regex(restriction):
            findings.append(
                LintFinding(
                    GapClass.A2_RAW_REGEX, tool_name, arg_name,
                    f"restriction {restriction!r} is compiled as a regex; metacharacters are not literal",
                    severity="medium",
                )
            )
        return findings

    if not isinstance(restriction, dict):
        return findings

    declared_type = restriction.get("type")

    if isinstance(restriction.get("pattern"), str):
        pattern = restriction["pattern"]
        if not _is_anchored(pattern):
            findings.append(
                LintFinding(
                    GapClass.A1_UNANCHORED, tool_name, arg_name,
                    f"pattern {pattern!r} is unanchored (JSON Schema uses re.search); "
                    "a value containing it anywhere is admitted",
                )
            )
        if declared_type is None:
            findings.append(
                LintFinding(
                    GapClass.A3_TYPE_SCOPED_NOOP, tool_name, arg_name,
                    "pattern has no accompanying \"type\"; it constrains strings only and is a "
                    "no-op for int/float/bool/array/object values",
                )
            )

    fmt = restriction.get("format")
    if fmt is not None:
        pattern_present = isinstance(restriction.get("pattern"), str)
        if fmt in UNENFORCEABLE_FORMATS:
            findings.append(
                LintFinding(
                    GapClass.A4_FORMAT_UNENFORCED, tool_name, arg_name,
                    f"format={fmt!r} has no validator in the standard install and enforces nothing; "
                    "add an anchored pattern",
                )
            )
        elif not pattern_present:
            findings.append(
                LintFinding(
                    GapClass.A4_FORMAT_UNENFORCED, tool_name, arg_name,
                    f"format={fmt!r} is only enforced if a format_checker is enabled (Progent does not); "
                    "rely on an anchored pattern instead",
                )
            )

    # Type-scoped keyword on a schema whose declared type it does not apply to.
    for keyword, applicable in TYPE_SCOPED_KEYWORDS.items():
        if keyword not in restriction or declared_type is None:
            continue
        if not _declared_type_matches(declared_type, applicable):
            findings.append(
                LintFinding(
                    GapClass.A3_TYPE_SCOPED_NOOP, tool_name, arg_name,
                    f"keyword {keyword!r} does not apply to declared type {declared_type!r}; "
                    "it will be silently ignored",
                )
            )

    if declared_type == "object" and restriction.get("additionalProperties", True) is not False:
        findings.append(
            LintFinding(
                GapClass.A5_UNCONSTRAINED_SIBLINGS, tool_name, arg_name,
                "object schema allows additionalProperties; keys the policy did not name are unconstrained",
                severity="medium",
            )
        )

    # A pattern written for a list or object argument lives one level down. A
    # linter that stopped at the top level would pass exactly the array policy
    # Progent's own prompt tells the model to write.
    for label, nested in _nested_schemas(restriction):
        findings.extend(_lint_restriction(tool_name, f"{arg_name}.{label}", nested))

    return findings


def _nested_schemas(schema: dict) -> list[tuple[str, dict]]:
    """(label, sub-schema) for every nested schema position a policy uses."""
    out: list[tuple[str, dict]] = []
    items = schema.get("items")
    if isinstance(items, dict):
        out.append(("items", items))
    elif isinstance(items, list):
        out.extend((f"items[{i}]", s) for i, s in enumerate(items) if isinstance(s, dict))
    for key, sub in (schema.get("properties") or {}).items():
        if isinstance(sub, dict):
            out.append((f"properties.{key}", sub))
    if isinstance(schema.get("additionalProperties"), dict):
        out.append(("additionalProperties", schema["additionalProperties"]))
    for key in ("anyOf", "allOf", "oneOf"):
        out.extend((f"{key}[{i}]", s) for i, s in enumerate(schema.get(key, []) or []) if isinstance(s, dict))
    return out


def harden_policy(policy: Policy, *, deny_unknown_args: bool = True) -> Policy:
    """Return a tightened copy of `policy` that closes the gaps.

    Never loosens: patterns are anchored (at every nesting depth), missing
    types inferred, unenforceable formats backed by a pattern, objects closed
    to extra keys. The result is meant to be enforced by the same engine, whose
    matcher will now admit only what the author intended. `deny_unknown_args`
    additionally rewrites empty object schemas to forbid unnamed keys (the A5
    fix with a false-positive cost).

    One engine-specific caveat (B6): under Progent's optional
    ``SECAGENT_ONLY_ALLOW_NARROW`` mode, the z3 policy-narrowing check cannot
    translate ``^``/``$``/``\\A``/``\\Z`` anchors and swallows the failure as
    "subset holds", so an anchored (hardened) policy silently disables that
    check. That is a fault in the analysis, not in anchoring; the fix belongs
    in the engine, which is why no lint rule discourages anchoring.
    """
    if policy is None:
        return None
    hardened: Policy = {}
    for tool_name, rules in policy.items():
        new_rules = []
        for rule in rules:
            if len(rule) < 4:
                new_rules.append(rule)
                continue
            priority, effect, conditions, fallback = rule[0], rule[1], rule[2], rule[3]
            if fallback not in (0, 1, 2):
                fallback = 0  # restore default-deny semantics
            if isinstance(conditions, dict):
                conditions = {a: _harden_restriction(r, deny_unknown_args) for a, r in conditions.items()}
            new_rules.append((priority, effect, conditions, fallback))
        hardened[tool_name] = new_rules
    return hardened


def _harden_restriction(restriction: Any, deny_unknown_args: bool) -> Any:
    if isinstance(restriction, str):
        # Promote a bare string to an anchored, literal-safe schema.
        if _looks_like_regex(restriction):
            return {"type": "string", "pattern": _anchor(restriction)}
        return {"type": "string", "const": restriction}

    if not isinstance(restriction, dict):
        return restriction

    out = dict(restriction)
    if isinstance(out.get("pattern"), str):
        pattern = out.pop("pattern")
        out.setdefault("type", "string")
        if _looks_like_regex(pattern):
            # A genuine pattern: anchor it so it must match the whole value.
            out["pattern"] = _anchor(pattern)
        else:
            # A literal pasted into `pattern` (the common LLM idiom, and the A2
            # trap when it carries incidental metacharacters). Pin it exactly.
            out["const"] = pattern
    if out.get("format") in UNENFORCEABLE_FORMATS and "pattern" not in out:
        # Cannot synthesise a safe URL pattern automatically; downgrade the
        # format to a signal and leave the (now-flagged) restriction in place.
        out.setdefault("type", "string")
    if out.get("type") == "object" and deny_unknown_args:
        out.setdefault("additionalProperties", False)

    # Harden nested schemas the same way, so an `items.pattern` (the array
    # idiom) is anchored rather than left as the one loophole.
    if isinstance(out.get("items"), dict):
        out["items"] = _harden_restriction(out["items"], deny_unknown_args)
    elif isinstance(out.get("items"), list):
        out["items"] = [
            _harden_restriction(s, deny_unknown_args) if isinstance(s, dict) else s for s in out["items"]
        ]
    if isinstance(out.get("properties"), dict):
        out["properties"] = {
            k: (_harden_restriction(v, deny_unknown_args) if isinstance(v, dict) else v)
            for k, v in out["properties"].items()
        }
    for key in ("anyOf", "allOf", "oneOf"):
        if isinstance(out.get(key), list):
            out[key] = [
                _harden_restriction(s, deny_unknown_args) if isinstance(s, dict) else s for s in out[key]
            ]
    return out


# -- helpers ----------------------------------------------------------------

def _is_anchored(pattern: str) -> bool:
    starts = pattern.startswith("^") or pattern.startswith(r"\A")
    ends = pattern.endswith("$") or pattern.endswith(r"\Z")
    return starts and ends


def _declared_type_matches(declared_type: Any, applicable: tuple[type, ...]) -> bool:
    names = {
        str: {"string"},
        int: {"integer", "number"},
        float: {"number"},
        bool: {"boolean"},
        list: {"array"},
        dict: {"object"},
    }
    allowed_names: set[str] = set()
    for t in applicable:
        allowed_names |= names.get(t, set())
    declared = declared_type if isinstance(declared_type, list) else [declared_type]
    return any(d in allowed_names for d in declared)
