"""Tests for the linter and the hardening it produces.

The linter is the deployable form of the strict reference, so these tests check
two things: it *detects* each gap class, and its *repair* actually closes the
gap when the hardened policy is run under the real engine (for policy-fixable
gaps) or the strict matcher (for engine-level ones).
"""

from __future__ import annotations

import pytest

from src.enforcers.base import PERMISSIVE_GAPS, GapClass
from src.enforcers.strict import StrictEnforcer
from src.enforcers.strict import ALL_FIXES
from src.policy_lint import (
    ENGINE_LEVEL_GAPS,
    POLICY_FIXABLE_GAPS,
    POLICY_SHAPE_HAZARDS,
    harden_policy,
    lint_policy,
)


def _classes(policy):
    return set(lint_policy(policy).by_class())


def test_detects_unanchored_pattern():
    policy = {"t": [(100, 0, {"a": {"type": "string", "pattern": "GOOD"}}, 0)]}
    assert GapClass.A1_UNANCHORED.value in _classes(policy)


def test_detects_pattern_without_type():
    policy = {"t": [(100, 0, {"a": {"pattern": "^GOOD$"}}, 0)]}
    assert GapClass.A3_TYPE_SCOPED_NOOP.value in _classes(policy)


def test_detects_unenforceable_format():
    policy = {"t": [(100, 0, {"a": {"type": "string", "format": "uri"}}, 0)]}
    assert GapClass.A4_FORMAT_UNENFORCED.value in _classes(policy)


def test_detects_out_of_range_fallback():
    policy = {"t": [(100, 0, {"a": {"type": "string", "const": "x"}}, 3)]}
    assert GapClass.B2_FALLBACK_LEAK.value in _classes(policy)


def test_detects_open_object():
    policy = {"t": [(100, 0, {"a": {"type": "object", "properties": {"to": {"const": "x"}}}}, 0)]}
    assert GapClass.A5_UNCONSTRAINED_SIBLINGS.value in _classes(policy)


def test_exact_enum_is_clean():
    policy = {"t": [(100, 0, {"a": {"type": "string", "enum": ["EXACT"]}}, 0)]}
    assert lint_policy(policy).clean


def test_unset_policy_flagged():
    assert GapClass.B5_NO_POLICY_ALLOWS.value in _classes(None)


def test_hardening_anchors_pattern_and_closes_gap():
    policy = {"t": [(100, 0, {"a": {"type": "string", "pattern": "GOOD"}}, 0)]}
    hardened = harden_policy(policy)
    strict = StrictEnforcer()
    # The intended value still works...
    assert strict.would_allow(hardened, "t", {"a": "GOOD"}).allowed
    # ...but the suffix bypass no longer does.
    assert not strict.would_allow(hardened, "t", {"a": "GOOD-EVIL"}).allowed


def test_hardening_keeps_literal_with_incidental_metachars():
    """A prose value with a '?' must survive hardening (the utility-FP bug).

    "...in DM?" is a literal, not a regex; hardening must pin it exactly, not
    turn the '?' into a quantifier that rejects the original value.
    """
    literal = "Hi, can everybody write me their favorite hobby in DM?"
    policy = {"send": [(100, 0, {"body": {"type": "string", "pattern": literal}}, 0)]}
    hardened = harden_policy(policy)
    strict = StrictEnforcer()
    assert strict.would_allow(hardened, "send", {"body": literal}).allowed


def test_hardening_preserves_genuine_regex():
    """A real regex (character class) stays a pattern, just anchored."""
    policy = {"send": [(100, 0, {"to": {"type": "string", "pattern": r"[a-z]+@corp\.com"}}, 0)]}
    hardened = harden_policy(policy)
    strict = StrictEnforcer()
    assert strict.would_allow(hardened, "send", {"to": "alice@corp.com"}).allowed
    assert not strict.would_allow(hardened, "send", {"to": "alice@corp.com.evil.com"}).allowed


def test_hardening_restores_default_deny_on_bad_fallback():
    policy = {"t": [(100, 0, {"a": {"type": "string", "const": "x"}}, 3)]}
    hardened = harden_policy(policy)
    assert hardened["t"][0][3] == 0


def test_gap_partition_is_complete_and_disjoint():
    """Every *admittance* gap is in exactly one of three tiers.

    policy-fixable (a rewrite closes it), engine-level (the matcher must
    change), or policy-shape hazard (the engine is honouring its documented
    semantics against a badly arranged policy; only detectable, not
    repairable). The partition is over `PERMISSIVE_GAPS`, not the whole enum.
    C1 (boundary disclosure) is a property of the denial path rather than of
    what the matcher admits, so the question does not apply to it. It is
    asserted absent below so that adding it to a tier by reflex would fail
    loudly.
    """
    tiers = (POLICY_FIXABLE_GAPS, ENGINE_LEVEL_GAPS, POLICY_SHAPE_HAZARDS)
    for i, a in enumerate(tiers):
        for b in tiers[i + 1:]:
            assert a.isdisjoint(b)
    assert POLICY_FIXABLE_GAPS | ENGINE_LEVEL_GAPS | POLICY_SHAPE_HAZARDS == set(PERMISSIVE_GAPS)
    assert GapClass.C1_BOUNDARY_DISCLOSURE not in set().union(*tiers)


def test_shape_hazards_have_no_reference_fix():
    """A shape hazard is detected by lint and *not* claimed as fixed by the reference."""
    assert POLICY_SHAPE_HAZARDS == {GapClass.B4_PRECEDENCE_INVERSION}
    assert POLICY_SHAPE_HAZARDS.isdisjoint(ALL_FIXES)
    assert GapClass.B6_SUBSET_CHECK_FAILS_OPEN in ENGINE_LEVEL_GAPS
    assert GapClass.B6_SUBSET_CHECK_FAILS_OPEN not in ALL_FIXES


def test_detects_precedence_inversion_as_shape_hazard():
    """B4: a broad low-numbered allow that shadows a higher-numbered deny."""
    policy = {"t": [(1, 0, {}, 0), (100, 1, {"to": {"type": "string"}}, 0)]}
    report = lint_policy(policy)
    assert GapClass.B4_PRECEDENCE_INVERSION.value in report.by_class()
    assert report.policy_shape
    assert "policy-shape hazard" in report.render()
    # The same two rules the other way round are fine: the deny is reached first.
    fine = {"t": [(100, 0, {}, 0), (1, 1, {"to": {"type": "string"}}, 0)]}
    assert GapClass.B4_PRECEDENCE_INVERSION.value not in lint_policy(fine).by_class()


def test_lint_reaches_nested_items_pattern():
    """The array idiom keeps its pattern under `items`; lint must look there."""
    policy = {"send_email": [(100, 0, {"recipients": {"type": "array", "items": {"type": "string", "pattern": "emma@corp.com"}}}, 0)]}
    report = lint_policy(policy)
    assert any(
        f.gap_class is GapClass.A1_UNANCHORED and f.arg_name == "recipients.items" for f in report.findings
    )


def test_hardening_anchors_nested_items_pattern():
    """Hardening must anchor a nested pattern, or the array idiom stays open.

    Before nested anchoring, a `recipients` policy whose `items.pattern` was a
    pasted benign address admitted the display-name form
    `'"benign" <attacker>'` - and so did the strict reference. That value is
    what the tool's own email parser resolves to the attacker.
    """
    benign = "emma@bluesparrowtech.com"
    smuggled = f'"{benign}" <mark.black-2134@gmail.com>'
    policy = {"send_email": [(100, 0, {"recipients": {"type": "array", "items": {"type": "string", "pattern": benign}}}, 0)]}
    hardened = harden_policy(policy)
    strict = StrictEnforcer()
    assert strict.would_allow(hardened, "send_email", {"recipients": [benign]}).allowed
    assert not strict.would_allow(hardened, "send_email", {"recipients": [smuggled]}).allowed


def test_report_separates_the_two_tiers():
    policy = {
        "t": [
            (100, 0, {"a": {"type": "string", "pattern": "GOOD"}}, 0),  # A1: policy-fixable
            (100, 0, {}, 0),  # A5: engine-level (unconditional allow)
        ]
    }
    report = lint_policy(policy)
    assert report.policy_fixable
    assert report.engine_level
    assert "ENGINE-level" in report.render()
