"""Tests for the linter and the hardening it produces.

The linter is the deployable form of the strict reference, so these tests check
two things: it *detects* each gap class, and its *repair* actually closes the
gap when the hardened policy is run under the real engine (for policy-fixable
gaps) or the strict matcher (for engine-level ones).
"""

from __future__ import annotations

import pytest

from src.enforcers.base import GapClass
from src.enforcers.strict import StrictEnforcer
from src.policy_lint import (
    ENGINE_LEVEL_GAPS,
    POLICY_FIXABLE_GAPS,
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
    """Every gap class is either policy-fixable or engine-level, never both."""
    assert POLICY_FIXABLE_GAPS.isdisjoint(ENGINE_LEVEL_GAPS)
    assert POLICY_FIXABLE_GAPS | ENGINE_LEVEL_GAPS == set(GapClass)


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
