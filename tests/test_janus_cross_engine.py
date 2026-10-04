"""Cross-engine generalization: which gaps propagate to a reimplementation.

Janus (`janus-guard`) is a reimplementation of Progent's design - its
policy-generation prompt is Progent's system prompt verbatim and its generator
emits the same `(100, 0, args, 0)` rules - with its own enforcer code. That
makes it the right second engine for a *lineage* question rather than a
convergence one: a gap that lives in the shared primitives (`jsonschema`,
`re.match`, `if arg in kwargs`) should reappear in any faithful
reimplementation, while a gap that is one codebase's control-flow bug should
not. Both halves are asserted here: A1-A5, B1, B5 and T1 propagate; B2 (the
loop-carried fallback) does not, and one B3 flavour (a malformed deny regex)
fails closed in Janus. That per-class split is what the write-up means by
"a property of the design".

Skipped automatically if `janus-guard` is not installed, so the core suite still
runs without it.
"""

from __future__ import annotations

import pytest

pytest.importorskip("janus", reason="janus-guard not installed")

from src.enforcers import build_enforcer
from src.enforcers.base import GapClass
from src.enforcers.strict import StrictEnforcer


@pytest.fixture(scope="module")
def janus():
    return build_enforcer("janus")


@pytest.fixture(scope="module")
def strict():
    return StrictEnforcer()


def _allow(cond):
    return (100, 0, cond, 0)


def assert_gap(janus, strict, policy, tool, args):
    assert janus.would_allow(policy, tool, args).allowed, "expected janus to ALLOW"
    assert not strict.would_allow(policy, tool, args).allowed, "expected strict to DENY"


def test_janus_A1_unanchored(janus, strict):
    policy = {"send_email": [_allow({"to": {"type": "string", "pattern": "alice@company.com"}})]}
    assert_gap(janus, strict, policy, "send_email", {"to": "evil@attacker.com#alice@company.com"})


def test_janus_A1_string_prefix(janus, strict):
    """Janus's str branch, like Progent's, is re.match — prefix only."""
    policy = {"get_webpage": [_allow({"url": "https://company.com/"})]}
    assert_gap(janus, strict, policy, "get_webpage", {"url": "https://company.com/@evil.tld/x"})


def test_janus_A3_type_scoped_noop(janus, strict):
    policy = {"send_email": [_allow({"recipients": {"type": "array", "pattern": "^emma@corp.com$"}})]}
    assert_gap(janus, strict, policy, "send_email", {"recipients": ["attacker@evil.com"]})


def test_janus_A4_format_unenforced(janus, strict):
    policy = {"t": [_allow({"a": {"type": "string", "format": "email"}})]}
    assert_gap(janus, strict, policy, "t", {"a": "definitely-not-an-email"})


def test_janus_A5_unconstrained_sibling(janus, strict):
    policy = {"send_money": [_allow({"recipient": {"type": "string", "enum": ["GB29"]}})]}
    assert_gap(janus, strict, policy, "send_money", {"recipient": "GB29", "amount": 1_000_000})


def test_janus_B1_absent_arg_skip(janus, strict):
    policy = {"send_money": [_allow({"recipient": {"type": "string", "enum": ["GOOD"]}})]}
    assert_gap(janus, strict, policy, "send_money", {"amount": 1})


def test_janus_exact_enum_is_sound(janus):
    """Control: the one sound idiom resists in Janus too."""
    policy = {"t": [_allow({"a": {"type": "string", "enum": ["EXACT"]}})]}
    assert not janus.would_allow(policy, "t", {"a": "EXACT-EVIL"}).allowed


def test_janus_and_progent_agree_on_the_taxonomy():
    """The two engines give the same verdicts on the shared-primitive fixtures.

    Same primitives, same gaps - this asserts the propagation result numerically
    rather than by eyeballing two sweep tables.
    """
    progent = build_enforcer("progent")
    janus = build_enforcer("janus")
    fixtures = [
        ({"s": [_allow({"a": {"type": "string", "pattern": "GOOD"}})]}, "s", {"a": "GOOD-EVIL"}),
        ({"s": [_allow({"a": {"type": "array", "pattern": "^x$"}})]}, "s", {"a": ["evil"]}),
        ({"s": [_allow({"a": {"type": "string", "format": "email"}})]}, "s", {"a": "nope"}),
        ({"s": [_allow({"a": {"type": "string", "enum": ["x"]}})]}, "s", {"a": "x", "b": "extra"}),
    ]
    for policy, tool, args in fixtures:
        assert (
            progent.would_allow(policy, tool, args).allowed
            == janus.would_allow(policy, tool, args).allowed
        ), f"engines disagree on {args} - the propagation claim would need qualifying"


def test_B2_is_progent_only(janus, strict):
    """B2 did not propagate: Janus has a real default-deny, not a loop-carried fallback.

    The one control-flow bug in Progent's `_check_tool_call` that is a *code*
    defect rather than a design choice. A reimplementation with its own control
    flow does not inherit it - which is exactly what distinguishes this class
    from A1-A5/B1 in the cross-engine profile.
    """
    policy = {
        "t": [
            (1, 0, {"a": {"enum": ["GOOD"]}}, 0),
            (2, 0, {"a": {"enum": ["OTHER"]}}, 3),  # out-of-range fallback on the last rule
        ]
    }
    progent = build_enforcer("progent")
    assert progent.would_allow(policy, "t", {"a": "EVIL"}).allowed, "Progent: B2 present"
    assert not janus.would_allow(policy, "t", {"a": "EVIL"}).allowed, "Janus: real default-deny"
    assert not strict.would_allow(policy, "t", {"a": "EVIL"}).allowed


def test_B3_malformed_deny_regex_fails_closed_in_janus(janus):
    """One B3 flavour did not propagate either: Janus lets `re.error` escape.

    Progent's bare `except: continue` swallows it and drops the deny rule;
    Janus catches only its own `ArgumentValidationError`, so a malformed regex
    propagates and the call is refused. The throwing-predicate flavour *does*
    propagate (Janus wraps custom-validator errors into the caught type) - see
    the per-class profile.
    """
    policy = {"t": [(1, 1, {"to": {"type": "string", "pattern": "[unclosed"}}, 0), (2, 0, {}, 0)]}
    progent = build_enforcer("progent")
    assert progent.would_allow(policy, "t", {"to": "evil"}).allowed
    assert not janus.would_allow(policy, "t", {"to": "evil"}).allowed


def test_per_class_progent_vs_janus_profile(janus):
    """The verified per-class matrix, as a test and as the `gapfuzz crossengine` table."""
    from src.gapfuzz.crossengine import run_crossengine

    progent = build_enforcer("progent")
    report = run_crossengine([progent, janus])
    rows = {row.gap_class: row for row in report.rows}

    propagated = {
        GapClass.A1_UNANCHORED, GapClass.A2_RAW_REGEX, GapClass.A3_TYPE_SCOPED_NOOP,
        GapClass.A4_FORMAT_UNENFORCED, GapClass.A5_UNCONSTRAINED_SIBLINGS,
        GapClass.B1_ABSENT_ARG_SKIP, GapClass.B3_DENY_FAILS_OPEN, GapClass.B4_PRECEDENCE_INVERSION,
        GapClass.B5_NO_POLICY_ALLOWS, GapClass.T1_TOOL_COERCION,
    }
    for gap in propagated:
        assert rows[gap].verdicts == {"progent": True, "janus": True}, gap
        assert rows[gap].label == "propagated", gap

    assert rows[GapClass.B2_FALLBACK_LEAK].verdicts == {"progent": True, "janus": False}
    assert rows[GapClass.B6_SUBSET_CHECK_FAILS_OPEN].verdicts == {"progent": True, "janus": None}

    # The reference denies every matcher witness except the per-spec B4 shape,
    # which it deliberately does not "fix".
    for gap, row in rows.items():
        if gap is GapClass.B6_SUBSET_CHECK_FAILS_OPEN:
            assert row.reference_denies is None
        elif gap is GapClass.B4_PRECEDENCE_INVERSION:
            assert row.reference_denies is False and not row.has_reference_fix
        else:
            assert row.reference_denies is True, gap
            assert row.has_reference_fix, gap

    rendered = report.render()
    assert "not a bypass rate" in rendered
    assert "verbatim" in rendered, "the lineage note must travel with the table"
