"""Characterization tests for the differential sweep itself.

Why this file exists
--------------------
The sweep is the project's flagship artifact: `python -m gapfuzz audit` and the
headline "760 labelled gap instances" both come out of `src/gapfuzz/sweep.py`,
`operators.py`, and `corpus.py`. Until this file was written, **none of those
three modules had a single test**. Every test in the suite covered `strict`,
`progent`, `janus`, `policy_lint`, `harm_oracle`, or `find_bypass` - so "114
tests pass" was doing rhetorical work the suite did not actually support for the
one number a reader is most likely to quote.

That absence had a consequence, which is the second reason this file exists:
because nothing asserted coverage, nobody noticed that the corpus can only
generate a single policy *shape*, leaving seven of the eleven taxonomy classes
structurally unreachable by the sweep. An untested generator does not complain
about what it cannot produce.

So these tests do two jobs:

1.  **Pin current behaviour exactly**, so the planned refactors (widening the
    mutation operators to see the tool schema; adding a policy-shape dimension
    to the corpus) are verifiable rather than hopeful. When a number here moves,
    it must move because a commit deliberately moved it, with a comment saying
    why.
2.  **Record the coverage ceiling as an executable fact** rather than a prose
    caveat, via :func:`test_sweep_coverage_ceiling_is_pinned`. That test asserts
    the *current* incomplete state on purpose, and is written to fail loudly the
    moment coverage improves - at which point it is updated, not deleted.

`slack` is the default fixture: it is the smallest suite (15 policy-relevant
string arguments) and exercises every code path the larger suites do. The
all-suites totals are pinned once, marked `slow`.

No LLM, no network, no cost - same as everything else here.
"""

from __future__ import annotations

import pytest

from src.enforcers.base import PERMISSIVE_GAPS, GapClass, GapInstance, Verdict
from src.enforcers.strict import StrictEnforcer
from src.gapfuzz import attribution
from src.gapfuzz.attribution import Attribution, attribute
from src.gapfuzz.corpus import suite_corpus
from src.gapfuzz.operators import MUTATORS, mutate_call
from src.gapfuzz.sweep import run_sweep, sweep_fragment

pytest.importorskip("secagent", reason="Progent (secagent) not installed")

#: Styles the corpus emits today. Adding one is a deliberate act; this set is
#: what makes an accidental addition visible.
EXPECTED_STYLES = {"pattern-pinned", "pattern-no-type", "format-only", "enum-exact"}

#: Admittance classes the sweep can actually produce. The other nine are pinned
#: in tests/test_enforcement_gaps.py (B6 in tests/test_progent_subset_check.py)
#: but are unreachable here - see the module docstring and
#: test_sweep_coverage_ceiling_is_pinned. (C1 is not an admittance class at
#: all; it is measured by the disclosure probe - tests/test_disclosure.py.)
SWEPT_CLASSES = {
    GapClass.A1_UNANCHORED,
    GapClass.A3_TYPE_SCOPED_NOOP,
    GapClass.A4_FORMAT_UNENFORCED,
}


@pytest.fixture(scope="module")
def progent():
    from src.enforcers.progent import ProgentEnforcer

    return ProgentEnforcer()


@pytest.fixture(scope="module")
def reference():
    return StrictEnforcer()


@pytest.fixture(scope="module")
def suites():
    from agentdojo.task_suite.load_suites import get_suites

    return get_suites("v1")


@pytest.fixture(scope="module")
def slack(suites):
    return suites["slack"]


@pytest.fixture(scope="module")
def slack_report(slack, progent):
    """One sweep, reused across tests - it is the expensive part of this file."""
    return run_sweep({"slack": slack}, progent)


# --------------------------------------------------------------------------
# corpus
# --------------------------------------------------------------------------


def test_corpus_shape_is_pinned(slack):
    """slack has 15 policy-relevant string args, written four ways each."""
    fragments = list(suite_corpus(slack))
    assert len(fragments) == 60
    assert {f.style for f in fragments} == EXPECTED_STYLES
    per_style = {s: sum(1 for f in fragments if f.style == s) for s in EXPECTED_STYLES}
    assert set(per_style.values()) == {15}, per_style


def test_corpus_emits_one_rule_allow_policies(slack):
    """The invariant that causes the coverage ceiling, asserted directly.

    Every fragment is a single allow rule at priority 100 with fallback 0 and a
    dict restriction. B2 needs a nonzero fallback, B3 a forbid rule, B4 a second
    rule, B5 no policy at all, and A2 a bare-string restriction - so none of
    them can be expressed while this holds. Closing the coverage gap means this
    test's assertions get *relaxed*, deliberately.
    """
    for fragment in suite_corpus(slack):
        rules = fragment.policy[fragment.tool_name]
        assert len(rules) == 1, f"{fragment.style} emitted {len(rules)} rules"
        priority, effect, conditions, fallback = rules[0]
        assert (priority, effect, fallback) == (100, 0, 0)
        assert isinstance(conditions, dict)
        for restriction in conditions.values():
            assert isinstance(restriction, dict), "bare-string restriction would reach A2"


def test_corpus_sample_value_has_no_regex_metacharacter(slack):
    """A2 is unreachable partly because the planted value is inert.

    `EXPECTED_VALUE` contains no `.`, so there is nothing for a raw-regex
    wildcard to over-match. Real identifiers - emails, URLs, IBANs - are full of
    metacharacters, which is exactly why A2 bites in practice and why replacing
    this placeholder is the cheapest coverage win available.
    """
    for fragment in suite_corpus(slack):
        assert isinstance(fragment.intended_value, str)
        assert not set(fragment.intended_value) & set(".*+?[]()|^$\\")


# --------------------------------------------------------------------------
# operators
# --------------------------------------------------------------------------


def test_sibling_injection_is_currently_dead(slack):
    """`sibling_injection` is registered but yields nothing.

    Its body is `return iter(())` and its docstring promises "the caller
    supplies candidate sibling names from the tool schema" - but no caller does,
    because `mutate_call` only ever receives an args dict. A5 therefore has zero
    production path despite being registered as an operator.

    Pinned so that implementing it is a visible, intentional change.
    """
    assert "sibling_injection" in MUTATORS
    assert list(MUTATORS["sibling_injection"]({"recipient": "alice@corp.com"})) == []


def test_mutators_never_add_or_remove_arguments():
    """The structural reason A5 and B1 cannot be swept.

    Every operator iterates the *existing* keys, so the candidate key-set always
    equals the input key-set. A5 needs a key added; B1 needs one removed.
    Neither is expressible until the operator signature widens to carry the tool
    schema.
    """
    base = {"recipient": "alice@corp.com", "amount": "100"}
    for candidate in mutate_call(base):
        assert set(candidate.args) == set(base), candidate.rationale


def test_mutate_call_is_deterministic():
    """Reproducibility: the same input yields the same candidates in order.

    This is not incidental - it is why the audit can be quoted as an exact
    number rather than a sample, and why a reviewer re-running it gets 760.
    """
    base = {"url": "https://example.com/report"}
    first = [(c.args, c.hypothesis, c.rationale) for c in mutate_call(base)]
    second = [(c.args, c.hypothesis, c.rationale) for c in mutate_call(base)]
    assert first == second
    assert first, "expected at least one candidate"


# --------------------------------------------------------------------------
# attribution
# --------------------------------------------------------------------------


def test_attribution_reports_the_fix_that_flips_the_verdict():
    """Attribution names the reference fix responsible, not the operator's guess.

    A suffix appended to a `format`-only policy is admitted because `format` is
    never enforced (A4), not because of anchoring - even though the mutation
    looks like the A1 suffix operator produced it. The operator's `hypothesis`
    (A1 here) is only a last-resort fallback; isolation overrides it with A4.
    """
    policy = {"send_email": [(100, 0, {"to": {"type": "string", "format": "email"}}, 0)]}
    got = attribute(
        policy, "send_email", {"to": "not-an-email"}, hypothesis=GapClass.A1_UNANCHORED
    )
    assert got.gap_class is GapClass.A4_FORMAT_UNENFORCED
    assert got.method == "isolated"
    assert got.candidates == frozenset({GapClass.A4_FORMAT_UNENFORCED})


def test_attribution_reports_over_determination():
    """Two fixes each independently deny -> reported, not silently tie-broken away.

    A `format`-only policy on `to`, with the attacker adding an unnamed `bcc`:
    the call fails A4 (the pinned `to` is not a real email) *and* A5 (the `bcc`
    sibling is unconstrained). Both are genuine causes. Attribution surfaces the
    full set and picks the enum-lowest (A4) as a documented representative,
    rather than the previous first-match-wins that hid A5 entirely.
    """
    policy = {"send_email": [(100, 0, {"to": {"type": "string", "format": "email"}}, 0)]}
    got = attribute(policy, "send_email", {"to": "NOPE", "bcc": "evil@x.com"})
    assert got.method == "over-determined"
    assert got.candidates == frozenset(
        {GapClass.A4_FORMAT_UNENFORCED, GapClass.A5_UNCONSTRAINED_SIBLINGS}
    )
    assert got.gap_class is GapClass.A4_FORMAT_UNENFORCED  # enum-lowest tie-break


def test_attribution_rejects_a_non_gap():
    """A call the baseline semantics already deny is not attributed to any fix.

    A bare-string restriction with a metacharacter (`.`) and a value that does
    not even prefix-match: the *unfixed* reference already denies it, so every
    single-fix probe denies too. First-match-wins would have mislabelled this as
    A1; the baseline guard returns `not-a-gap` instead.
    """
    policy = {"send_email": [(100, 0, {"to": "alice@corp.com"}, 0)]}
    got = attribute(policy, "send_email", {"to": "aliceXcorpXcom"})
    assert got.method == "not-a-gap"
    assert got.gap_class is None
    assert got.candidates == frozenset()


def test_leave_one_out_attributes_cooperating_fixes(monkeypatch):
    """The pass for denials that need two fixes cooperating.

    No input under today's strict semantics reaches this branch - each fix
    targets an orthogonal failure mode, verified by brute force - so it is tested
    with probes that simulate a call denied only when *both* A1 and A3 are
    active. Track 3's policy-shape corpus will produce such cooperative denials
    for real; the pass must already be correct when they arrive.
    """
    A1, A3 = GapClass.A1_UNANCHORED, GapClass.A3_TYPE_SCOPED_NOOP

    class Fake:
        def __init__(self, fixes, schemas=None):
            self.fixes = frozenset(fixes)

        def would_allow(self, policy, tool, args):
            denied = {A1, A3} <= self.fixes  # only the full pair denies
            return Verdict(allowed=not denied)

    monkeypatch.setattr(attribution, "_PROBES", {})
    monkeypatch.setattr(attribution, "_probe", Fake)
    got = attribute({"t": []}, "t", {"x": "v"})
    assert got.method == "leave-one-out"
    assert got.candidates == frozenset({A1, A3})
    assert got.gap_class is A1  # enum-lowest of the responsible pair


def test_attribution_result_is_frozen():
    """`Attribution` is a value object; instances must not be mutated in place."""
    got = attribute(
        {"send_email": [(100, 0, {"to": {"pattern": "alice@corp.com"}}, 0)]},
        "send_email",
        {"to": "alice@corp.comEVIL"},
    )
    assert isinstance(got, Attribution)
    with pytest.raises(Exception):
        got.gap_class = GapClass.A2_RAW_REGEX  # type: ignore[misc]


# --------------------------------------------------------------------------
# sweep results
# --------------------------------------------------------------------------


def test_slack_sweep_totals_are_pinned(slack_report):
    """The exact per-style numbers for one suite.

    These are the numbers the write-up's headline is built from, at 1/4 scale.
    If one moves, a commit moved it - say why in that commit.
    """
    assert slack_report.enforcer == "progent"
    assert len(slack_report.instances) == 120
    counts = {
        style: (r.fragments, r.bypassable_fragments, dict(r.gap_counts))
        for style, r in slack_report.styles.items()
    }
    assert counts == {
        "enum-exact": (15, 0, {}),
        "format-only": (15, 15, {"A4_format_unenforced": 45}),
        "pattern-no-type": (15, 15, {"A1_unanchored": 30, "A3_type_scoped_noop": 15}),
        "pattern-pinned": (15, 15, {"A1_unanchored": 30}),
    }


def test_all_instances_attribute_to_exactly_one_fix(slack_report):
    """Every gap instance isolates to a single reference fix - the finding.

    This is the evidence that makes the per-class table trustworthy: attribution
    is a clean isolation, not a heuristic ranking. Across the whole sweep there
    are zero over-determined and zero unattributed instances, and every instance
    carries `method == "isolated"` with a single co-attribution candidate.

    It is written to fail informatively the moment Track 3 introduces genuinely
    ambiguous candidates (multi-argument calls, cooperating policy shapes) - at
    which point the over_determined / unattributed counts become the thing to
    report, and this assertion is relaxed deliberately, not deleted.
    """
    assert slack_report.over_determined == 0
    assert slack_report.unattributed == 0
    for instance in slack_report.instances:
        assert instance.attribution_method == "isolated", instance.note
        assert instance.co_attributed == frozenset()


def test_report_renders_attribution_line(slack_report):
    """The over-determined / unattributed counts are surfaced, not just tallied.

    A reviewer who reads '0 over-determined, 0 unattributed' can trust the
    per-class counts; one who sees no such line has to take them on faith.
    """
    rendered = slack_report.render()
    assert "attribution: 0 over-determined, 0 unattributed" in rendered


def test_exact_enum_is_never_bypassable(slack_report):
    """The negative control, standing alone because the whole thesis leans on it.

    A differential that flagged everything would be worthless. `enum-exact` is
    the one idiom with sound semantics, and it must score zero: that is what
    makes "100% on the flawed idioms" a finding rather than an artifact of a
    trigger-happy tool.
    """
    enum_style = slack_report.styles["enum-exact"]
    assert enum_style.fragments == 15
    assert enum_style.bypassable_fragments == 0
    assert enum_style.bypass_rate == 0.0
    assert not any("enum-exact" in i.note for i in slack_report.instances)


def test_reference_soundness_invariant_holds(slack_report):
    """The reference must never admit what the engine denies.

    A violation would mean our reference is wrong - which invalidates every
    number in the project, not just this one. Asserted in every sweep for that
    reason.
    """
    assert slack_report.invariant_violations == 0


def test_every_instance_is_a_genuine_permissive_gap(slack_report):
    """Each instance really is engine-allows / reference-denies."""
    assert slack_report.instances
    for instance in slack_report.instances:
        assert isinstance(instance, GapInstance)
        assert instance.is_permissive
        assert instance.enforcer_verdict.allowed
        assert not instance.strict_verdict.allowed


def test_strict_against_itself_finds_nothing(slack, reference):
    """Self-consistency: the reference has no gaps relative to itself.

    Guards against a reference so strict that it rejects its own intended
    values, which would manufacture gaps out of nothing.
    """
    report = run_sweep({"slack": slack}, reference)
    assert len(report.instances) == 0
    assert report.invariant_violations == 0
    assert all(r.bypassable_fragments == 0 for r in report.styles.values())


def test_fragment_whose_intended_value_is_denied_is_skipped(progent, reference):
    """A fragment the engine rejects outright yields nothing - by design.

    Worth pinning because it is a silent path: such a fragment still counts
    toward `fragments` in the report, so it depresses the bypass rate without
    ever being measured. That conflation is exactly the kind of error this
    project exists to point out in others, and the planned fix reports these
    separately.
    """
    from src.gapfuzz.corpus import PolicyFragment

    fragment = PolicyFragment(
        tool_name="send_channel_message",
        policy={"send_channel_message": [(100, 0, {"body": {"type": "string", "enum": ["ONLY_THIS"]}}, 0)]},
        style="unsatisfiable",
        pinned_arg="body",
        intended_value="SOMETHING_ELSE",
    )
    assert list(sweep_fragment(fragment, progent, reference)) == []


# --------------------------------------------------------------------------
# coverage - the ceiling, asserted rather than described
# --------------------------------------------------------------------------


def test_sweep_coverage_ceiling_is_pinned(slack_report):
    """The sweep produces three of the twelve admittance classes. Asserted, not hoped.

    This test deliberately pins an *incomplete* state. The taxonomy claims
    A1-A5, B1-B6, T1 and C; the sweep can only ever emit A1, A3 and A4, because
    the corpus fixes the policy shape, pins only string-typed arguments (so the
    numeric coercion class T1 has nothing to bite), and the operators cannot
    add or remove arguments (see the two tests above for each half of that).

    When the coverage work lands, this test fails - and that failure is the
    signal to update it, never to loosen it. The published claim and the
    executable fact stay in step.
    """
    produced = {i.gap_class for i in slack_report.instances}
    assert produced == SWEPT_CLASSES

    # Measured over the *admittance* gaps only. C1 is a GapClass member now, but
    # it is not a coverage gap: it has no admittance to sweep for, and it is
    # measured instead by the disclosure probe (see the C1 tests below). Counting
    # it as "unreachable" would report a permanent shortfall that no coverage
    # work can ever close.
    unreachable = set(PERMISSIVE_GAPS) - SWEPT_CLASSES
    assert produced & unreachable == set()
    assert unreachable == {
        GapClass.A2_RAW_REGEX,
        GapClass.A5_UNCONSTRAINED_SIBLINGS,
        GapClass.B1_ABSENT_ARG_SKIP,
        GapClass.B2_FALLBACK_LEAK,
        GapClass.B3_DENY_FAILS_OPEN,
        GapClass.B4_PRECEDENCE_INVERSION,
        GapClass.B5_NO_POLICY_ALLOWS,
        GapClass.B6_SUBSET_CHECK_FAILS_OPEN,
        GapClass.T1_TOOL_COERCION,
    }
    assert len(unreachable) == 9
    assert GapClass.C1_BOUNDARY_DISCLOSURE not in unreachable
    assert GapClass.C1_BOUNDARY_DISCLOSURE not in produced, "C1 must never be an admittance gap"


def test_janus_and_progent_sweeps_are_identical(slack):
    """The propagation claim on the swept classes, as a test.

    Janus reimplements Progent's design with the same primitives, and on the
    three classes the value-level corpus reaches (A1/A3/A4 - all of them
    `jsonschema.validate` and `re` behaviour) it admits exactly the same
    superset, instance for instance. That is what "the gap lives in the shared
    primitives" means operationally. The per-class profile, including the
    classes on which the two engines *differ*, is in
    tests/test_janus_cross_engine.py.
    """
    pytest.importorskip("janus", reason="janus-guard not installed")
    from src.enforcers.janus import JanusEnforcer
    from src.enforcers.progent import ProgentEnforcer

    janus = run_sweep({"slack": slack}, JanusEnforcer())
    progent = run_sweep({"slack": slack}, ProgentEnforcer())

    assert janus.enforcer != progent.enforcer
    assert len(janus.instances) == len(progent.instances)
    assert janus.invariant_violations == progent.invariant_violations == 0
    for style in EXPECTED_STYLES:
        j, p = janus.styles[style], progent.styles[style]
        assert (j.fragments, j.bypassable_fragments) == (p.fragments, p.bypassable_fragments), style
        assert dict(j.gap_counts) == dict(p.gap_counts), style


@pytest.mark.slow
def test_all_suites_totals_are_pinned(suites, progent):
    """The published headline: 760 instances over 380 fragments, 95 arguments.

    The number quoted in README.md, FINDINGS.md and demo.html. Pinned once here
    so those documents cannot drift from the code again.
    """
    report = run_sweep(suites, progent)
    assert len(report.instances) == 760
    assert report.invariant_violations == 0
    assert sum(r.fragments for r in report.styles.values()) == 380
    assert {s: r.fragments for s, r in report.styles.items()} == {s: 95 for s in EXPECTED_STYLES}
    assert report.styles["enum-exact"].bypassable_fragments == 0
    for style in EXPECTED_STYLES - {"enum-exact"}:
        assert report.styles[style].bypass_rate == 1.0, style
