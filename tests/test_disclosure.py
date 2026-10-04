"""Gap class C1: the engine hands its own policy back when it refuses.

C1 is structurally unlike every other row in the taxonomy. A1-A5 and B1-B5 are
*admittance* gaps - the matcher permits more than the policy reads, and each is
closed by a fix in the strict reference. C1 is a property of the **denial**
path, which by construction admits nothing. There is no matcher fix for it, so
it must stay out of `PERMISSIVE_GAPS`, out of `ALL_FIXES`, out of attribution,
and out of the bypass-rate table - while still sharing the one taxonomy
namespace, so a log line, a test name and a paper row remain the same
identifier. Half the tests here defend exactly that separation.

The other half is the finding. Both engines quote their allow-list back on
every refusal, and the idiom that leaks is the idiom that cannot be bypassed -
see `test_the_sound_idiom_is_the_disclosing_idiom`.

No LLM, no network, no cost.
"""

from __future__ import annotations

import pytest

from src.enforcers.base import (
    ALLOW,
    PERMISSIVE_GAPS,
    BaseEnforcer,
    GapClass,
    Verdict,
    policy_literals,
)
from src.enforcers.strict import ALL_FIXES, StrictEnforcer

ALLOWED = "GB29NWBK60161331926819"
DENIED = "DE89370400440532013000"


def _enum_policy():
    return {"send_money": [(100, 0, {"recipient": {"type": "string", "enum": [ALLOWED]}}, 0)]}


@pytest.fixture(scope="module")
def progent():
    pytest.importorskip("secagent", reason="Progent (secagent) not installed")
    from src.enforcers.progent import ProgentEnforcer

    return ProgentEnforcer()


@pytest.fixture(scope="module")
def janus():
    pytest.importorskip("janus", reason="janus-guard not installed")
    from src.enforcers.janus import JanusEnforcer

    return JanusEnforcer()


# --------------------------------------------------------------------------
# C1 is a taxonomy member, but NOT an admittance gap
# --------------------------------------------------------------------------


def test_c1_is_not_an_admittance_gap():
    """The predicate that keeps a denial-path finding out of the matcher tables."""
    assert GapClass.C1_BOUNDARY_DISCLOSURE.is_admittance is False
    assert all(g.is_admittance for g in GapClass if g.value.startswith(("A", "B", "T")))


def test_c1_is_excluded_from_every_fix_set():
    """No reference matcher claims to fix disclosure, because none can.

    If C1 leaked into `ALL_FIXES`, `StrictEnforcer` would advertise a repair it
    never performs; if it leaked into `PERMISSIVE_GAPS`, attribution would probe
    for a fix that does not exist and could mislabel a real gap.
    """
    assert GapClass.C1_BOUNDARY_DISCLOSURE not in PERMISSIVE_GAPS
    assert GapClass.C1_BOUNDARY_DISCLOSURE not in ALL_FIXES
    assert PERMISSIVE_GAPS == frozenset(g for g in GapClass if g.is_admittance)


def test_c1_is_never_a_candidate_for_attribution():
    """Attribution iterates the reference-fixable gaps, so C1 drops out automatically.

    So do B4 and B6: they are admittance-direction findings with no reference
    fix, and probing them would be indistinguishable from the no-fix baseline.
    """
    from src.gapfuzz.attribution import _CANDIDATE_GAPS

    assert GapClass.C1_BOUNDARY_DISCLOSURE not in _CANDIDATE_GAPS
    assert GapClass.B4_PRECEDENCE_INVERSION not in _CANDIDATE_GAPS
    assert GapClass.B6_SUBSET_CHECK_FAILS_OPEN not in _CANDIDATE_GAPS
    assert set(_CANDIDATE_GAPS) == set(ALL_FIXES)
    assert set(_CANDIDATE_GAPS) < set(PERMISSIVE_GAPS)


# --------------------------------------------------------------------------
# policy_literals - what a denial must not echo
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "restriction,expected",
    [
        ({"type": "string", "enum": ["A", "B"]}, {"A", "B"}),
        ({"type": "string", "const": "C"}, {"C"}),
        ({"type": "string", "pattern": "P"}, {"P"}),
        ("bare-string-restriction", {"bare-string-restriction"}),
        ({"type": "object", "properties": {"x": {"const": "nested"}}}, {"nested"}),
        ({"type": "array", "items": {"enum": ["inside"]}}, {"inside"}),
        ({"anyOf": [{"const": "one"}, {"const": "two"}]}, {"one", "two"}),
        ({"type": "string", "format": "email"}, set()),  # names no concrete value
    ],
)
def test_policy_literals_extracts_concrete_values(restriction, expected):
    policy = {"t": [(100, 0, {"arg": restriction}, 0)]}
    assert policy_literals(policy, "t") == expected


def test_policy_literals_is_empty_for_unknown_tool():
    assert policy_literals(_enum_policy(), "not_a_tool") == set()


# --------------------------------------------------------------------------
# The engines leak
# --------------------------------------------------------------------------


def test_progent_denial_discloses_value_schema_and_routing(progent):
    policy, args = _enum_policy(), {"recipient": DENIED}
    verdict = progent.would_allow(policy, "send_money", args)
    found = progent.discloses_policy(verdict, policy, "send_money", args)

    assert found is not None and found.leaked
    assert found.leaked_literals == [ALLOWED]
    assert found.discloses_schema, "Progent re-raises the raw jsonschema error"
    assert found.agent_routed, "and appends its own instruction for the model to read"
    assert found.enforcer == "progent"


def test_janus_leaks_through_the_generic_check_with_no_janus_specific_code(janus):
    """The cross-engine claim, made structurally rather than asserted.

    `JanusEnforcer` defines no disclosure logic whatsoever - it inherits
    `BaseEnforcer.discloses_policy` untouched. That the generic "do the policy's
    own literals appear in the agent-visible text?" check finds Janus leaking is
    the evidence that disclosure is a property of the architecture rather than
    of one team's error handling.
    """
    assert "discloses_policy" not in vars(type(janus)), "Janus must need no override"
    assert "_discloses_schema" not in vars(type(janus))

    policy, args = _enum_policy(), {"recipient": DENIED}
    verdict = janus.would_allow(policy, "send_money", args)
    found = janus.discloses_policy(verdict, policy, "send_money", args)

    assert found is not None and found.leaked
    assert found.leaked_literals == [ALLOWED]
    assert found.enforcer == "janus"


def test_janus_leaks_at_every_priority_where_progent_leaks_only_at_100(progent, janus):
    """A real cross-engine difference, and it runs against Janus.

    Progent's schema dump is scoped to priority-100 rules; Janus surfaces the
    failing constraint at any priority. Progent's scoping is not a mitigation in
    practice - 100 is where every generated rule lands - but it does mean an
    operator's hand-written low-priority rule denies silently under Progent and
    loudly under Janus.
    """
    conditions = {"recipient": {"type": "string", "enum": [ALLOWED]}}
    args = {"recipient": DENIED}
    for priority in (1, 50):
        policy = {"send_money": [(priority, 0, conditions, 0)]}
        assert ALLOWED not in progent.would_allow(policy, "send_money", args).agent_visible_error
        assert ALLOWED in janus.would_allow(policy, "send_money", args).agent_visible_error


# --------------------------------------------------------------------------
# Negative controls
# --------------------------------------------------------------------------


def test_an_allow_is_never_a_disclosure(progent):
    """No denial text, no finding - and None, not an empty record.

    "Did not leak" and "had no refusal to leak on" must stay distinguishable in
    the aggregate, or an engine that admits everything scores as discreet.
    """
    policy = _enum_policy()
    args = {"recipient": ALLOWED}
    verdict = progent.would_allow(policy, "send_money", args)
    assert verdict.allowed
    assert progent.discloses_policy(verdict, policy, "send_money", args) is None


def test_the_strict_reference_never_discloses():
    """The sound matcher has no agent-facing channel, so it cannot leak into one."""
    strict = StrictEnforcer()
    policy, args = _enum_policy(), {"recipient": DENIED}
    verdict = strict.would_allow(policy, "send_money", args)
    assert not verdict.allowed
    assert strict.discloses_policy(verdict, policy, "send_money", args) is None


def test_a_silent_denial_is_not_a_disclosure():
    """An engine that refuses without quoting the policy produces no finding.

    This is the behaviour the mitigation should produce, so it must be
    representable: the check has to be capable of returning "refused, leaked
    nothing", or a 100% leak rate would be an artifact of the detector.
    """

    class SilentEngine(BaseEnforcer):
        name = "silent"

        def would_allow(self, policy, tool_name, args):
            return Verdict(False, "denied", agent_visible_error="The tool is not allowed.")

    engine = SilentEngine()
    policy, args = _enum_policy(), {"recipient": DENIED}
    verdict = engine.would_allow(policy, "send_money", args)
    assert not verdict.allowed
    assert engine.discloses_policy(verdict, policy, "send_money", args) is None


# --------------------------------------------------------------------------
# The finding
# --------------------------------------------------------------------------


def test_the_sound_idiom_is_the_disclosing_idiom(progent):
    """The cross that makes C1 a finding rather than a footnote.

    Measured on the real corpus: `enum`-exact is the ONE idiom the differential
    cannot bypass (0% of 95 fragments) and it is also the idiom whose refusal
    quotes its permitted value back verbatim. The loose idioms leak too, but
    their disclosure is moot - an attacker never has to ask a policy that is
    already bypassable. Security-by-exact-match and disclosure-of-the-exact-match
    turn out to be the same property.
    """
    from agentdojo.task_suite.load_suites import get_suites
    from src.gapfuzz.sweep import run_sweep

    report = run_sweep({"slack": get_suites("v1")["slack"]}, progent)

    enum_style = report.styles["enum-exact"]
    assert enum_style.bypassable_fragments == 0, "the sound control must stay sound"
    assert enum_style.denied_probes == enum_style.fragments
    assert enum_style.leak_rate == 1.0, "and yet it discloses on every refusal"

    # `format`-only admits everything, so it never refuses and cannot leak. That
    # is undefined, not 0% - crediting it with discretion would be wrong.
    assert report.styles["format-only"].denied_probes == 0
    assert report.styles["format-only"].leak_rate == 0.0

    # C1 evidence never contaminates the admittance tables.
    assert all(d.gap_class is GapClass.C1_BOUNDARY_DISCLOSURE for d in report.disclosures)
    assert "C1_boundary_disclosure" not in enum_style.gap_counts


def test_disclosure_instances_serialize(progent):
    """The evidence has to survive into the JSON a reviewer reads."""
    from agentdojo.task_suite.load_suites import get_suites
    from src.gapfuzz.sweep import run_sweep

    report = run_sweep({"slack": get_suites("v1")["slack"]}, progent)
    assert report.disclosures
    row = report.disclosures[0].as_dict()
    assert row["gap_class"] == "C1_boundary_disclosure"
    assert row["leaked_literals"] and row["leak_fraction"] == 1.0
    assert row["denial_text"]
