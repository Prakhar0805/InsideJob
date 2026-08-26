"""Attribute a gap instance to the reference fix (or fixes) responsible for it.

The differential tells us an engine admitted a call a sound matcher would deny.
Attribution answers the next question: *which* soundness fix is the one the
engine is missing? That is what lets the write-up print a per-class table
instead of a single lump count, and what lets a reader trust that "A1: 380" is a
claim about anchoring specifically rather than about "something in here".

The method is isolation, not the operator's guess. The mutation operator that
*produced* a candidate declares a hypothesis about which gap it probes, but the
operator is often wrong about which gap actually *admits* the result: a payload
appended to a `format`-only policy is admitted because `format` is never
enforced (A4), not because of anchoring (A1), even though an A1 suffix operator
made it. So we run the strict reference with one fix enabled at a time and let
the reference tell us which fix flips the verdict from allow to deny.

Two properties this module is careful about, because both are ways to lie with a
per-class table:

*   **Not-a-gap rejection.** Probing an *irrelevant* fix yields the unfixed
    semantics. If the unfixed reference already denies the call, every probe
    denies and a naive "count the deniers" reads as "all ten classes at once".
    So attribution first checks that the *no-fix* baseline admits the call (else
    the call is denied by baseline semantics — not our gap) and that the *full*
    reference denies it (else there is nothing to attribute).
*   **Over-determination, reported not hidden.** When two independent fixes each
    deny the call, that is a real fact about the call, not noise. We surface the
    full set and pick a deterministic representative (lowest by enum order) as a
    documented tie-break — never as a claim that the others are not also causes.

Everything here is pure matcher evaluation: no engine, no LLM, no network. The
probes are memoised, so attributing all 760 instances adds a fraction of a
second to the sweep.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence

from src.enforcers.base import GapClass, PERMISSIVE_GAPS, Policy
from src.enforcers.strict import ALL_FIXES, StrictEnforcer

#: How attribution reached its verdict. Carried on every result so a reviewer
#: can tell an isolated finding from a tie-broken one at a glance.
AttributionMethod = Literal[
    "isolated",  # exactly one fix denies — the clean, overwhelming-majority case
    "over-determined",  # two or more fixes each independently deny
    "leave-one-out",  # no single fix denies, but removing one from the full set admits
    "unattributed",  # the full reference denies yet no fix is pinpointable
    "not-a-gap",  # baseline already denies, or the full reference admits: nothing to attribute
]

#: The gaps attribution will probe, in enum-declaration order. Restricted to the
#: *permissive* classes (the ones a StrictEnforcer actually fixes); a
#: disclosure-only class such as C1 is not an admittance gap and has no fix to
#: isolate, so it is excluded here automatically once it joins the enum.
_CANDIDATE_GAPS: tuple[GapClass, ...] = tuple(g for g in GapClass if g in PERMISSIVE_GAPS)


@dataclass(frozen=True)
class Attribution:
    """The fix (or fixes) responsible for a differential disagreement."""

    gap_class: GapClass | None
    method: AttributionMethod
    #: Every fix that independently flips the verdict. A single-element set for
    #: an isolated finding; the full contended set for an over-determined one;
    #: empty when nothing was attributed.
    candidates: frozenset[GapClass]


#: Memoised probe enforcers, keyed on their fix set. Attribution builds ~20
#: probes per candidate (one per fix, plus leave-one-out); without caching that
#: is thousands of identical StrictEnforcer constructions across a sweep.
_PROBES: dict[frozenset[GapClass], StrictEnforcer] = {}


def _probe(fixes: frozenset[GapClass]) -> StrictEnforcer:
    """A reference with exactly `fixes` enabled.

    `deny_unknown_args` is held True on every probe so that only `fixes` varies.
    That is not the same as always-on A5: both A5 sites are additionally gated on
    `fixes_gap(A5)`, so with A5 absent from `fixes` the flag does nothing. Fixing
    it removes a confusing second knob from the isolation loop without changing
    any verdict (verified: the 760-instance distribution is unchanged).
    """
    enforcer = _PROBES.get(fixes)
    if enforcer is None:
        enforcer = StrictEnforcer(fixes=fixes, deny_unknown_args=True)
        _PROBES[fixes] = enforcer
    return enforcer


def attribute(
    policy: Policy,
    tool_name: str,
    args: Mapping[str, Any],
    *,
    hypothesis: GapClass | None = None,
) -> Attribution:
    """Name the reference fix responsible for denying `(tool_name, args)`.

    Args:
        policy, tool_name, args: the call to attribute.
        hypothesis: the operator's declared class, used only as the last-resort
            label when isolation is inconclusive.

    The passes run cheapest-first and short-circuit:

    0.  **Guards.** The no-fix baseline must admit the call (else baseline
        semantics already deny it and it is not our gap) and the full reference
        must deny it (else the sound matcher admits it and there is nothing to
        attribute). Either failure returns ``not-a-gap``.
    1.  **Isolate.** Enable one fix at a time. Exactly one denier is the clean
        ``isolated`` case; two or more is ``over-determined`` with the full set
        carried and the enum-lowest chosen as a documented tie-break.
    2.  **Leave-one-out.** Reached only when no single fix denies although the
        full set does — i.e. fixes cooperating. The fix whose *removal* re-admits
        the call is responsible. No input reaches this under today's semantics,
        which are orthogonal per fix; it exists for the cooperative denials that
        Track 3's policy-shape corpus will introduce.
    3.  **Unattributed.** The full reference denies, no fix is pinpointable; fall
        back to the operator's `hypothesis`.
    """
    def denies(fixes: frozenset[GapClass]) -> bool:
        return not _probe(fixes).would_allow(policy, tool_name, args).allowed

    # Pass 0 - guards.
    if denies(frozenset()):
        return Attribution(None, "not-a-gap", frozenset())
    if not denies(ALL_FIXES):
        return Attribution(None, "not-a-gap", frozenset())

    # Pass 1 - isolate. Built in enum order, so `single[0]` is the tie-break rep.
    single = [g for g in _CANDIDATE_GAPS if denies(frozenset({g}))]
    if len(single) == 1:
        return Attribution(single[0], "isolated", frozenset(single))
    if len(single) >= 2:
        return Attribution(single[0], "over-determined", frozenset(single))

    # Pass 2 - leave-one-out. A fix is responsible if removing it re-admits.
    responsible = [g for g in _CANDIDATE_GAPS if not denies(ALL_FIXES - frozenset({g}))]
    if responsible:
        return Attribution(responsible[0], "leave-one-out", frozenset(responsible))

    # Pass 3 - the full reference denies but no fix isolates it.
    return Attribution(hypothesis, "unattributed", frozenset())


def attribute_calls(
    policy: Policy,
    calls: Sequence[Any],
    *,
    hypothesis: GapClass | None = None,
) -> Attribution:
    """Attribute a multi-call bypass to the first call the full reference rejects.

    The literal-bypass path in :mod:`src.gapfuzz.search` carries a *sequence* of
    ground-truth calls; a policy has to block only one of them for the bypass to
    stand. We attribute that first-rejected call with the full single-call
    machinery, so the literal path and the mutated path now attribute by the same
    rule instead of two divergent ones.
    """
    reference = _probe(ALL_FIXES)
    for call in calls:
        if not reference.would_allow(policy, call.function, call.args).allowed:
            return attribute(policy, call.function, call.args, hypothesis=hypothesis)
    return Attribution(None, "not-a-gap", frozenset())
