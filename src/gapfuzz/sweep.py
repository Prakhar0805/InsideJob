"""The differential sweep: how much larger is the admitted set than the policy?

For every policy fragment in the corpus, mutate the intended value with the gap
operators and record every variant the enforcer admits but the strict reference
rejects. Aggregated by policy *style*, this answers the Phase-A question with a
large, free sample:

    - how often is each natural policy idiom bypassable?
    - which gap class does each bypass exploit?
    - does the one sound idiom (an exact enum) resist, as it should?

This is pure matcher behaviour - no AgentDojo, no harm oracle, no LLM. The harm
oracle (Phase B) then confirms that these admitted-but-unintended calls actually
achieve attacker objectives on the real tasks.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator

from src.enforcers.base import DisclosureInstance, EnforcerAdapter, GapInstance
from src.enforcers.strict import StrictEnforcer
from src.gapfuzz.attribution import attribute
from src.gapfuzz.corpus import PolicyFragment, suite_corpus
from src.gapfuzz.operators import mutate_call

#: A value no policy in the corpus could plausibly permit. Sent to provoke a
#: denial so the *denial text* can be inspected; deliberately not an attack
#: payload, because this probe measures disclosure, not admittance.
DISCLOSURE_PROBE_VALUE = "ZZ00_DISCLOSURE_PROBE_0000"


def disclosure_probe(
    fragment: PolicyFragment,
    enforcer: EnforcerAdapter,
) -> tuple[bool, DisclosureInstance | None]:
    """Does this fragment's engine leak the policy when it refuses? (C1)

    Returns `(refused, disclosure)`. Free: it reuses a fragment the sweep
    already built and costs one extra check. Send an obviously-impermissible
    value for the pinned argument and inspect what comes back.

    Both halves of the return matter, and collapsing them would misreport the
    result. If the engine *admits* the probe value there is nothing to measure -
    that admission is an A-class gap, already counted by the mutation loop, and
    an engine that never refuses can never leak on refusal. `format`-only is
    exactly that case. Reporting it as "0% leaked" would credit it with
    discretion it does not have; it is reported as *undefined* instead, because
    "did not leak" and "never had the chance to leak" are different facts.
    """
    arg = fragment.pinned_arg
    if arg is None:
        return False, None
    probe_args = {arg: DISCLOSURE_PROBE_VALUE}
    verdict = enforcer.would_allow(fragment.policy, fragment.tool_name, probe_args)
    if verdict.allowed:
        return False, None
    discloses = getattr(enforcer, "discloses_policy", None)
    if discloses is None:
        return True, None
    found = discloses(verdict, fragment.policy, fragment.tool_name, probe_args)
    if found is not None:
        found.note = f"style={fragment.style}"
    return True, found


def sweep_fragment(
    fragment: PolicyFragment,
    enforcer: EnforcerAdapter,
    reference: StrictEnforcer,
) -> Iterator[GapInstance]:
    """Every admitted-but-reference-rejected variant of one policy fragment.

    The intended (benign) value is planted as the argument, then mutated. A
    variant that the enforcer admits and the reference rejects is a gap instance,
    attributed to the operator's declared class.
    """
    tool = fragment.tool_name
    arg = fragment.pinned_arg
    if arg is None:
        return
    base_args = {arg: fragment.intended_value}

    # First: does the enforcer even admit the *intended* value? If not, the
    # fragment is malformed for this engine and mutations are meaningless.
    if not enforcer.would_allow(fragment.policy, tool, base_args).allowed:
        return

    seen: set[str] = set()
    for candidate in mutate_call(base_args):
        signature = f"{candidate.hypothesis.value}:{candidate.args.get(arg)!r}"
        if signature in seen:
            continue
        seen.add(signature)

        engine_verdict = enforcer.would_allow(fragment.policy, tool, candidate.args)
        if not engine_verdict.allowed:
            continue
        ref_verdict = reference.would_allow(fragment.policy, tool, candidate.args)
        if ref_verdict.allowed:
            continue  # both admit it: not a gap
        found = attribute(fragment.policy, tool, candidate.args, hypothesis=candidate.hypothesis)
        yield GapInstance(
            gap_class=found.gap_class or candidate.hypothesis,
            enforcer=enforcer.name,
            tool_name=tool,
            policy=fragment.policy,
            args=candidate.args,
            enforcer_verdict=engine_verdict,
            strict_verdict=ref_verdict,
            attribution_method=found.method,
            co_attributed=found.candidates if len(found.candidates) > 1 else frozenset(),
            note=f"style={fragment.style}; via {candidate.rationale}",
        )


@dataclass
class StyleReport:
    """Per-policy-style bypass statistics."""

    style: str
    fragments: int = 0
    bypassable_fragments: int = 0
    gap_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    #: Fragments whose engine actually refused the disclosure probe. An idiom
    #: that admits everything (`format`-only) never refuses, so it has no
    #: opportunity to leak - counted separately from refusing-but-silent.
    denied_probes: int = 0
    #: Of those refusals, how many handed the policy back to the agent.
    leaked: int = 0

    @property
    def bypass_rate(self) -> float:
        return self.bypassable_fragments / self.fragments if self.fragments else 0.0

    @property
    def leak_rate(self) -> float:
        """Share of *refusals* that disclosed. Denominator is denied_probes, not
        fragments: an idiom that never refuses is undefined here, not 0%."""
        return self.leaked / self.denied_probes if self.denied_probes else 0.0


@dataclass
class SweepReport:
    """The full differential result for one enforcer over one or more suites."""

    enforcer: str
    styles: dict[str, StyleReport] = field(default_factory=dict)
    instances: list[GapInstance] = field(default_factory=list)
    invariant_violations: int = 0
    #: Attribution quality, reported so a per-class table can be trusted. An
    #: instance denied by two independent fixes is `over_determined`; one the
    #: full reference denies but no fix isolates is `unattributed`.
    over_determined: int = 0
    unattributed: int = 0
    #: C1 evidence. Kept in its own list, never in `instances`: a GapInstance is
    #: an admittance record and requires the engine to have allowed, while every
    #: one of these is a denial. Two findings, two record types, one report.
    disclosures: list[DisclosureInstance] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            f"differential sweep: enforcer={self.enforcer}",
            f"{'policy style':<18} {'fragments':>9} {'bypassable':>11} {'rate':>7}  gap classes",
            "-" * 78,
        ]
        for style in sorted(self.styles):
            r = self.styles[style]
            gaps = ", ".join(f"{k}x{v}" for k, v in sorted(r.gap_counts.items()))
            lines.append(
                f"{style:<18} {r.fragments:>9} {r.bypassable_fragments:>11} {r.bypass_rate:>6.0%}  {gaps}"
            )
        lines.append("-" * 78)
        lines.append(f"total gap instances: {len(self.instances)}")
        lines.append(
            f"attribution: {self.over_determined} over-determined, "
            f"{self.unattributed} unattributed"
        )
        if self.invariant_violations:
            lines.append(
                f"!! {self.invariant_violations} reference-soundness violations - see log; results suspect"
            )
        else:
            lines.append("reference invariant held: strict never admitted what the engine denied")

        lines.extend(self._render_disclosure())
        return "\n".join(lines)

    def _render_disclosure(self) -> list[str]:
        """The C1 block, kept visually apart so it is never read as a bypass rate.

        Two different questions - "can the admitted set be widened?" and "does a
        refusal quote the policy back?" - measured over the same fragments.
        Conflating them into one table would be the exact error this project
        exists to point out in others.
        """
        probed = sum(r.denied_probes for r in self.styles.values())
        if not probed:
            return ["", "boundary disclosure (C1): no refusals to inspect"]

        lines = [
            "",
            "boundary disclosure (C1) - what a REFUSAL hands back to the agent",
            f"{'policy style':<18} {'refusals':>9} {'leaked':>7} {'rate':>7}  discloses",
            "-" * 78,
        ]
        for style in sorted(self.styles):
            r = self.styles[style]
            if not r.denied_probes:
                lines.append(
                    f"{style:<18} {0:>9} {'-':>7} {'n/a':>7}  never refuses, so never leaks"
                )
                continue
            sample = next(
                (d for d in self.disclosures if d.note == f"style={style}"), None
            )
            what = []
            if sample and sample.leaked_literals:
                what.append("the permitted value")
            if sample and sample.discloses_schema:
                what.append("the schema fragment")
            if sample and sample.agent_routed:
                what.append("routed to the agent")
            lines.append(
                f"{style:<18} {r.denied_probes:>9} {r.leaked:>7} {r.leak_rate:>6.0%}  "
                f"{', '.join(what) or '-'}"
            )
        lines.append("-" * 78)

        # The cross that makes this a finding rather than a footnote.
        sound = [s for s, r in self.styles.items() if r.fragments and not r.bypassable_fragments]
        leaky_sound = [s for s in sound if self.styles[s].leaked]
        if leaky_sound:
            lines.append(
                f"NOTE: {', '.join(sorted(leaky_sound))} is the only idiom the differential "
                "cannot bypass (0%),"
            )
            lines.append(
                "      and it is the one whose refusal quotes its permitted value back. The "
                "other idioms"
            )
            lines.append(
                "      leak too, but an attacker never has to ask - they are already bypassable."
            )
        return lines


def run_sweep(
    suites: dict,
    enforcer: EnforcerAdapter,
    *,
    reference: StrictEnforcer | None = None,
) -> SweepReport:
    """Run the differential sweep for one enforcer across the given suites."""
    reference = reference or StrictEnforcer()
    report = SweepReport(enforcer=enforcer.name)

    for suite in suites.values():
        for fragment in suite_corpus(suite):
            style = report.styles.setdefault(fragment.style, StyleReport(fragment.style))
            style.fragments += 1

            # Reference-soundness invariant, checked on the intended value: the
            # reference must never be more permissive than the engine.
            if fragment.pinned_arg is not None:
                base = {fragment.pinned_arg: fragment.intended_value}
                if (
                    reference.would_allow(fragment.policy, fragment.tool_name, base).allowed
                    and not enforcer.would_allow(fragment.policy, fragment.tool_name, base).allowed
                ):
                    report.invariant_violations += 1

            # C1: what does this engine say when it *refuses*? Orthogonal to the
            # mutation loop below, which measures what it wrongly *admits*.
            refused, disclosure = disclosure_probe(fragment, enforcer)
            if refused:
                style.denied_probes += 1
                if disclosure is not None:
                    style.leaked += 1
                    report.disclosures.append(disclosure)

            hit = False
            for instance in sweep_fragment(fragment, enforcer, reference):
                report.instances.append(instance)
                style.gap_counts[instance.gap_class.value] += 1
                if instance.attribution_method == "over-determined":
                    report.over_determined += 1
                elif instance.attribution_method == "unattributed":
                    report.unattributed += 1
                hit = True
            if hit:
                style.bypassable_fragments += 1

    return report
