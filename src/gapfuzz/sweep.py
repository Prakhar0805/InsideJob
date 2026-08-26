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

from src.enforcers.base import EnforcerAdapter, GapInstance
from src.enforcers.strict import StrictEnforcer
from src.gapfuzz.attribution import attribute
from src.gapfuzz.corpus import PolicyFragment, suite_corpus
from src.gapfuzz.operators import mutate_call


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

    @property
    def bypass_rate(self) -> float:
        return self.bypassable_fragments / self.fragments if self.fragments else 0.0


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
        return "\n".join(lines)


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
