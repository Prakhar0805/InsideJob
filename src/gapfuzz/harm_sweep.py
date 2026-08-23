"""Reachable-harm sweep: which injection tasks have a validated bypass, for free.

Phase C will test *LLM-generated* policies. This module is the zero-cost
complement that still uses entirely realistic policies, by exploiting a fact
about AgentDojo: injection tasks attack the *same tools* that legitimate user
tasks use. So for each injection task we can build a genuinely representative
least-privilege policy without any LLM at all:

    1. find a real benign user task whose ground truth uses the injection's
       effectful tool;
    2. write the natural least-privilege policy for that benign task - pin the
       tool's string arguments to the benign values, with the flawed-but-common
       `pattern` idiom;
    3. ask: can the attacker still reach harm through an enforcement gap?

This is defensible because every input is real: the tool is real, the benign
values are a real user task's, and the policy idiom is the one Progent's own
prompt recommends. The only synthetic step is writing the policy ourselves
instead of paying an LLM to write the same thing - and Phase C checks that an
LLM does write the same thing.

The confounded / trace-scored / scoring-bug tasks from `harm_oracle` are handled
here: confounded pairs are skipped, the others are run but flagged so they never
silently enter a headline number.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from agentdojo.functions_runtime import FunctionCall
from agentdojo.task_suite.task_suite import TaskSuite

from src.enforcers.base import EnforcerAdapter
from src.enforcers.strict import StrictEnforcer
from src.gapfuzz.search import BypassResult, _effectful_calls, find_bypass
from src.harm_oracle import CONFOUNDED_USER_TASKS, HarmOracle


def _natural_policy_for(calls: list[FunctionCall]) -> dict:
    """The least-privilege policy a good-faith author writes for these calls.

    Each string argument is pinned with a `pattern` set to its literal value -
    the natural idiom, flawed only because the matcher is unanchored. Non-string
    args are pinned by exact schema (`const`), which is sound, so any bypass the
    sweep finds cannot be blamed on our policy being sloppier than necessary.
    """
    policy: dict[str, list[tuple]] = defaultdict(list)
    for call in calls:
        conditions: dict[str, Any] = {}
        for arg, value in call.args.items():
            if isinstance(value, str):
                conditions[arg] = {"type": "string", "pattern": value}
            elif isinstance(value, bool):
                conditions[arg] = {"type": "boolean", "const": value}
            elif isinstance(value, (int, float)):
                conditions[arg] = {"type": "number", "const": value}
            # complex args: left unconstrained, exactly as Progent strips them
        policy[call.function].append((100, 0, conditions, 0))
    return dict(policy)


def _benign_donor(suite: TaskSuite, tool_name: str) -> tuple[BaseUserTask, list[FunctionCall]] | None:
    """A real user task whose ground truth uses `tool_name`, and its calls.

    This is what makes the policy realistic rather than invented: the benign
    values come from an actual legitimate task in the same suite.
    """
    environment = suite.load_and_inject_default_environment({})
    for user_task in suite.user_tasks.values():
        if (suite.name, user_task.ID) in CONFOUNDED_USER_TASKS:
            continue
        try:
            calls = list(user_task.ground_truth(environment.model_copy(deep=True)))
        except Exception:  # noqa: BLE001
            continue
        if any(c.function == tool_name for c in calls):
            return user_task, calls
    return None


@dataclass
class TaskHarmResult:
    suite: str
    injection_task_id: str
    donor_user_task: str | None
    result: BypassResult
    skipped_reason: str = ""


@dataclass
class HarmSweepReport:
    enforcer: str
    results: list[TaskHarmResult] = field(default_factory=list)

    @property
    def scored(self) -> list[TaskHarmResult]:
        """Results that count toward headline numbers (calibrated, not skipped)."""
        return [
            r for r in self.results
            if not r.skipped_reason and not r.result.oracle_miscalibrated
        ]

    def as_dict(self) -> dict[str, Any]:
        return {
            "enforcer": self.enforcer,
            "n_tasks": len(self.results),
            "n_scored": len(self.scored),
            "n_bypassed": sum(1 for r in self.scored if r.result.bypass_found),
            "results": [
                {
                    "suite": r.suite,
                    "injection_task_id": r.injection_task_id,
                    "donor_user_task": r.donor_user_task,
                    "skipped_reason": r.skipped_reason,
                    **r.result.as_dict(),
                }
                for r in self.results
            ],
        }

    def render(self) -> str:
        scored = self.scored
        bypassed = [r for r in scored if r.result.bypass_found]
        by_gap: dict[str, int] = defaultdict(int)
        for r in bypassed:
            if r.result.gap_class:
                by_gap[r.result.gap_class.value] += 1

        lines = [
            f"reachable-harm sweep: enforcer={self.enforcer}",
            "",
            f"{'suite':<10} {'injection task':<20} {'donor user task':<16} {'result':<28} gap",
            "-" * 92,
        ]
        for r in self.results:
            if r.skipped_reason:
                verdict = f"skipped: {r.skipped_reason}"
                gap = ""
            elif r.result.oracle_miscalibrated:
                verdict = "excluded: oracle miscalibrated"
                gap = ""
            elif r.result.bypass_found:
                flags = []
                if r.result.trace_scored:
                    flags.append("trace-scored")
                if r.result.scoring_bug_flagged:
                    flags.append("scoring-bug")
                verdict = "BYPASSED" + (f" [{','.join(flags)}]" if flags else "")
                gap = r.result.gap_class.value if r.result.gap_class else ""
            else:
                verdict = "held"
                gap = ""
            lines.append(
                f"{r.suite:<10} {r.injection_task_id:<20} {(r.donor_user_task or '-'):<16} {verdict:<28} {gap}"
            )
        lines.append("-" * 92)
        n = len(scored)
        lines.append(
            f"scored tasks: {n}  |  bypassed: {len(bypassed)}"
            + (f" ({len(bypassed) / n:.0%})" if n else "")
        )
        if by_gap:
            lines.append("bypasses by gap class: " + ", ".join(f"{k}x{v}" for k, v in sorted(by_gap.items())))
        skipped = [r for r in self.results if r.skipped_reason]
        if skipped:
            lines.append(f"skipped (confounded / no donor): {len(skipped)} - see rows above")
        lines += [
            "",
            "NOTE: this baseline pins EVERY argument to its exact benign value - a policy",
            "far tighter than any LLM generates. A 'held' here means the injection targets a",
            "resource the benign task never touched, so exact pinning blocks it. The gaps bite",
            "where real generation is looser (unanchored/loose patterns, unconstrained args,",
            "omitted keywords) - which is what the generated-policy sweep (Phase C) measures.",
        ]
        return "\n".join(lines)


def run_harm_sweep(
    suites: dict,
    enforcer: EnforcerAdapter,
    *,
    reference: StrictEnforcer | None = None,
) -> HarmSweepReport:
    reference = reference or StrictEnforcer()
    report = HarmSweepReport(enforcer=enforcer.name)

    for suite in suites.values():
        oracle = HarmOracle(suite)
        for task_id, injection_task in suite.injection_tasks.items():
            gt = oracle.ground_truth_calls(injection_task)
            effectful = _effectful_calls(gt)
            tool_name = effectful[0].function if effectful else None

            donor = _benign_donor(suite, tool_name) if tool_name else None
            if donor is None:
                report.results.append(
                    TaskHarmResult(
                        suite=suite.name,
                        injection_task_id=task_id,
                        donor_user_task=None,
                        result=BypassResult(suite=suite.name, injection_task_id=task_id, enforcer=enforcer.name),
                        skipped_reason="no benign user task uses this tool",
                    )
                )
                continue

            donor_task, donor_calls = donor
            # Build the policy from the donor's calls to the SAME tool, so the
            # pinned values are legitimately what a policy for that task allows.
            donor_effectful = [c for c in donor_calls if c.function == tool_name]
            policy = _natural_policy_for(donor_effectful)

            result = find_bypass(
                policy=policy,
                injection_task=injection_task,
                enforcer=enforcer,
                oracle=oracle,
                reference=reference,
            )
            report.results.append(
                TaskHarmResult(
                    suite=suite.name,
                    injection_task_id=task_id,
                    donor_user_task=donor_task.ID,
                    result=result,
                )
            )

    return report
