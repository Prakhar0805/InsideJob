"""Measure what hardening costs in false positives - for free.

A mitigation that blocks the attack but also breaks legitimate work is not a
mitigation. The original project made "never report ASR without Utility" a
standing rule; the same discipline applies here. The good news is that on the
enforcement side, utility is checkable with zero LLM calls: a policy preserves a
user task's utility iff it still *admits that task's own ground-truth calls*. If
hardening rejects a call the legitimate task needs, that is a measurable false
positive.

So for each user task we:

    1. build the least-privilege policy for it (from its own ground truth);
    2. harden that policy with `policy_lint`;
    3. check the hardened policy still admits every ground-truth call.

Any rejection is a utility loss attributable to a specific hardening rule -
usually the A5 "deny unnamed arguments" fix, which is exactly why that fix is
opt-in and reported separately.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from agentdojo.functions_runtime import FunctionCall
from agentdojo.task_suite.task_suite import TaskSuite

from src.enforcers.strict import StrictEnforcer
from src.gapfuzz.harm_sweep import _natural_policy_for
from src.harm_oracle import CONFOUNDED_USER_TASKS


@dataclass
class UtilityResult:
    suite: str
    user_task_id: str
    preserved: bool
    rejected_calls: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class UtilityReport:
    deny_unknown_args: bool
    results: list[UtilityResult] = field(default_factory=list)

    @property
    def n(self) -> int:
        return len(self.results)

    @property
    def n_preserved(self) -> int:
        return sum(1 for r in self.results if r.preserved)

    @property
    def preservation_rate(self) -> float:
        return self.n_preserved / self.n if self.n else 1.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "deny_unknown_args": self.deny_unknown_args,
            "n_user_tasks": self.n,
            "n_preserved": self.n_preserved,
            "preservation_rate": round(self.preservation_rate, 4),
            "false_positives": [
                {"suite": r.suite, "user_task": r.user_task_id, "rejected": r.rejected_calls}
                for r in self.results
                if not r.preserved
            ],
        }

    def render(self) -> str:
        lines = [
            f"utility cost of hardening (deny_unknown_args={self.deny_unknown_args}):",
            f"  user tasks checked : {self.n}",
            f"  utility preserved  : {self.n_preserved} ({self.preservation_rate:.0%})",
        ]
        losses = [r for r in self.results if not r.preserved]
        if losses:
            lines.append(f"  false positives    : {len(losses)}")
            for r in losses[:20]:
                lines.append(f"    - {r.suite}/{r.user_task_id}: rejected {', '.join(r.rejected_calls)}")
            if len(losses) > 20:
                lines.append(f"    ... and {len(losses) - 20} more")
        return "\n".join(lines)


def measure_utility_cost(
    suites: dict,
    *,
    deny_unknown_args: bool = True,
) -> UtilityReport:
    """For every user task, does its own hardened least-privilege policy still admit it?

    The hardened matcher is the strict reference (the linter's deployable form).
    Using the task's own ground truth as both the policy source and the
    admittance target isolates the *hardening* cost: an unhardened natural policy
    admits its own ground truth by construction, so any rejection after hardening
    is caused by the tightening, not by the policy being wrong.
    """
    from src.policy_lint import harden_policy

    report = UtilityReport(deny_unknown_args=deny_unknown_args)
    reference = StrictEnforcer(deny_unknown_args=deny_unknown_args)

    for suite in suites.values():
        environment = suite.load_and_inject_default_environment({})
        for user_task in suite.user_tasks.values():
            if (suite.name, user_task.ID) in CONFOUNDED_USER_TASKS:
                continue
            try:
                calls = list(user_task.ground_truth(environment.model_copy(deep=True)))
            except Exception as exc:  # noqa: BLE001
                report.results.append(
                    UtilityResult(suite.name, user_task.ID, preserved=True, note=f"no ground truth ({exc})")
                )
                continue

            effectful = [c for c in calls if _is_effectful(c)]
            if not effectful:
                report.results.append(
                    UtilityResult(suite.name, user_task.ID, preserved=True, note="read-only task")
                )
                continue

            policy = harden_policy(_natural_policy_for(effectful), deny_unknown_args=deny_unknown_args)
            rejected = [
                c.function
                for c in effectful
                if not reference.would_allow(policy, c.function, c.args).allowed
            ]
            report.results.append(
                UtilityResult(
                    suite.name, user_task.ID, preserved=not rejected, rejected_calls=rejected
                )
            )

    return report


def _is_effectful(call: FunctionCall) -> bool:
    read_prefixes = ("get_", "read_", "search_", "list_", "check_", "find_", "retrieve_")
    return not call.function.startswith(read_prefixes)
