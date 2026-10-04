"""Tests for the free utility-cost measurement.

The headline mitigation claim - the policy-level fixes are free, the A5 fix is
not - is a number these tests guard against regressions in.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("GROQ_API_KEY", "test")
os.environ.setdefault("SECAGENT_GENERATE", "False")
os.environ.pop("SECAGENT_SUITE", None)

from src.config import bootstrap  # noqa: E402

bootstrap()

pytest.importorskip("secagent")

from agentdojo.task_suite.load_suites import get_suites  # noqa: E402

from src.utility_cost import measure_utility_cost  # noqa: E402


@pytest.fixture(scope="module")
def suites():
    return get_suites("v1")


def test_policy_level_hardening_is_free(suites):
    """Anchoring / types / format / literal-escaping must break no legit task.

    This is the mitigation's central claim: the cheap fixes cost nothing.
    """
    report = measure_utility_cost(suites, deny_unknown_args=False)
    assert report.preservation_rate == 1.0, (
        f"policy-level hardening lost utility on: "
        f"{[(r.suite, r.user_task_id, r.rejected_calls) for r in report.results if not r.preserved]}"
    )


def test_a5_fix_has_a_real_but_bounded_cost(suites):
    """Denying unknown args costs utility - measurably, but not catastrophically.

    The point is that the cost exists and is quantified, so the write-up can be
    honest that this fix is not free. The bound guards against a regression that
    would make it useless.
    """
    report = measure_utility_cost(suites, deny_unknown_args=True)
    assert report.preservation_rate < 1.0, "expected some false positives from the A5 fix"
    assert report.preservation_rate > 0.70, (
        f"A5 fix broke too much utility ({report.preservation_rate:.0%}); "
        "a per-tool required-args schema would be needed instead of a blanket deny"
    )
