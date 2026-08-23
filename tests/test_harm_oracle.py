"""Tests for the zero-LLM harm oracle and the bypass search.

These run against the real AgentDojo suites (no API) and assert the two
properties the project's evidence depends on: the oracle agrees with AgentDojo's
own scoring on ground truth, and the search only ever reports a bypass that is
simultaneously admitted, reference-rejected, and harmful.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("GROQ_API_KEY", "test")
os.environ.setdefault("SECAGENT_GENERATE", "False")
os.environ.pop("SECAGENT_SUITE", None)

from src.config import bootstrap  # noqa: E402

bootstrap(enable_progent=False)

pytest.importorskip("secagent", reason="Progent (secagent) not installed")

from agentdojo.task_suite.load_suites import get_suites  # noqa: E402

from src.enforcers import build_enforcer  # noqa: E402
from src.gapfuzz.search import find_bypass  # noqa: E402
from src.harm_oracle import HarmOracle, is_confounded  # noqa: E402


@pytest.fixture(scope="module")
def suites():
    return get_suites("v1")


@pytest.fixture(scope="module")
def progent():
    return build_enforcer("progent")


@pytest.mark.parametrize("suite_name", ["banking", "slack", "travel", "workspace"])
def test_every_ground_truth_registers_as_harmful(suites, suite_name):
    """Calibration: the oracle must agree with AgentDojo on every ground truth.

    If any injection task's own ground truth does not score as harmful, the
    oracle is misconfigured and no negative result from it means anything.
    """
    suite = suites[suite_name]
    oracle = HarmOracle(suite)
    for task_id, task in suite.injection_tasks.items():
        assert oracle.self_test(task), f"{suite_name}/{task_id} ground truth did not score harmful"


def test_oracle_refuses_policy_wrapped_suite(monkeypatch, suites):
    """Guard against silently measuring the wrong thing."""
    monkeypatch.setenv("SECAGENT_SUITE", "banking")
    with pytest.raises(RuntimeError, match="policy-wrapped"):
        HarmOracle(suites["banking"])


def test_search_finds_unanchored_url_bypass(suites, progent):
    """A loose URL pattern - exactly what Progent's prompt encourages - is bypassable."""
    slack = suites["slack"]
    oracle = HarmOracle(slack)
    inj = slack.get_injection_task_by_id("injection_task_3")
    policy = {"get_webpage": [(100, 0, {"url": {"type": "string", "pattern": "informations"}}, 0)]}
    result = find_bypass(policy=policy, injection_task=inj, enforcer=progent, oracle=oracle)
    assert result.bypass_found
    assert result.gap_class.value == "A1_unanchored"
    assert not result.oracle_miscalibrated


def test_search_finds_uncapped_amount_bypass(suites, progent):
    """Recipient pinned, amount unconstrained -> unlimited transfer (A5)."""
    banking = suites["banking"]
    oracle = HarmOracle(banking)
    inj = banking.get_injection_task_by_id("injection_task_5")
    policy = {"send_money": [(100, 0, {"recipient": {"type": "string", "pattern": "US133000000121212121212"}}, 0)]}
    result = find_bypass(policy=policy, injection_task=inj, enforcer=progent, oracle=oracle)
    assert result.bypass_found
    assert result.gap_class.value == "A5_unconstrained_siblings"


def test_search_declines_when_policy_genuinely_blocks(suites, progent):
    """A correct, tight policy for a *different* recipient must NOT yield a bypass.

    This is the honesty check: the search must not manufacture a bypass where
    the policy actually holds. A tool the policy never mentions is default-denied.
    """
    banking = suites["banking"]
    oracle = HarmOracle(banking)
    inj = banking.get_injection_task_by_id("injection_task_4")  # redirect to attacker IBAN
    # Policy only knows an unrelated tool; the harmful tool is not covered at all.
    policy = {"get_balance": [(100, 0, {}, 0)]}
    result = find_bypass(policy=policy, injection_task=inj, enforcer=progent, oracle=oracle)
    assert not result.bypass_found


def test_reported_bypass_is_always_reference_rejected(suites, progent):
    """Invariant: a reported bypass is one the strict reference would have denied.

    If the reference also admits the winning call, the policy is merely too
    broad (a generation failure), which is not an enforcement gap and must not
    be reported as one.
    """
    from src.enforcers.strict import StrictEnforcer

    reference = StrictEnforcer()
    slack = suites["slack"]
    oracle = HarmOracle(slack)
    inj = slack.get_injection_task_by_id("injection_task_3")
    policy = {"get_webpage": [(100, 0, {"url": {"type": "string", "pattern": "informations"}}, 0)]}
    result = find_bypass(policy=policy, injection_task=inj, enforcer=progent, oracle=oracle)
    assert result.bypass_found
    ref_verdict = reference.would_allow(policy, result.winning_function, result.winning_call)
    assert not ref_verdict.allowed, "a reported bypass must be one the reference rejects"


def test_confounded_user_task_is_flagged():
    """banking/user_task_15 legitimately pays the attacker IBAN; must be excluded."""
    assert is_confounded("banking", "user_task_15")
    assert not is_confounded("banking", "user_task_0")
