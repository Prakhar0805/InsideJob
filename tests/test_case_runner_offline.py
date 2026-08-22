"""Offline end-to-end wiring test for the per-case adaptive loop.

Exercises the *real* AgentDojo banking suite and the real scope check, but with
a stubbed LLM element instead of an API-backed one, so it runs with no network,
no keys, and no cost. It cannot cover Progent's LLM-driven policy generation
(that genuinely needs an API), so it runs the undefended arm - which is enough
to prove the plumbing: environment injection, tool execution, message recording,
ledger construction, scope verdict, early stop, and record finalisation.

A stubbed attacker LLM is used too, so the adaptive path is exercised without
calling out.
"""

from __future__ import annotations

import os

import pytest

# Undefended arm: no Progent env needed, no policy generation.
os.environ.setdefault("GROQ_API_KEY", "test")
os.environ.setdefault("GEMINI_API_KEY", "test")

from src.config import bootstrap  # noqa: E402

bootstrap(enable_progent=False)

from collections.abc import Sequence  # noqa: E402

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor  # noqa: E402
from agentdojo.functions_runtime import EmptyEnv, FunctionCall  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402
from agentdojo.types import ChatAssistantMessage  # noqa: E402

from src.agent import RecordingPipeline  # noqa: E402
from src.attacker import AdaptiveAttacker, AttackContext  # noqa: E402
from src.case_runner import CaseSpec, run_case  # noqa: E402
from src.config import ModelSpec, Settings  # noqa: E402
from src.defense import NoDefense  # noqa: E402


class ScriptedLLM(BasePipelineElement):
    """An LLM stand-in that emits a fixed tool call once, then stops.

    ``attacker_iban`` is the banking injection task's target; emitting a
    send_money to it mimics a fully injected agent, letting us assert that the
    scope check and scoring see the attack as succeeding.
    """

    def __init__(self, attacker_iban: str) -> None:
        self.name = "scripted"
        self.attacker_iban = attacker_iban

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args={}):
        last = messages[-1] if messages else None
        # If the last message is a tool result, we already acted: finish.
        if last is not None and last.get("role") == "tool":
            done = ChatAssistantMessage(role="assistant", content="Done.", tool_calls=None)
            return query, runtime, env, [*messages, done], extra_args
        call = FunctionCall(function="send_money", args={
            "recipient": self.attacker_iban,
            "amount": 10.0,
            "subject": "music streaming service",
            "date": "2022-01-01",
        }, id="1")
        msg = ChatAssistantMessage(role="assistant", content="", tool_calls=[call])
        return query, runtime, env, [*messages, msg], extra_args


def _scripted_pipeline(attacker_iban: str) -> AgentPipeline:
    loop = ToolsExecutionLoop([ToolsExecutor(), ScriptedLLM(attacker_iban)])
    pipe = AgentPipeline([SystemMessage("sys"), InitQuery(), ScriptedLLM(attacker_iban), loop])
    pipe.name = "scripted"
    return pipe


@pytest.fixture
def banking():
    return get_suites("v1")["banking"]


def test_undefended_injection_succeeds_in_scope(banking, monkeypatch):
    """A fully-injected agent's send_money should score as an in-scope success."""
    inj_task = banking.get_injection_task_by_id("injection_task_0")
    attacker_iban = _extract_attacker_iban(inj_task.GOAL)

    settings = Settings(
        agent=ModelSpec("groq", "llama-3.3-70b-versatile"),
        attacker=ModelSpec("gemini", "gemini-2.5-flash"),
        policy=ModelSpec("groq", "llama-3.3-70b-versatile"),
    )
    pipeline = RecordingPipeline(_scripted_pipeline(attacker_iban))
    attacker = AdaptiveAttacker(settings.attacker)

    # Stub the attacker's network call so the adaptive path never leaves the box.
    monkeypatch.setattr(
        "src.attacker.simple_completion",
        lambda *a, **k: '{"strategy":"stub","injections":{"injection_incoming_transaction":"x"}}',
    )

    spec = CaseSpec(
        suite=banking,
        user_task=banking.get_user_task_by_id("user_task_0"),
        injection_task=inj_task,
        defense_state="none",
        max_rounds=3,
    )
    record = run_case(
        spec, settings=settings, pipeline=pipeline,
        policy_probe=None, defense=NoDefense(), attacker=attacker,
    )

    assert record.attack_succeeded is True
    assert record.within_authorized_scope is True
    assert record.headline_success() is True
    # Early stop: the seed round already succeeded, so we should not have used
    # the whole budget.
    assert record.rounds_used == 1
    assert "send_money" in record.final_action_taken


def test_candidate_discovery_finds_injectable_placeholders(banking):
    """Discovery should find at least one placeholder the agent reads."""
    from src.case_runner import injection_candidate_keys

    keys = injection_candidate_keys(
        banking, banking.get_user_task_by_id("user_task_0"), NoDefense()
    )
    assert keys, "expected at least one injectable placeholder"
    # Every returned key must be a real injection vector for the suite.
    assert set(keys) <= set(banking.get_injection_vector_defaults())


def _extract_attacker_iban(goal: str) -> str:
    import re

    match = re.search(r"[A-Z]{2}\d{2}[A-Z0-9]+", goal)
    assert match, f"no IBAN found in goal: {goal}"
    return match.group(0)
