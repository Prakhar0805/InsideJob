"""The tool-side parser differential, end to end on AgentDojo's own tasks.

The headline of this arm: a policy that pins `recipients` to a benign address
with the array idiom is bypassed by a display-name value that the engine admits,
the sound reference (with nested anchoring) rejects, and AgentDojo's *own*
`security()` predicate scores harmful - all three gates, no LLM, no modelling.
The IBAN negative control and the agentdojo/modeled separation are pinned too.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("GROQ_API_KEY", "test")
os.environ.setdefault("SECAGENT_GENERATE", "False")
os.environ.pop("SECAGENT_SUITE", None)

from src.config import bootstrap  # noqa: E402

bootstrap()

pytest.importorskip("secagent", reason="Progent (secagent) not installed")
pytest.importorskip("email_validator", reason="pydantic EmailStr needs email_validator")

from agentdojo.task_suite.load_suites import get_suites  # noqa: E402

from src.enforcers import build_enforcer  # noqa: E402
from src.gapfuzz.semantic import run_semantic_sweep  # noqa: E402


@pytest.fixture(scope="module")
def suites():
    return get_suites("v1")


@pytest.fixture(scope="module")
def progent():
    return build_enforcer("progent")


@pytest.fixture(scope="module")
def workspace_report(suites, progent):
    return run_semantic_sweep({"workspace": suites["workspace"]}, progent)


def test_workspace_email_bypass_clears_three_gates(workspace_report):
    """A display-name recipient is admitted, reference-denied, and security()-harmful."""
    email_bypasses = [
        r for r in workspace_report.results
        if r.kind == "email" and r.bypass_found and r.harm_source == "agentdojo"
    ]
    assert email_bypasses, "expected at least one AgentDojo-scored email bypass"
    r = email_bypasses[0]
    assert r.engine_admits and r.reference_denies and r.harm_confirmed
    # The winning value literally contains the pinned benign address and resolves
    # to the attacker's.
    assert r.benign_value in r.winning_value
    assert r.resolved_to and r.resolved_to != r.benign_value


def test_email_bypass_is_agentdojo_scored_not_modeled(workspace_report):
    for r in workspace_report.results:
        if r.kind == "email" and r.bypass_found:
            assert r.harm_source == "agentdojo", "email harm must be benchmark-validated, not modeled"


def test_banking_iban_has_no_tool_side_bypass(suites, progent):
    """Negative control: an exact-compared IBAN has no tool parser to disagree with."""
    report = run_semantic_sweep({"banking": suites["banking"]}, progent)
    ibans = [r for r in report.results if r.kind == "iban"]
    assert ibans, "expected banking injection tasks to target an IBAN argument"
    assert all(not r.bypass_found for r in ibans)
    assert all(r.note == "negative control" for r in ibans)


def test_modeled_and_agentdojo_harm_are_labeled_and_never_summed(workspace_report):
    d = workspace_report.as_dict()
    assert "n_bypassed_agentdojo" in d and "n_bypassed_modeled" in d
    # The render keeps them on separate lines and says so.
    rendered = workspace_report.render()
    assert "never summed" in rendered
    assert "[agentdojo]" in rendered


def test_value_level_harm_baseline_is_unchanged(suites, progent):
    """The semantic path must not perturb the conservative harm sweep (still 0)."""
    from src.gapfuzz.harm_sweep import run_harm_sweep

    report = run_harm_sweep({"banking": suites["banking"]}, progent)
    assert sum(1 for r in report.scored if r.result.bypass_found) == 0
