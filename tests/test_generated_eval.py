"""Offline tests for the generated-policy evaluation (`src/gapfuzz/generated.py`).

A tiny hand-built corpus of `PolicyRecord`s stands in for real generation, so the
idiom histogram, lint prevalence, and differential-bypassability measurements are
pinned deterministically. This is what lets a reviewer trust the Phase-C numbers
without re-spending budget.
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

from src.enforcers import build_enforcer  # noqa: E402
from src.enforcers.strict import ToolSchemas  # noqa: E402
from src.gapfuzz.generated import classify_idiom, evaluate_records  # noqa: E402
from src.policy_corpus import PolicyRecord  # noqa: E402


@pytest.mark.parametrize(
    ("restriction", "expected"),
    [
        ({"type": "string", "enum": ["a"]}, "enum/const"),
        ({"type": "string", "const": "a"}, "enum/const"),
        ({"type": "string", "pattern": "^a$"}, "anchored-pattern"),
        ({"type": "string", "pattern": "a"}, "unanchored-pattern"),
        ({"pattern": "a"}, "unanchored-pattern-typeless"),
        ({"type": "string", "format": "email"}, "format-only"),
        ("bare", "bare-string"),
        ({"type": "object"}, "open-object"),
        ({"type": "string"}, "type-only"),
    ],
)
def test_idiom_classification(restriction, expected):
    assert classify_idiom(restriction) == expected


def _rec(policy, tid="user_task_0", model="groq:m", error=None):
    return PolicyRecord(suite="workspace", user_task_id=tid, model=model, prompt="p",
                        policy=policy, error=error)


def test_evaluation_counts_idioms_lint_and_bypassability():
    progent = build_enforcer("progent")
    schemas = ToolSchemas.from_properties({"send_money": {"amount": {"type": "number"}}})
    records = [
        # unanchored pattern on an IBAN recipient -> lint A1, engine-bypassable
        _rec({"send_money": [[100, 0, {"recipient": {"type": "string", "pattern": "GB29NWBK"}}, 0]]}, "user_task_0"),
        # sound enum on the same arg -> clean, not bypassable
        _rec({"send_money": [[100, 0, {"recipient": {"type": "string", "enum": ["GB29NWBK"]}}, 0]]}, "user_task_1"),
        # a recorded generation failure -> excluded from n_policies, counted as failure
        _rec(None, "user_task_2", error="JSONDecodeError"),
    ]
    ev = evaluate_records(records, progent, schemas)

    assert ev.n_policies == 2
    assert ev.generation_failures == 1
    # kind classification reached the IBAN recipient
    assert ev.idiom_by_kind["iban"]["unanchored-pattern"] == 1
    assert ev.idiom_by_kind["iban"]["enum/const"] == 1
    # the unanchored one lints and is engine-bypassable; the enum one is neither
    assert ev.lint_by_class.get("A1_unanchored", 0) >= 1
    assert ev.n_with_lint_finding == 1
    assert ev.n_engine_bypassable == 1


def test_too_broad_vs_gap_are_distinguishable_in_the_render():
    """A policy the reference *also* admits is not counted as an enforcement gap."""
    progent = build_enforcer("progent")
    # An empty-conditions allow: both engine and reference admit everything, so it
    # is "too broad", not a differential bypass.
    records = [_rec({"send_email": [[100, 0, {}, 0]]}, "user_task_0")]
    ev = evaluate_records(records, progent, None)
    assert ev.n_policies == 1
    assert ev.n_engine_bypassable == 0  # no engine-vs-reference disagreement
    # but lint still flags the unconstrained allow (A5)
    assert ev.n_with_lint_finding == 1


def test_render_is_stable_text():
    progent = build_enforcer("progent")
    ev = evaluate_records([_rec({"send_money": [[100, 0, {"recipient": {"type": "string", "pattern": "X"}}, 0]]})],
                          progent, None)
    text = ev.render()
    assert "idiom prevalence, by argument kind" in text
    assert "engine-vs-reference bypass" in text
