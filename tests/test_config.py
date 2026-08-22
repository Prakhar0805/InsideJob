"""Tests for model-spec parsing and the role-separation rules (CLAUDE.md section 5)."""

from __future__ import annotations

import pytest

from src.config import ModelSpec, Settings


def test_model_spec_parse():
    spec = ModelSpec.parse("groq:llama-3.3-70b-versatile")
    assert spec.provider == "groq"
    assert spec.model == "llama-3.3-70b-versatile"
    assert str(spec) == "groq:llama-3.3-70b-versatile"


def test_model_spec_parse_rejects_bad_input():
    with pytest.raises(ValueError):
        ModelSpec.parse("no-colon")
    with pytest.raises(ValueError):
        ModelSpec.parse("openai:gpt-4o")  # unknown provider for this project
    with pytest.raises(ValueError):
        ModelSpec.parse("groq:")


def test_agent_and_attacker_must_differ_in_provider():
    with pytest.raises(ValueError, match="different providers"):
        Settings(
            agent=ModelSpec("groq", "a"),
            attacker=ModelSpec("groq", "b"),
            policy=ModelSpec("groq", "a"),
        ).validate_roles()


def test_policy_model_must_not_be_attacker_provider():
    with pytest.raises(ValueError, match="system\nunder test|system under test"):
        Settings(
            agent=ModelSpec("groq", "a"),
            attacker=ModelSpec("gemini", "b"),
            policy=ModelSpec("gemini", "c"),  # policy on attacker's provider: illegal
        ).validate_roles()


def test_valid_role_assignment_passes():
    Settings(
        agent=ModelSpec("groq", "llama-3.3-70b-versatile"),
        attacker=ModelSpec("gemini", "gemini-2.5-flash"),
        policy=ModelSpec("groq", "llama-3.3-70b-versatile"),
    ).validate_roles()


def test_default_base_urls():
    assert "groq.com" in ModelSpec("groq", "x").base_url()
    assert "generativelanguage" in ModelSpec("gemini", "x").base_url()
