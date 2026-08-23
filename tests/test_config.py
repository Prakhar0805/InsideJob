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


def test_family_inference():
    from src.config import infer_family

    assert infer_family("llama-3.3-70b-versatile") == "llama"
    assert infer_family("openai/gpt-oss-120b") == "gpt-oss"
    assert infer_family("moonshotai/kimi-k2-instruct") == "kimi"
    assert infer_family("qwen/qwen3-32b") == "qwen"
    assert infer_family("gemini-2.5-flash") == "gemini"
    # Ordering matters: a DeepSeek distill mentions llama but is not one.
    assert infer_family("deepseek-r1-distill-llama-70b") == "deepseek"
    # Unknown models get their own id as family (permissive, and flagged).
    assert infer_family("some-new-model-v9") == "some-new-model-v9"
    assert ModelSpec("groq", "llama-3.3-70b-versatile").family_is_known is True
    assert ModelSpec("groq", "some-new-model-v9").family_is_known is False


def test_agent_and_attacker_must_differ_in_family():
    with pytest.raises(ValueError, match="model family"):
        Settings(
            agent=ModelSpec("groq", "llama-3.3-70b-versatile"),
            attacker=ModelSpec("groq", "llama-3.1-8b-instant"),  # same family
            policy=ModelSpec("groq", "llama-3.3-70b-versatile"),
        ).validate_roles()


def test_policy_model_must_not_share_attacker_family():
    with pytest.raises(ValueError, match="same family"):
        Settings(
            agent=ModelSpec("groq", "llama-3.3-70b-versatile"),
            attacker=ModelSpec("groq", "openai/gpt-oss-120b"),
            policy=ModelSpec("groq", "openai/gpt-oss-20b"),  # attacker's family: illegal
        ).validate_roles()


def test_groq_only_setup_is_valid_when_families_differ():
    """The Groq-only configuration must pass: different families, one provider."""
    settings = Settings(
        agent=ModelSpec("groq", "llama-3.3-70b-versatile"),
        attacker=ModelSpec("groq", "openai/gpt-oss-120b"),
        policy=ModelSpec("groq", "llama-3.3-70b-versatile"),
    )
    settings.validate_roles()
    # ...but the weaker separation must be reported, not silently accepted.
    note = settings.separation_note()
    assert "CAVEAT" in note
    assert "share provider" in note


def test_cross_provider_setup_has_no_caveat():
    settings = Settings(
        agent=ModelSpec("groq", "llama-3.3-70b-versatile"),
        attacker=ModelSpec("gemini", "gemini-2.5-flash"),
        policy=ModelSpec("groq", "llama-3.3-70b-versatile"),
    )
    settings.validate_roles()
    assert "CAVEAT" not in settings.separation_note()


def test_default_base_urls():
    assert "groq.com" in ModelSpec("groq", "x").base_url()
    assert "generativelanguage" in ModelSpec("gemini", "x").base_url()
