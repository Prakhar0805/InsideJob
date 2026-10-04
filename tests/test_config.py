"""Tests for model-spec parsing."""

from __future__ import annotations

import pytest

from src.config import ModelSpec


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


def test_default_base_urls():
    assert "groq.com" in ModelSpec("groq", "x").base_url()
    assert "generativelanguage" in ModelSpec("gemini", "x").base_url()
