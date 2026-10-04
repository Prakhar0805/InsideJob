"""Offline tests for Phase C generation plumbing — no network, no API.

The one arm of the project that spends budget must be exercised without spending
any: every test here injects a fake client and a fake parser, so the retry
ladder, failure recording, cache round-trip and resume logic are all pinned
deterministically.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("GROQ_API_KEY", "test")

from src.config import ModelSpec  # noqa: E402
from src.llm_clients import DailyQuotaExhausted  # noqa: E402
from src import policy_corpus  # noqa: E402
from src.policy_corpus import (  # noqa: E402
    PolicyRecord,
    generate_one,
    load_records,
    write_summary,
)

SPEC = ModelSpec.parse("groq:openai/gpt-oss-120b")
TOOLS = [{"name": "send_email", "description": "d", "args": {"to": {"type": "string"}}}]
GOOD_JSON = '```json\n[{"name": "send_email", "args": {"to": {"type": "string", "enum": ["a@b.com"]}}}]\n```'


class _FakeCompletion:
    def __init__(self, text):
        self.choices = [type("C", (), {"message": type("M", (), {"content": text})()})()]


class _FakeClient:
    """Returns a scripted sequence of responses or raises scripted exceptions."""

    def __init__(self, script):
        self._script = list(script)
        self.calls = 0

        class _Comp:
            def __init__(inner):
                inner.completions = inner

            def create(inner, **kwargs):
                self.calls += 1
                item = self._script.pop(0)
                if isinstance(item, Exception):
                    raise item
                return _FakeCompletion(item)

        self.chat = _Comp()


def _patch_client(monkeypatch, script):
    client = _FakeClient(script)
    monkeypatch.setattr("src.policy_corpus.build_client", lambda spec: client, raising=False)
    # generate_one imports build_client from src.llm_clients inside the function.
    monkeypatch.setattr("src.llm_clients.build_client", lambda spec: client)
    return client


def _real_extract():
    from secagent.utils import extract_json  # noqa: PLC0415

    return extract_json


@pytest.fixture
def extract():
    pytest.importorskip("secagent")
    return _real_extract()


def test_successful_generation_installs_the_policy(monkeypatch, extract):
    _patch_client(monkeypatch, [GOOD_JSON])
    rec = generate_one(SPEC, "sys", TOOLS, "user_task_0", "do a thing", suite="workspace", extract_json=extract)
    assert rec.ok
    assert rec.policy["send_email"][0] == (100, 0, {"to": {"type": "string", "enum": ["a@b.com"]}}, 0)
    assert rec.attempts == 1


def test_prose_preamble_is_recorded_as_failure_not_crash(monkeypatch, extract):
    # gpt-oss-style reasoning preamble with no code block -> JSONDecodeError every attempt.
    client = _patch_client(monkeypatch, ["Sure! Here is my reasoning about the policy..."] * 6)
    rec = generate_one(SPEC, "sys", TOOLS, "user_task_0", "q", suite="workspace", extract_json=extract)
    assert not rec.ok
    assert rec.error and rec.attempts == 6
    assert client.calls == 6  # the full retry ladder ran


def test_response_starting_with_no_is_recorded(monkeypatch, extract):
    # extract_json returns None for a leading "No"; _install then yields no policy.
    _patch_client(monkeypatch, ["No policy is needed for this task."] * 6)
    rec = generate_one(SPEC, "sys", TOOLS, "user_task_0", "q", suite="workspace", extract_json=extract)
    assert not rec.ok
    assert "no installable policy" in rec.error


def test_retry_succeeds_after_a_transient_failure(monkeypatch, extract):
    _patch_client(monkeypatch, [ValueError("blip"), GOOD_JSON])
    rec = generate_one(SPEC, "sys", TOOLS, "user_task_0", "q", suite="workspace", extract_json=extract)
    assert rec.ok
    assert rec.attempts == 2
    assert rec.temperature_used == pytest.approx(0.2)


def test_daily_quota_is_reraised(monkeypatch, extract):
    _patch_client(monkeypatch, [DailyQuotaExhausted("per day")])
    with pytest.raises(DailyQuotaExhausted):
        generate_one(SPEC, "sys", TOOLS, "user_task_0", "q", suite="workspace", extract_json=extract)


def test_record_roundtrips_through_json():
    rec = PolicyRecord(suite="s", user_task_id="t", model="m", prompt="p",
                       policy={"tool": [(100, 0, {}, 0)]}, generated_at="now")
    back = PolicyRecord.from_dict(rec.as_dict())
    assert back.user_task_id == "t" and back.ok


def test_cache_roundtrip_and_resume(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_corpus, "CORPUS_ROOT", tmp_path)
    ok = PolicyRecord(suite="workspace", user_task_id="user_task_0", model=SPEC.model, prompt="p",
                      policy={"send_email": [(100, 0, {}, 0)]})
    fail = PolicyRecord(suite="workspace", user_task_id="user_task_1", model=SPEC.model, prompt="p",
                        error="boom")
    policy_corpus._append_record(SPEC.model, "workspace", ok)
    policy_corpus._append_record(SPEC.model, "workspace", fail)
    write_summary(SPEC.model, "workspace")

    loaded = load_records(SPEC.model, "workspace")
    assert set(loaded) == {"user_task_0", "user_task_1"}
    assert loaded["user_task_0"].ok and not loaded["user_task_1"].ok
    # The committed summary carries the failure rate.
    import json
    summary = json.loads((tmp_path / policy_corpus.model_slug(SPEC.model) / "workspace.json").read_text())
    assert summary["n_ok"] == 1 and summary["n_failed"] == 1
    assert summary["generation_failure_rate"] == 0.5


def test_a_later_record_supersedes_an_earlier_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_corpus, "CORPUS_ROOT", tmp_path)
    policy_corpus._append_record(
        SPEC.model, "workspace",
        PolicyRecord(suite="workspace", user_task_id="user_task_0", model=SPEC.model, prompt="p", error="first try failed"),
    )
    policy_corpus._append_record(
        SPEC.model, "workspace",
        PolicyRecord(suite="workspace", user_task_id="user_task_0", model=SPEC.model, prompt="p",
                     policy={"t": [(100, 0, {}, 0)]}),
    )
    loaded = load_records(SPEC.model, "workspace")
    assert loaded["user_task_0"].ok, "the retry should win over the earlier failure"
