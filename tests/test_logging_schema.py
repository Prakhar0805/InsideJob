"""Tests for the result log: round-trip, resume keys, and the section 9 rules."""

from __future__ import annotations

from src.logging_schema import (
    CaseRecord,
    ResultWriter,
    RoundRecord,
    completed_keys,
    read_records,
)


def _rec(task="u1", inj="i1", state="adaptive", **kw):
    return CaseRecord(
        model_provider="groq", model_name="llama-3.3-70b-versatile",
        attacker_model="gemini:gemini-2.5-flash", domain="banking",
        task_id=task, injection_task_id=inj, defense_state=state, **kw,
    )


def test_round_trip(tmp_path):
    path = tmp_path / "r.jsonl"
    writer = ResultWriter(path)
    rec = _rec(rounds=[RoundRecord(round_index=0, attack_succeeded=True, within_authorized_scope=True)],
               attack_succeeded=True, within_authorized_scope=True, utility_score=1.0)
    writer.write(rec)
    back = list(read_records(path))
    assert len(back) == 1
    assert back[0].task_id == "u1"
    assert back[0].rounds[0].attack_succeeded is True


def test_utility_score_is_required_field():
    # Pydantic model: utility_score has a default of 0.0, so a record always
    # carries one - there is no way to log an attack outcome without it.
    rec = _rec()
    assert hasattr(rec, "utility_score")
    assert rec.utility_score == 0.0


def test_headline_success_requires_both_conditions():
    assert _rec(attack_succeeded=True, within_authorized_scope=True).headline_success() is True
    assert _rec(attack_succeeded=True, within_authorized_scope=False).headline_success() is False
    assert _rec(attack_succeeded=False, within_authorized_scope=True).headline_success() is False


def test_completed_keys_enables_resume(tmp_path):
    path = tmp_path / "r.jsonl"
    writer = ResultWriter(path)
    writer.write(_rec(task="u1", inj="i1"))
    writer.write(_rec(task="u2", inj="i1"))
    keys = completed_keys(path)
    assert ("llama-3.3-70b-versatile", "adaptive", "banking", "u1", "i1") in keys
    assert ("llama-3.3-70b-versatile", "adaptive", "banking", "u2", "i1") in keys
    assert len(keys) == 2


def test_completed_keys_tolerates_truncated_last_line(tmp_path):
    path = tmp_path / "r.jsonl"
    writer = ResultWriter(path)
    writer.write(_rec(task="u1", inj="i1"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"partial": "record with no newline and invalid')  # simulate a kill mid-write
    keys = completed_keys(path)
    assert ("llama-3.3-70b-versatile", "adaptive", "banking", "u1", "i1") in keys
    assert len(keys) == 1
