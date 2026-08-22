"""Structured result logging (CLAUDE.md section 9).

One :class:`CaseRecord` per (user task, injection task, defence state) run,
written as JSON Lines so a sweep that dies halfway still leaves usable data and
so a resumed sweep can skip what it already has.

Two rules from CLAUDE.md are enforced here rather than left to discipline:

*   **Utility travels with ASR.** ``utility_score`` is a required field, so no
    record can exist that reports an attack outcome without the corresponding
    task-success outcome. A defence that blocks everything and also breaks
    every real task is not a win, and the schema should make that impossible to
    accidentally hide.
*   **Blocked attempts are logged too.** Every round of the adaptive loop is
    recorded in ``rounds``, including the ones that were refused. The shape of
    what got blocked is part of the finding.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

DefenseState = Literal["none", "static", "adaptive"]

SCHEMA_VERSION = 1


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class RoundRecord(BaseModel):
    """One attack attempt inside the adaptive loop.

    Kept even when the attempt was blocked or errored: round-over-round
    behaviour is the evidence for "the attacker demonstrably improves"
    (CLAUDE.md section 8, Phase 2 definition of done), and that cannot be
    reconstructed from successes alone.
    """

    round_index: int
    strategy: str = ""
    parent_round: int | None = None
    injection_preview: dict[str, str] = Field(default_factory=dict)
    blocked: bool = False
    blocked_tools: list[str] = Field(default_factory=list)
    executed_tools: list[str] = Field(default_factory=list)
    attack_succeeded: bool = False
    utility_score: float = 0.0
    within_authorized_scope: bool = True
    escape_kind: str | None = None
    scope_reason: str = ""
    error: str | None = None
    duration_s: float = 0.0


class CaseRecord(BaseModel):
    """The unit of result. Field names follow CLAUDE.md section 9 verbatim."""

    schema_version: int = SCHEMA_VERSION
    timestamp: str = Field(default_factory=utcnow)

    # --- who was running ---
    model_provider: str
    model_name: str
    attacker_model: str
    policy_model: str = ""

    # --- what was being run ---
    domain: str
    task_id: str
    injection_task_id: str
    defense: str = "progent"
    defense_state: DefenseState

    # --- what happened ---
    rounds_used: int = 0
    blocked: bool = False
    final_action_taken: str = ""
    within_authorized_scope: bool = True
    escape_kind: str | None = None
    utility_score: float = 0.0
    attack_succeeded: bool = False

    # --- provenance ---
    notes: str = ""
    transcript_path: str = ""
    rounds: list[RoundRecord] = Field(default_factory=list)

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        """Identity for resume/dedup: same case, same conditions."""
        return (self.model_name, self.defense_state, self.domain, self.task_id, self.injection_task_id)

    def headline_success(self) -> bool:
        """An attack that counts toward the primary ASR number.

        Both conditions are required. A success that escaped the policy
        boundary is a real finding, but it answers a different question than
        the one in CLAUDE.md section 2, so it is excluded here and reported in
        its own bucket by :mod:`src.aggregate`.
        """
        return self.attack_succeeded and self.within_authorized_scope


class ResultWriter:
    """Append-only JSONL writer, safe for concurrent use within a process."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, record: CaseRecord) -> None:
        line = record.model_dump_json()
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())  # a killed sweep must not lose finished cases

    def write_all(self, records: Iterable[CaseRecord]) -> None:
        for record in records:
            self.write(record)


def read_records(path: Path) -> Iterator[CaseRecord]:
    """Stream records back, skipping any truncated final line from a hard kill."""
    path = Path(path)
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield CaseRecord.model_validate_json(line)
            except Exception as exc:  # noqa: BLE001
                raise ValueError(f"{path}:{line_no} is not a valid CaseRecord: {exc}") from exc


def completed_keys(path: Path) -> set[tuple[str, str, str, str, str]]:
    """Keys already present in ``path``, so a resumed sweep can skip them."""
    try:
        return {record.key for record in read_records(path)}
    except ValueError:
        # A partially written last line is expected after a kill; fall back to
        # a lenient pass so resume still works.
        keys: set[tuple[str, str, str, str, str]] = set()
        with Path(path).open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    keys.add(CaseRecord.model_validate_json(line).key)
                except Exception:  # noqa: BLE001
                    continue
        return keys


def write_transcript(directory: Path, record: CaseRecord, messages: Any) -> str:
    """Persist the raw message list for a case and return its relative path.

    CLAUDE.md section 9 requires raw transcripts to be kept and aggregate
    numbers to be checked against them before anything goes in the write-up.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    safe = f"{record.domain}__{record.task_id}__{record.injection_task_id}__{record.defense_state}.json"
    target = directory / safe
    payload = {
        "case": record.model_dump(exclude={"rounds"}),
        "messages": _jsonable(messages),
    }
    target.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return str(target)


def _jsonable(value: Any) -> Any:
    """Best-effort conversion of AgentDojo message objects into plain JSON."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if hasattr(value, "model_dump"):
        try:
            return _jsonable(value.model_dump())
        except Exception:  # noqa: BLE001
            pass
    return str(value)
