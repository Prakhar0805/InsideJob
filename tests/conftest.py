"""Shared test fixtures and a fake defence for exercising scope logic offline.

The scope checker must be testable without Progent or any API, both because
CLAUDE.md section 11 requires tests around scope-checking and aggregation, and
because those tests define what "in scope" means precisely enough to trust the
headline number.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class FakeDefense:
    """A defence whose policy is just a set of allowed ``(tool, arg)`` pairs.

    Mirrors :class:`src.defense.DefenseAdapter`'s protocol closely enough to
    drive :mod:`src.scope_check`, but with fully deterministic, inspectable
    behaviour: a policy is ``{tool_name: set_of_allowed_values_or_None}`` and a
    call is allowed iff the tool is present and (if a value set is given) every
    arg value is in it. ``None`` means "any args".
    """

    name = "fake"

    def __init__(self, *, enabled: bool = True, block_marker: str = "BLOCKED_BY_FAKE") -> None:
        self.enabled = enabled
        self.block_marker = block_marker
        self._policy: dict[str, set | None] = {}

    def set_policy(self, policy: dict[str, set | None]) -> None:
        self._policy = policy

    def reset(self) -> None:
        self._policy = {}

    def snapshot_policy(self) -> Any:
        return {k: (set(v) if v is not None else None) for k, v in self._policy.items()}

    def would_allow(self, policy: Any, tool_name: str, args: Mapping[str, Any]) -> bool:
        if policy is None:
            return True
        if tool_name not in policy:
            return False
        allowed = policy[tool_name]
        if allowed is None:
            return True
        return all(value in allowed for value in args.values())

    def classify(self, tool_name: str, error: str | None, content: Any) -> str:
        if not error:
            return "allowed"
        return "blocked_by_defense" if self.block_marker in error else "tool_error"


@pytest.fixture
def fake_defense() -> FakeDefense:
    return FakeDefense()
