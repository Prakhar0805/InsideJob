"""Policy-engine adapters under test, plus the strict reference.

Adding an engine means implementing :class:`~src.enforcers.base.EnforcerAdapter`
and registering it here. Nothing else in the codebase changes — that is the
property that makes the cross-system claim cheap.
"""

from __future__ import annotations

from typing import Callable

from src.enforcers.base import (
    ALLOW,
    EnforcerAdapter,
    GapClass,
    GapInstance,
    Policy,
    Rule,
    Verdict,
    normalise_rule,
)
from src.enforcers.strict import ALL_FIXES, StrictEnforcer

__all__ = [
    "ALLOW",
    "ALL_FIXES",
    "EnforcerAdapter",
    "GapClass",
    "GapInstance",
    "Policy",
    "Rule",
    "StrictEnforcer",
    "Verdict",
    "build_enforcer",
    "normalise_rule",
    "available_enforcers",
]


def _progent() -> EnforcerAdapter:
    from src.enforcers.progent import ProgentEnforcer

    return ProgentEnforcer()


def _janus() -> EnforcerAdapter:
    from src.enforcers.janus import JanusEnforcer

    return JanusEnforcer()


def _strict() -> EnforcerAdapter:
    return StrictEnforcer()


#: Lazy so that importing this package never pulls in an optional engine.
ENFORCERS: dict[str, Callable[[], EnforcerAdapter]] = {
    "progent": _progent,
    "janus": _janus,
    "strict": _strict,
}


def build_enforcer(name: str) -> EnforcerAdapter:
    if name not in ENFORCERS:
        raise ValueError(f"Unknown enforcer {name!r}. Known: {', '.join(sorted(ENFORCERS))}")
    return ENFORCERS[name]()


def available_enforcers() -> list[str]:
    """Which engines are actually importable here (Janus is optional)."""
    found = []
    for name, factory in ENFORCERS.items():
        try:
            factory()
        except Exception:  # noqa: BLE001 - not installed is not an error
            continue
        found.append(name)
    return found
