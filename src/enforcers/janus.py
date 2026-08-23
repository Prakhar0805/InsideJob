"""Adapter for Janus (`janus-guard` on PyPI), unmodified.

Janus is the cross-engine check. It was built independently of Progent, by a
different team, yet it adopted the *same* policy shape — `(priority, effect,
conditions, fallback)` tuples keyed by tool — and, as its own source shows, the
*same* enforcement primitives:

    - `janus.policy.validator.validate_argument`: a `dict` restriction goes to
      `jsonschema.validate` (unanchored `pattern`, no `format_checker`), a `str`
      restriction to `re.match` (prefix-only). → gaps A1, A3, A4.
    - `janus.policy.enforcer._check_conditions`: `if arg_name in arguments:` —
      a restriction on an absent argument is skipped, and unnamed arguments are
      never checked. → gaps B1, A5.

If the differential finds the same classes here as in Progent, the finding is a
property of the *architecture* (LLM-authored JSON-Schema policy + code matcher),
not of one implementation. That is the whole point of testing a second engine,
and it is why nothing in `gapfuzz` is allowed to know which engine it is driving.

As with Progent, this adapter only *calls* Janus's public API; it never
reimplements the matching.
"""

from __future__ import annotations

from typing import Any, Mapping

from src.enforcers.base import Policy, Verdict


def _import_janus():
    from janus.policy.enforcer import PolicyEnforcer  # noqa: PLC0415

    return PolicyEnforcer


class JanusEnforcer:
    """Janus's `PolicyEnforcer`, driven through its public `enforce` call."""

    name = "janus"

    def __init__(self) -> None:
        self._PolicyEnforcer = _import_janus()

    def would_allow(self, policy: Policy, tool_name: str, args: Mapping[str, Any]) -> Verdict:
        # A fresh enforcer per check keeps the probe stateless, mirroring the
        # Progent adapter. Janus's rules are the same tuple shape we use, so no
        # translation is needed; a 5-tuple (unused here) would be trimmed.
        normalised = None
        if policy is not None:
            normalised = {
                tool: [tuple(rule[:4]) for rule in rules] for tool, rules in policy.items()
            }
        enforcer = self._PolicyEnforcer(normalised)
        try:
            enforcer.enforce(tool_name, dict(args))
            return Verdict(True, "permitted by janus")
        except Exception as exc:  # noqa: BLE001 - any raise is a denial
            return Verdict(False, f"denied by janus: {type(exc).__name__}", agent_visible_error=str(exc))
