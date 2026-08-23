"""Adapter for Progent's policy engine (`secagent`), unmodified.

Everything here goes through Progent's public API — install a policy, ask it to
check a call, restore. We never reimplement its matching, because the entire
point of the differential is that the *real* engine's behaviour is compared
against a sound reference. A reimplementation would only prove our own bugs.

Two behaviours of `secagent` shape this adapter:

*   `secagent.tool` reads `SECAGENT_POLICY_MODEL` and friends at import time and
    prints on import, so the import is deferred and quietened.
*   `check_tool_call` mutates module-global state — it can install a policy
    rewrite carried on a 5-tuple rule. Every check therefore saves and restores
    the live policy, so one probe cannot contaminate the next.
"""

from __future__ import annotations

import contextlib
import copy
import io
import os
from typing import Any, Mapping

from src.enforcers.base import Policy, Verdict

#: Progent appends this to every policy denial before re-raising. It is also
#: the string that leaks the policy back to the agent (finding C1).
BLOCK_MARKER = "Please try other tools or arguments and continue to finish the user task"


@contextlib.contextmanager
def _quiet():
    """Swallow Progent's per-call policy dumps.

    It prints the entire policy on every `update_security_policy`, and a sweep
    performs hundreds of thousands of those. Only ever wrapped around our own
    bookkeeping, never around anything whose output is evidence.
    """
    sink = io.StringIO()
    with contextlib.redirect_stderr(sink), contextlib.redirect_stdout(sink):
        yield sink


def _import_secagent():
    """Import `secagent` with policy generation disabled.

    `SECAGENT_GENERATE=False` matters: without it, any code path that reaches
    `generate_security_policy` makes a live API call. This project's core
    result must cost nothing, so the module is imported in a state where that
    cannot happen by accident.
    """
    os.environ.setdefault("SECAGENT_GENERATE", "False")
    os.environ.setdefault("SECAGENT_UPDATE", "False")
    with _quiet():
        import secagent  # noqa: PLC0415

        return secagent


class ProgentEnforcer:
    """Progent, driven through `secagent`'s public interface."""

    name = "progent"

    def __init__(self) -> None:
        self._secagent = _import_secagent()

    def would_allow(self, policy: Policy, tool_name: str, args: Mapping[str, Any]) -> Verdict:
        secagent = self._secagent
        live = secagent.get_current_config()
        try:
            with _quiet():
                # Deep copy so a rule that rewrites the policy on match mutates
                # our throwaway copy rather than the caller's fixture.
                secagent.update_security_policy(copy.deepcopy(policy) if policy else policy)
            try:
                with _quiet():
                    secagent.check_tool_call(tool_name, dict(args))
                return Verdict(True, "permitted by progent")
            except Exception as exc:  # noqa: BLE001 - any raise is a denial
                text = str(exc)
                return Verdict(
                    False,
                    f"denied by progent: {type(exc).__name__}",
                    agent_visible_error=text,
                )
        finally:
            with _quiet():
                secagent.update_security_policy(live)

    def discloses_policy(self, verdict: Verdict) -> bool:
        """Does this denial hand the policy back to the agent? (finding C1)

        Progent re-raises the raw `jsonschema` error for priority-100 rules, so
        the message can carry the schema fragment and the user's original query
        verbatim. That turns every refusal into a probe of the boundary, which
        is what makes an adaptive attack against this design cheap.
        """
        if verdict.allowed:
            return False
        text = verdict.agent_visible_error
        return any(
            marker in text
            for marker in ("Failed validating", "is not one of", "does not match", "On instance")
        )
