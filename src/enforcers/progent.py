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

from src.enforcers.base import BaseEnforcer, DisclosureInstance, Policy, Verdict

#: Progent appends this to every policy denial before re-raising (`tool.py:590`).
#: Its presence in the captured text is the *proof of routing* for finding C1:
#: it shows the string is addressed to the model ("please try other arguments"),
#: not an internal log line we happened to intercept. Verified present in
#: `Verdict.agent_visible_error`.
BLOCK_MARKER = "Please try other tools or arguments and continue to finish the user task"

#: `jsonschema` renders these in a raw ValidationError. Their presence means the
#: denial carried the *schema fragment* itself, disclosing the shape of the
#: constraint on top of its literal values.
_SCHEMA_DUMP_MARKERS = ("Failed validating", "is not one of", "does not match", "On instance")


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


class ProgentEnforcer(BaseEnforcer):
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

    def probe_subset_check_fails_open(self) -> bool:
        """B6: does the z3 policy-narrowing check accept a widened anchored pattern?

        Lives on the adapter, not in `gapfuzz`, because it needs
        `secagent.policy_analysis` and `gapfuzz` must stay engine-free. The
        cross-engine profile looks this method up by name; an adapter without
        it has no update-path analysis to fail (Janus).
        """
        from secagent.policy_analysis import security_policy_subset_check  # noqa: PLC0415

        tight = {"send_money": [(100, 0, {"recipient": {"type": "string", "pattern": "^GOOD$"}}, 0)]}
        wide = {"send_money": [(100, 0, {"recipient": {"type": "string", "pattern": "^.*$"}}, 0)]}
        with _quiet():
            return bool(security_policy_subset_check(tight, wide))

    def _discloses_schema(self, text: str) -> bool:
        """Progent re-raises the raw `jsonschema` error, dumping the schema.

        This fires on exactly one branch: a **priority-100 allow rule with
        `fallback == 0`** (`secagent/tool.py:537-539` does a bare `raise e`). A
        rule at any lower priority falls through to the generic
        "The tool 'x' is not allowed." (`tool.py:562`) and leaks nothing.

        That conditional is the finding, not a caveat: Progent's own generator
        hardcodes `(100, 0, args, 0)` for every rule it writes
        (`tool.py:401-405`), so the disclosing branch is precisely the branch
        every LLM-authored policy takes. A hand-written operator rule denies
        silently; the generated policy that constitutes the actual deployment
        quotes its own allow-list back.
        """
        return any(marker in text for marker in _SCHEMA_DUMP_MARKERS)

    def _agent_routed(self, text: str) -> bool:
        """Is this text addressed to the model, or merely an internal error?

        `BLOCK_MARKER` is the instruction Progent appends for the agent to read.
        Its presence is what makes the disclosure a *channel* finding rather
        than an observation about an exception we caught. Progent also appends
        the user's original query at the same point (`tool.py:590`), which in a
        live run leaks the task prompt alongside the policy.
        """
        return BLOCK_MARKER in text
