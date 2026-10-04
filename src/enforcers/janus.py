"""Adapter for Janus (`janus-guard` on PyPI), unmodified.

Janus is the cross-engine check. It is a *reimplementation* of Progent's
design, not an independent one: its policy-generation prompt (`prompts/
policy_generate.j2`) is Progent's system prompt verbatim and its generator
emits the same `(100, 0, args, 0)` rules. What it does not share is Progent's
enforcer *code*. So it is the right second engine for a lineage question: it
adopted the `(priority, effect, conditions, fallback)` shape and, as its own
source shows, the *same* enforcement primitives:

    - `janus.policy.validator.validate_argument`: a `dict` restriction goes to
      `jsonschema.validate` (unanchored `pattern`, no `format_checker`), a `str`
      restriction to `re.match` (prefix-only). → gaps A1, A3, A4.
    - `janus.policy.enforcer._check_conditions`: `if arg_name in arguments:` —
      a restriction on an absent argument is skipped, and unnamed arguments are
      never checked. → gaps B1, A5.

A gap that reappears here therefore lives in those shared primitives and
propagates with the design; a gap that is one codebase's own control-flow bug
does not (Progent's loop-carried fallback, B2, is absent in Janus, whose
`_evaluate_rules` has a real default-deny; a malformed deny regex fails closed
here where it fails open in Progent). `src/gapfuzz/crossengine.py` prints that
per-class split. Nothing in `gapfuzz` is allowed to know which engine it is
driving, which is what keeps the cross-engine claim a config change.

As with Progent, this adapter only *calls* Janus's public API; it never
reimplements the matching.
"""

from __future__ import annotations

from typing import Any, Mapping

from src.enforcers.base import BaseEnforcer, Policy, Verdict


def _import_janus():
    from janus.policy.enforcer import PolicyEnforcer  # noqa: PLC0415

    return PolicyEnforcer


class JanusEnforcer(BaseEnforcer):
    """Janus's `PolicyEnforcer`, driven through its public `enforce` call.

    Note what is *absent*: this class defines no disclosure logic at all. It
    inherits `BaseEnforcer.discloses_policy` unchanged, and the generic check -
    "do the policy's own literals appear in the text the agent receives?" -
    finds Janus leaking just as Progent does, because Janus embeds the same
    `jsonschema` message in its `PolicyViolation`
    (`janus/policy/validator.py`). A second engine covered by zero
    engine-specific code is the architectural claim stated in code rather than
    in prose.

    One measured difference from Progent, and it runs the wrong way for Janus:
    Progent only dumps the schema for priority-100 rules, while Janus surfaces
    the failing constraint at *every* priority - so its disclosure is
    unconditional where Progent's is (accidentally) scoped. Conversely, several
    admittance gaps that reappear here did *not* fully propagate: Janus has a
    real default-deny (no B2) and fails closed on a malformed deny regex. It
    also has no policy-update analysis at all, so B6 has no Janus counterpart.
    """

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
