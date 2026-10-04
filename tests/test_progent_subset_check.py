"""Gap class B6: Progent's policy-narrowing check fails open on anchored patterns.

Progent can be run with ``SECAGENT_ONLY_ALLOW_NARROW=True`` (off by default;
``tool.py:464-481``), in which a mid-run policy update is accepted only if
``security_policy_subset_check`` proves the new policy is a subset of the old
one. The proof is delegated to z3. The solver wrapper, ``solve_schema``
(``policy_analysis.py:318-329``), wraps every attempt in a bare
``except Exception: pass`` and returns "no model", and the caller reads "no
model" as "no counterexample, therefore subset holds".

The regex-to-z3 translation cannot express ``^``/``$``/``\\A``/``\\Z`` anchors, so
every anchored pattern raises inside that ``try`` - and every widening of an
anchored pattern is accepted as a narrowing. Anchoring is precisely what a
sound policy does, and what ``policy_lint.harden_policy`` produces, so the
project's own mitigation silently disables this check.

Two things this file is careful about:

* It calls the analysis function **directly**, not through ``check_tool_call``.
  B6 is not a matcher gap - the strict reference has no update path to model -
  so it has no differential fixture and lives outside ``strict.ALL_FIXES``.
  Pinning it against the engine's own function is the only honest evidence.
* It is Progent-only. Janus has no update-path analysis at all, so there is
  nothing to compare; the cross-engine profile records it as Progent-only.

No LLM, no network, no cost.
"""

from __future__ import annotations

import contextlib
import io

import pytest

pytest.importorskip("secagent", reason="Progent (secagent) not installed")
pytest.importorskip("z3", reason="z3-solver not installed")

from src.enforcers.base import GapClass  # noqa: E402
from src.enforcers.strict import ALL_FIXES  # noqa: E402


def _subset_check(original: dict, new: dict) -> bool:
    """Run Progent's check with its stderr chatter suppressed."""
    from secagent.policy_analysis import security_policy_subset_check

    sink = io.StringIO()
    with contextlib.redirect_stderr(sink), contextlib.redirect_stdout(sink):
        return bool(security_policy_subset_check(original, new))


def _policy(pattern: str) -> dict:
    return {"send_money": [(100, 0, {"recipient": {"type": "string", "pattern": pattern}}, 0)]}


@pytest.mark.parametrize(
    ("original", "widened"),
    [
        ("^GOOD$", "^.*$"),
        (r"\AGOOD\Z", r"\A.*\Z"),
        ("^GB29NWBK60161331926819$", "^GB29.*$"),
    ],
    ids=["caret-dollar", "A-Z", "iban-prefix"],
)
def test_widening_an_anchored_pattern_passes_as_a_subset(original, widened):
    """The finding: an anchored narrow->wide update is accepted (B6).

    The correct answer is False (the new policy admits strictly more). Progent
    returns True because the z3 translation of the anchor raises and the
    exception is swallowed as "no counterexample".
    """
    assert _subset_check(_policy(original), _policy(widened)) is True


def test_unanchored_widening_is_correctly_rejected():
    """Negative control: without anchors the solver works and catches the widening."""
    assert _subset_check(_policy("GOOD"), _policy(".*")) is False


def test_enum_widening_is_correctly_rejected():
    """Negative control: `enum` needs no regex translation, so it is checked soundly."""
    original = {"send_money": [(100, 0, {"recipient": {"type": "string", "enum": ["GOOD"]}}, 0)]}
    widened = {"send_money": [(100, 0, {"recipient": {"type": "string", "enum": ["GOOD", "EVIL"]}}, 0)]}
    assert _subset_check(original, widened) is False


def test_identical_anchored_policies_pass():
    """Sanity: the fail-open does not also reject legitimate no-op updates."""
    assert _subset_check(_policy("^GOOD$"), _policy("^GOOD$")) is True


def test_hardening_output_triggers_the_fail_open():
    """The project's own mitigation lands on the failing branch.

    `harden_policy` anchors every pattern. Feed a hardened policy and a
    hardened-but-wider policy to the check: the widening passes. This is why
    B6 is reported alongside the mitigation rather than buried as an engine
    footnote - a deployment that hardens *and* narrows would lose the narrowing
    guarantee without any signal.
    """
    from src.policy_lint import harden_policy

    tight = harden_policy({"send_money": [(100, 0, {"recipient": {"type": "string", "pattern": r"GB29\d+"}}, 0)]})
    wide = harden_policy({"send_money": [(100, 0, {"recipient": {"type": "string", "pattern": r".*"}}, 0)]})
    assert _subset_check(tight, wide) is True, "expected the anchored widening to be (wrongly) accepted"


def test_b6_is_in_the_taxonomy_but_has_no_reference_fix():
    """B6 is an admittance-direction finding with no matcher fix, by construction."""
    assert GapClass.B6_SUBSET_CHECK_FAILS_OPEN.is_admittance
    assert GapClass.B6_SUBSET_CHECK_FAILS_OPEN not in ALL_FIXES
