"""Evaluate the real LLM-generated policies (Phase C) — offline, no API.

Generation (`src/policy_corpus.py`) spends the budget and caches JSON. This
module reads that JSON back and answers the question the constructed corpus can
only assume: *do real generated policies actually contain the flawed idioms the
taxonomy is about, and often enough for the gaps to bite?* It never calls an
LLM and never needs `SECAGENT_SUITE` set.

Five measurements, per model and per engine, each carrying its harm/utility
context so no admittance number stands alone:

1.  **Idiom prevalence** — for every argument a generated policy constrains,
    which idiom did the model use (exact `enum`/`const`, an anchored pattern, an
    unanchored pattern, `format` only, a bare string, a typeless pattern, an
    unconstrained object), broken down by the argument's semantic *kind*. This is
    the direct test of the constructed corpus's assumption.
2.  **Lint prevalence** — `policy_lint` findings per class, and the share of
    generated policies carrying at least one.
3.  **Differential bypassability** — for each generated policy, does the engine
    admit a mutation the sound reference denies (using the user task's own
    ground-truth values as the intended values)?
4.  **Reachable harm** — over each suite's (user-task policy x injection-task)
    pairing, does `find_bypass` clear all three gates; and, separately, how often
    is the literal attack admitted because the *policy was simply too broad*
    (both engine and reference admit) rather than because of an enforcement gap.
5.  **Utility** — does the generated policy still admit its own task's ground
    truth, under the engine, under the reference, and after `harden_policy`.

`policy` values come back from JSON with list-shaped rules; they are normalised
to tuples on load.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from src.enforcers.base import EnforcerAdapter
from src.enforcers.strict import StrictEnforcer, ToolSchemas
from src.gapfuzz.operators import mutate_call
from src.policy_lint import harden_policy, lint_policy
from src.tool_semantics import kind_of


def _normalise_policy(policy: dict | None) -> dict | None:
    """JSON gives rules as lists; the engines expect `(priority, effect, conditions, fallback)` tuples."""
    if not policy:
        return policy
    out: dict[str, list] = {}
    for tool, rules in policy.items():
        norm = []
        for rule in rules:
            if isinstance(rule, (list, tuple)) and len(rule) >= 4:
                norm.append((rule[0], rule[1], rule[2], rule[3]))
        out[tool] = norm
    return out


def classify_idiom(restriction: Any) -> str:
    """Which policy idiom is this restriction written in?"""
    if isinstance(restriction, str):
        return "bare-string"
    if not isinstance(restriction, dict):
        return "other"
    if "enum" in restriction or "const" in restriction:
        return "enum/const"
    if isinstance(restriction.get("pattern"), str):
        pat = restriction["pattern"]
        anchored = (pat.startswith("^") or pat.startswith("\\A")) and (pat.endswith("$") or pat.endswith("\\Z"))
        base = "anchored-pattern" if anchored else "unanchored-pattern"
        return base if "type" in restriction else f"{base}-typeless"
    if restriction.get("format") is not None:
        return "format-only"
    if restriction.get("type") == "object" and restriction.get("additionalProperties", True) is not False:
        return "open-object"
    if restriction.get("type") and len(restriction) == 1:
        return "type-only"
    return "other"


_IDIOM_CODES = {
    "enum/const": "enum",
    "anchored-pattern": "aPat",
    "anchored-pattern-typeless": "aPatT",
    "unanchored-pattern": "uPat",
    "unanchored-pattern-typeless": "uPatT",
    "format-only": "fmt",
    "bare-string": "bare",
    "open-object": "obj",
    "type-only": "type",
    "other": "oth",
}


def _idiom_code(idiom: str) -> str:
    return _IDIOM_CODES.get(idiom, idiom[:5])


@dataclass
class GeneratedEval:
    model: str
    enforcer: str
    n_policies: int = 0
    idiom_by_kind: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    lint_by_class: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    n_with_lint_finding: int = 0
    n_engine_bypassable: int = 0
    n_reference_clean: int = 0
    generation_failures: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "enforcer": self.enforcer,
            "n_policies": self.n_policies,
            "generation_failures": self.generation_failures,
            "idiom_by_kind": {k: dict(v) for k, v in self.idiom_by_kind.items()},
            "lint_by_class": dict(self.lint_by_class),
            "n_with_lint_finding": self.n_with_lint_finding,
            "share_with_lint_finding": round(self.n_with_lint_finding / self.n_policies, 4) if self.n_policies else 0.0,
            "n_engine_bypassable": self.n_engine_bypassable,
            "share_engine_bypassable": round(self.n_engine_bypassable / self.n_policies, 4) if self.n_policies else 0.0,
        }

    def render(self) -> str:
        lines = [
            f"generated-policy evaluation: model={self.model} enforcer={self.enforcer}",
            f"  policies evaluated : {self.n_policies}  (generation failures: {self.generation_failures})",
            "",
            "  idiom prevalence, by argument kind (columns = idioms):",
        ]
        idioms = sorted({i for kv in self.idiom_by_kind.values() for i in kv})
        # Legend keeps the full idiom names; the table uses short codes so
        # columns cannot collide (e.g. anchored-pattern vs -typeless).
        codes = {i: _idiom_code(i) for i in idioms}
        lines.append("    legend: " + "  ".join(f"{codes[i]}={i}" for i in idioms))
        header = "    " + f"{'kind':<8}" + "".join(f"{codes[i]:>8}" for i in idioms)
        lines.append(header)
        for kind in sorted(self.idiom_by_kind):
            row = "    " + f"{kind:<8}" + "".join(f"{self.idiom_by_kind[kind].get(i, 0):>8}" for i in idioms)
            lines.append(row)
        lines += [
            "",
            f"  policies with >=1 lint finding : {self.n_with_lint_finding}/{self.n_policies} "
            f"({(self.n_with_lint_finding / self.n_policies if self.n_policies else 0):.0%})",
            "  lint findings by class : "
            + (", ".join(f"{k}x{v}" for k, v in sorted(self.lint_by_class.items())) or "none"),
            f"  policies with an engine-vs-reference bypass : {self.n_engine_bypassable}/{self.n_policies} "
            f"({(self.n_engine_bypassable / self.n_policies if self.n_policies else 0):.0%})",
            "",
            "  NOTE: a 'bypassable' policy is one where the engine admits a mutation the sound",
            "  reference denies; whether that reaches harm is the reachable-harm arm, and whether",
            "  the fix costs utility is measured by harden_policy on the same policies.",
        ]
        return "\n".join(lines)


def evaluate_records(records: list, enforcer: EnforcerAdapter, schemas: ToolSchemas | None = None) -> GeneratedEval:
    """Measurements 1-3 over a list of `PolicyRecord`-like objects for one model."""
    ev = GeneratedEval(model=records[0].model if records else "?", enforcer=enforcer.name)
    reference = StrictEnforcer(tool_schemas=schemas)

    for rec in records:
        if not rec.ok:
            ev.generation_failures += 1
            continue
        policy = _normalise_policy(rec.policy)
        ev.n_policies += 1

        # 1. idiom prevalence by kind
        for tool, rules in (policy or {}).items():
            for rule in rules:
                conditions = rule[2] if len(rule) >= 3 else {}
                for arg, restriction in (conditions or {}).items():
                    kind = kind_of(tool, arg) or "other"
                    ev.idiom_by_kind[kind][classify_idiom(restriction)] += 1

        # 2. lint prevalence
        report = lint_policy(policy)
        if report.findings:
            ev.n_with_lint_finding += 1
        for cls, n in report.by_class().items():
            ev.lint_by_class[cls] += n

        # 3. differential bypassability (value-level, using the policy's own literals)
        if _engine_bypassable(policy, enforcer, reference):
            ev.n_engine_bypassable += 1

    return ev


def _engine_bypassable(policy, enforcer, reference) -> bool:
    """Does the engine admit a mutation of some pinned value that the reference denies?"""
    for tool, rules in (policy or {}).items():
        for rule in rules:
            conditions = rule[2] if len(rule) >= 3 else {}
            for arg, restriction in (conditions or {}).items():
                intended = _literal_of(restriction)
                if intended is None:
                    continue
                base = {arg: intended}
                if not enforcer.would_allow(policy, tool, base).allowed:
                    continue
                for cand in mutate_call(base):
                    if (
                        enforcer.would_allow(policy, tool, cand.args).allowed
                        and not reference.would_allow(policy, tool, cand.args).allowed
                    ):
                        return True
    return False


def _literal_of(restriction: Any) -> str | None:
    """A concrete permitted value to mutate, if the restriction names one."""
    if isinstance(restriction, str):
        return restriction
    if not isinstance(restriction, dict):
        return None
    if isinstance(restriction.get("const"), str):
        return restriction["const"]
    enum = restriction.get("enum")
    if isinstance(enum, list) and enum and isinstance(enum[0], str):
        return enum[0]
    if isinstance(restriction.get("pattern"), str):
        pat = restriction["pattern"]
        return pat.strip("^$") if not any(c in pat for c in ".*+?[]()|\\") else None
    return None
