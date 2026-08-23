"""A combinatorial corpus of plausible policy fragments, derived from real tools.

Phase C generates policies with an LLM and costs a little budget. This module is
the free complement: it builds policy fragments the way a careful author (or a
prompt-following LLM) plausibly would - pin the security-relevant argument with
the natural, flawed idiom - directly from the AgentDojo tool schemas. That gives
the differential sweep a large, realistic, zero-cost input set.

The fragments deliberately embody the *good-faith* mistakes the taxonomy is
about: an unanchored pattern on an identifier, a loose URL pattern (exactly what
Progent's own prompt recommends), a single pinned argument leaving siblings
free. We are not constructing adversarial policies - we are constructing the
policies a reasonable person writes, and showing the enforcer admits more than
they intend.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator

from agentdojo.functions_runtime import Function
from agentdojo.task_suite.task_suite import TaskSuite

from src.enforcers.base import Policy


@dataclass(frozen=True)
class PolicyFragment:
    """One tool's policy plus a human-readable account of how it was written."""

    tool_name: str
    policy: Policy
    style: str
    pinned_arg: str | None
    intended_value: Any


def _string_args(tool: Function) -> list[tuple[str, dict]]:
    """(name, schema) for each string-typed, agent-controllable argument."""
    schema = tool.parameters.model_json_schema()
    props = schema.get("properties", {})
    out = []
    for name, spec in props.items():
        if spec.get("type") == "string" or "anyOf" in spec:
            out.append((name, spec))
    return out


def natural_policies_for_tool(tool: Function, sample_value: str = "EXPECTED_VALUE") -> Iterator[PolicyFragment]:
    """Yield the policies a good-faith author plausibly writes for one tool.

    Each embodies one idiom the taxonomy addresses. `sample_value` stands in for
    the concrete value the author meant to allow (an IBAN, an email, a URL).
    """
    for arg_name, _spec in _string_args(tool):
        # 1. The natural idiom: pin the argument with a `pattern`. Flawed only
        #    because the matcher is unanchored (A1) and, if `type` is omitted,
        #    type-scoped (A3).
        yield PolicyFragment(
            tool.name,
            {tool.name: [(100, 0, {arg_name: {"type": "string", "pattern": sample_value}}, 0)]},
            style="pattern-pinned",
            pinned_arg=arg_name,
            intended_value=sample_value,
        )
        # 2. The pattern without a `type` - a very common LLM omission (A3).
        yield PolicyFragment(
            tool.name,
            {tool.name: [(100, 0, {arg_name: {"pattern": sample_value}}, 0)]},
            style="pattern-no-type",
            pinned_arg=arg_name,
            intended_value=sample_value,
        )
        # 3. `format` instead of a pattern - recommended by Progent's prompt,
        #    never enforced (A4).
        yield PolicyFragment(
            tool.name,
            {tool.name: [(100, 0, {arg_name: {"type": "string", "format": "email"}}, 0)]},
            style="format-only",
            pinned_arg=arg_name,
            intended_value=sample_value,
        )
        # 4. The one sound idiom, as a control: an exact enum. A correct policy
        #    should NOT be bypassable, and the sweep must confirm that.
        yield PolicyFragment(
            tool.name,
            {tool.name: [(100, 0, {arg_name: {"type": "string", "enum": [sample_value]}}, 0)]},
            style="enum-exact",
            pinned_arg=arg_name,
            intended_value=sample_value,
        )


def suite_corpus(suite: TaskSuite, sample_value: str = "EXPECTED_VALUE") -> Iterator[PolicyFragment]:
    """Every natural policy fragment for every tool in a suite."""
    for tool in suite.tools:
        yield from natural_policies_for_tool(tool, sample_value)
