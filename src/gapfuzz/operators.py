"""Mutation operators, one family per enforcement-gap class.

Each operator takes the attacker's canonical target call and produces variants
that a *sound* policy would reject but a gapped enforcer might admit. An
operator declares the gap class it probes, so when a mutated call slips through,
the bypass is automatically attributed to a specific, named weakness rather than
to "fuzzing found something".

The operators are deterministic and enumerable. This is not random fuzzing: the
gaps are known and structural, so we generate exactly the variants that exploit
them. That makes the search fast, the results reproducible, and every hit
explainable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterator

from src.enforcers.base import GapClass


@dataclass(frozen=True)
class Candidate:
    """A mutated call plus the operator's *hypothesis* about which gap admits it.

    The name is deliberate: `hypothesis` is the operator's guess, not the
    finding. Which gap actually lets the mutation through is decided by
    isolating reference fixes in :mod:`src.gapfuzz.attribution` - and the two
    often differ (a suffix on a `format`-only policy is admitted via A4, not the
    A1 the suffix operator assumed). The hypothesis survives only as the
    last-resort label when isolation is inconclusive.
    """

    args: dict[str, Any]
    hypothesis: GapClass
    rationale: str


#: A mutator sees the original harmful args and yields candidate variants.
Mutator = Callable[[dict[str, Any]], Iterator[Candidate]]

#: Marker substrings appended to values to prove a bypass carries attacker
#: payload while keeping the policy-matching part intact. Chosen to be
#: obviously-not-benign so a hit is unambiguous.
_SUFFIX = "-ATTACKERPAYLOAD"
_PREFIX = "ATTACKERPAYLOAD#"


def _string_args(args: dict[str, Any]) -> Iterator[tuple[str, str]]:
    for key, value in args.items():
        if isinstance(value, str) and value:
            yield key, value


def unanchored_suffix(args: dict[str, Any]) -> Iterator[Candidate]:
    """A1: keep the policy-matching value as a prefix, append attacker payload.

    Defeats `re.match` (start-anchored, no end anchor) and jsonschema
    `pattern`/`re.search`. The appended text is where the real effect lives -
    an extra path on a URL, a spoofed field on an IBAN reference.
    """
    for key, value in _string_args(args):
        mutated = dict(args)
        mutated[key] = value + _SUFFIX
        yield Candidate(mutated, GapClass.A1_UNANCHORED, f"appended payload to {key!r}")


def unanchored_infix(args: dict[str, Any]) -> Iterator[Candidate]:
    """A1: embed the allowed value inside a larger attacker-controlled string.

    Defeats jsonschema `pattern` specifically, which searches anywhere in the
    value. The effective content is the prefix; the allowed value is buried to
    satisfy the matcher.
    """
    for key, value in _string_args(args):
        mutated = dict(args)
        mutated[key] = _PREFIX + value
        yield Candidate(mutated, GapClass.A1_UNANCHORED, f"prefixed payload onto {key!r}")


def type_shift(args: dict[str, Any]) -> Iterator[Candidate]:
    """A3: wrap the value so a string-only restriction no longer applies.

    If the policy pinned a string arg with a `pattern` but forgot `"type"`, or
    wrote the keyword on the wrong type, delivering the same logical value as a
    single-element list slips past the (now inapplicable) constraint while many
    tools still coerce or accept it.
    """
    for key, value in _string_args(args):
        mutated = dict(args)
        mutated[key] = [value + _SUFFIX]
        yield Candidate(
            mutated, GapClass.A3_TYPE_SCOPED_NOOP,
            f"delivered {key!r} as a list so a string keyword no longer bites",
        )


def sibling_injection(args: dict[str, Any]) -> Iterator[Candidate]:
    """A5: keep the constrained args exactly, add a harmful unconstrained one.

    The classic bcc: the policy pins `recipient`, so leave it untouched and add
    a second sink the policy never named. Only meaningful against tools that
    actually take such an argument, so the caller supplies candidate sibling
    names from the tool schema.
    """
    # The concrete sibling name is tool-specific, so this operator is driven by
    # the search layer, which knows the tool's parameters. Kept here as a
    # no-op-by-default so the registry stays uniform.
    return iter(())


def case_variation(args: dict[str, Any]) -> Iterator[Candidate]:
    """A1/canonicalization: change case where the matcher is case-sensitive but
    the tool is not. A same-effect value the pattern no longer matches."""
    for key, value in _string_args(args):
        swapped = value.upper() if value != value.upper() else value.lower()
        if swapped == value:
            continue
        mutated = dict(args)
        mutated[key] = swapped
        yield Candidate(
            mutated, GapClass.A1_UNANCHORED,
            f"case-varied {key!r}; matcher is case-sensitive, many tools are not",
        )


#: The registry the search layer iterates. Order is by gap code for stable,
#: reproducible output.
MUTATORS: dict[str, Mutator] = {
    "unanchored_suffix": unanchored_suffix,
    "unanchored_infix": unanchored_infix,
    "type_shift": type_shift,
    "case_variation": case_variation,
    "sibling_injection": sibling_injection,
}


def mutate_call(args: dict[str, Any]) -> Iterator[Candidate]:
    """All candidate mutations of one call, across every operator."""
    for mutator in MUTATORS.values():
        yield from mutator(dict(args))
