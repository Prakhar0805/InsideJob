"""gapfuzz - the offline differential fuzzer for agent policy engines.

Given a policy, an enforcer, and (optionally) an AgentDojo harm oracle, gapfuzz
searches for a tool call that the enforcer *admits* but that a sound reference
would *reject* - and, when an oracle is present, that actually achieves the
attacker's objective. The whole search runs without an LLM.
"""

from __future__ import annotations

from src.gapfuzz.operators import MUTATORS, Mutator, mutate_call
from src.gapfuzz.search import BypassResult, find_bypass

__all__ = ["MUTATORS", "Mutator", "mutate_call", "BypassResult", "find_bypass"]
