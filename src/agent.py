"""Agent wrapper: builds AgentDojo pipelines backed by Groq / Gemini free tiers.

CLAUDE.md section 6 requires frontier models reached over an API and forbids any
local hosting. AgentDojo's own provider table only knows OpenAI, Anthropic,
Cohere, Together and Vertex AI, none of which give us a free tier we can use
here. Rather than edit AgentDojo (section 11), we exploit the seam it already
provides: ``PipelineConfig.llm`` accepts a fully constructed pipeline element,
so we hand it an ``OpenAILLM`` pointed at an OpenAI-compatible free endpoint.

The only global state we touch in AgentDojo is ``MODEL_NAMES``, a
display-name lookup used by the ``important_instructions`` attack to address the
victim by name in prose. Adding entries is additive and touches no scoring path.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.models import MODEL_NAMES
from agentdojo.types import ChatMessage

from src.config import ModelSpec
from src.llm_clients import build_client

logger = logging.getLogger(__name__)

#: Prose names for the models AgentDojo does not ship with. The values follow
#: upstream's own convention: open-weight models get the generic
#: "AI assistant", Gemini variants get Google's phrasing. This is only used to
#: fill ``{model}`` in attack templates, never in scoring.
EXTRA_MODEL_NAMES: dict[str, str] = {
    "llama-3.3-70b-versatile": "AI assistant",
    "llama-3.1-8b-instant": "AI assistant",
    "openai/gpt-oss-120b": "AI assistant",
    "openai/gpt-oss-20b": "AI assistant",
    "openai/gpt-oss-safeguard-20b": "AI assistant",
    "moonshotai/kimi-k2-instruct": "AI assistant",
    "qwen/qwen3-32b": "AI assistant",
    "qwen/qwen3.6-27b": "AI assistant",
    "allam-2-7b": "AI assistant",
    "groq/compound": "AI assistant",
    "groq/compound-mini": "AI assistant",
    "gemini-2.5-flash": "AI model developed by Google",
    "gemini-2.5-flash-lite": "AI model developed by Google",
    "gemini-2.0-flash": "AI model developed by Google",
}


def register_model_names() -> None:
    """Teach AgentDojo the prose names of the models we add. Idempotent.

    Any model not listed still works: :func:`src.case_runner._agent_prose` falls
    back to a generic name, which only affects how attack templates address the
    victim, never scoring.
    """
    for model, prose in EXTRA_MODEL_NAMES.items():
        MODEL_NAMES.setdefault(model, prose)


def build_llm(spec: ModelSpec) -> OpenAILLM:
    """An AgentDojo LLM element speaking to ``spec`` over an OpenAI-compatible API.

    Temperature is pinned to 0.0 for the *agent*. The agent is the system under
    test, not the thing we are exploring: run-to-run variance in the victim
    would leak into the ASR and make round-over-round attacker improvement
    unreadable. The attacker samples hot instead (see
    :func:`src.llm_clients.simple_completion`).
    """
    register_model_names()
    llm = OpenAILLM(build_client(spec), spec.model, temperature=0.0)  # type: ignore[arg-type]
    llm.name = spec.model
    return llm


def build_pipeline(spec: ModelSpec) -> AgentPipeline:
    """Build the standard AgentDojo tool-calling pipeline for ``spec``.

    ``defense=None`` here means *no AgentDojo-side defence* (no tool filter, no
    PI detector). Progent is not an AgentDojo defence element - it lives under
    the tool layer, wrapping the suite's functions - so it is switched on
    through :func:`src.config.bootstrap`, not through this argument. Passing an
    AgentDojo defence here as well would confound the experiment: we would no
    longer be measuring Progent.
    """
    llm = build_llm(spec)
    pipeline = AgentPipeline.from_config(
        PipelineConfig(llm=llm, defense=None, system_message_name=None, system_message=None)
    )
    pipeline.name = spec.model
    return pipeline


@dataclass
class RunTrace:
    """Everything observable about one agent run, captured for later analysis.

    ``run_task_with_pipeline`` returns only ``(utility, security)``. We need the
    message list too: the scope check (CLAUDE.md section 5.5) has to inspect
    which tools were actually called, and the attacker needs to see *why* a call
    was refused in order to mutate usefully. Wrapping the pipeline is the least
    invasive way to get it - no AgentDojo edits, and it composes with any
    pipeline, including one wrapping a different defence.
    """

    messages: list[ChatMessage] = field(default_factory=list)
    queries: int = 0
    error: str | None = None

    @property
    def tool_calls(self) -> list[dict[str, Any]]:
        """Flat list of ``{name, args, error, content}`` for every tool result."""
        calls: list[dict[str, Any]] = []
        for message in self.messages:
            if message.get("role") != "tool":
                continue
            tool_call = message.get("tool_call")
            if tool_call is None:
                continue
            calls.append(
                {
                    "name": getattr(tool_call, "function", None),
                    "args": dict(getattr(tool_call, "args", {}) or {}),
                    "error": message.get("error"),
                    "content": message.get("content"),
                }
            )
        return calls

    @property
    def final_text(self) -> str:
        for message in reversed(self.messages):
            if message.get("role") == "assistant" and message.get("content"):
                return str(message["content"])
        return ""


class RecordingPipeline(BasePipelineElement):
    """Delegates to a real pipeline while recording the messages it produced.

    Defence-agnostic on purpose: it knows nothing about Progent, so the same
    wrapper works for the undefended baseline and for any other
    AgentDojo-wrapped defence someone swaps in (a CLAUDE.md section 3
    deliverable).
    """

    def __init__(self, inner: BasePipelineElement) -> None:
        self.inner = inner
        self.name = inner.name
        self.trace = RunTrace()

    def reset(self) -> None:
        self.trace = RunTrace()

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        self.trace.queries += 1
        try:
            result = self.inner.query(query, runtime, env, messages, extra_args)
        except Exception as exc:  # noqa: BLE001 - recorded, then re-raised
            self.trace.error = f"{type(exc).__name__}: {exc}"
            raise
        self.trace.messages = list(result[3])
        return result
