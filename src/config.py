"""Configuration: model specs, credentials, and free-tier rate budgets.

Several of Progent's settings are read at *import* time (each AgentDojo task
suite reads ``SECAGENT_SUITE`` when its module is first imported), which makes
import order matter. Environment handling for the offline audit therefore goes
through :func:`bootstrap`, which must run before anything imports ``agentdojo``
or ``secagent``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from dotenv import load_dotenv

REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent

PROVIDERS: Final[tuple[str, ...]] = ("groq", "gemini")

#: Default per-minute budgets, set a little below the published free-tier
#: limits: the project has a $0 budget, so it is better to sleep than to spend
#: the run retrying 429s.
#:
#: Groq's free tier for the models used here is 30 requests/min and 8,000
#: tokens/min. Tokens are what bind: a policy-generation prompt carries a few
#: thousand tokens of tool schema, so 8k TPM is reached long before 30 RPM.
#: Both limits are metered per model.
DEFAULT_RPM: Final[dict[str, int]] = {"groq": 28, "gemini": 8}
DEFAULT_TPM: Final[dict[str, int]] = {"groq": 7_000, "gemini": 200_000}


def _env_slug(model: str) -> str:
    """``openai/gpt-oss-120b`` -> ``OPENAI_GPT_OSS_120B`` for env-var lookup."""
    return "".join(ch if ch.isalnum() else "_" for ch in model).upper()

DEFAULT_BASE_URL: Final[dict[str, str]] = {
    "groq": "https://api.groq.com/openai/v1",
    # Google AI Studio's OpenAI-compatible endpoint (free tier). This is not
    # Vertex AI, which needs a GCP project and a billing account.
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/",
}

@dataclass(frozen=True)
class ModelSpec:
    """A single model, identified as ``provider:model_name``."""

    provider: str
    model: str

    @classmethod
    def parse(cls, spec: str) -> "ModelSpec":
        """Parse a ``provider:model`` string, e.g. ``groq:llama-3.3-70b-versatile``."""
        if ":" not in spec:
            raise ValueError(
                f"Model spec {spec!r} must be 'provider:model'. "
                f"Known providers: {', '.join(PROVIDERS)}"
            )
        provider, _, model = spec.partition(":")
        provider = provider.strip().lower()
        model = model.strip()
        if provider not in PROVIDERS:
            raise ValueError(f"Unknown provider {provider!r}. Known providers: {', '.join(PROVIDERS)}")
        if not model:
            raise ValueError(f"Model spec {spec!r} has an empty model name.")
        return cls(provider=provider, model=model)

    def __str__(self) -> str:
        return f"{self.provider}:{self.model}"

    @property
    def api_key_env(self) -> str:
        return f"{self.provider.upper()}_API_KEY"

    @property
    def base_url_env(self) -> str:
        return f"{self.provider.upper()}_BASE_URL"

    def api_key(self) -> str:
        key = os.getenv(self.api_key_env, "").strip()
        if not key:
            raise RuntimeError(
                f"{self.api_key_env} is not set. Copy .env.example to .env and fill it in."
            )
        return key

    def base_url(self) -> str:
        return os.getenv(self.base_url_env, "").strip() or DEFAULT_BASE_URL[self.provider]

    def rpm(self) -> int:
        return self._budget("RPM", DEFAULT_RPM[self.provider])

    def tpm(self) -> int:
        """Tokens-per-minute budget. On real free tiers this, not RPM, binds."""
        return self._budget("TPM", DEFAULT_TPM[self.provider])

    def _budget(self, kind: str, fallback: int) -> int:
        """Resolve a rate budget, most specific setting first.

        Per-model override wins because free-tier quotas are metered per model,
        and a single provider often exposes models with very different caps:

            INSIDEJOB_TPM_OPENAI_GPT_OSS_120B=7500   # this model only
            GROQ_TPM=7500                            # every Groq model
        """
        specific = os.getenv(f"INSIDEJOB_{kind}_{_env_slug(self.model)}", "").strip()
        if specific:
            return int(specific)
        general = os.getenv(f"{self.provider.upper()}_{kind}", "").strip()
        return int(general) if general else fallback


def bootstrap() -> None:
    """Load ``.env`` and switch Progent's AgentDojo hooks off.

    Must be called **before** importing ``agentdojo`` or ``secagent``; anything
    imported earlier has already frozen these values.

    The audit drives the matcher directly through the enforcer adapters, so the
    vendored AgentDojo fork must behave like stock AgentDojo here: no suite
    wrapped in Progent's tool wrapper, and no policy generation. The second
    point matters because the fork's ``InitQuery`` calls
    ``secagent.generate_security_policy`` on every task, and that makes an LLM
    call whenever ``SECAGENT_GENERATE`` is truthy, which is its default.
    """
    load_dotenv(REPO_ROOT / ".env")
    os.environ.pop("SECAGENT_SUITE", None)
    os.environ["ENABLE_SECAGENT"] = "False"
    os.environ["SECAGENT_UPDATE"] = "False"
    os.environ["SECAGENT_GENERATE"] = "False"
