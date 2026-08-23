"""Configuration: model specs, credentials, and free-tier rate budgets.

Why this module exists separately from the code that uses it: several of
Progent's settings are read at *import* time (``secagent.tool`` captures
``SECAGENT_POLICY_MODEL`` into a module global, and each AgentDojo task suite
reads ``SECAGENT_SUITE`` when the suite module is first imported). That makes
import order load-bearing, so all environment manipulation is funnelled through
here and through :func:`bootstrap`, which must run before anything imports
``agentdojo`` or ``secagent``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from dotenv import load_dotenv

REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
RESULTS_DIR: Final[Path] = REPO_ROOT / "results"

PROVIDERS: Final[tuple[str, ...]] = ("groq", "gemini")

#: Default per-minute request budgets. Deliberately below the published free
#: tier limits: CLAUDE.md section 6 sets a hard $0 ceiling, so we would rather
#: sleep than spend the run retrying 429s (or trip a paid overage).
DEFAULT_RPM: Final[dict[str, int]] = {"groq": 25, "gemini": 8}

DEFAULT_BASE_URL: Final[dict[str, str]] = {
    "groq": "https://api.groq.com/openai/v1",
    # Google AI Studio's OpenAI-compatible endpoint. Note this is *not* Vertex
    # AI: AgentDojo's built-in "google" provider goes through vertexai, which
    # needs a GCP project and a billing account. The AI Studio endpoint is the
    # free tier CLAUDE.md section 6 calls for, and it speaks the OpenAI wire
    # format, so we can drive it with AgentDojo's existing OpenAILLM element
    # instead of writing (and having to trust) a new one.
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/",
}

#: Model-family inference rules, checked in order (first substring match wins).
#: Order matters: "deepseek-r1-distill-llama-70b" is a DeepSeek model that
#: mentions llama, and "openai/gpt-oss-120b" must not fall through to a generic
#: "gpt" rule.
_FAMILY_RULES: Final[tuple[tuple[str, str], ...]] = (
    ("gpt-oss", "gpt-oss"),
    ("deepseek", "deepseek"),
    ("kimi", "kimi"),
    ("qwen", "qwen"),
    ("gemma", "gemma"),
    ("gemini", "gemini"),
    ("mixtral", "mistral"),
    ("mistral", "mistral"),
    ("llama", "llama"),
    ("claude", "claude"),
    ("gpt-", "gpt"),
)


def infer_family(model: str) -> str:
    """Best-effort model-family label, e.g. ``llama``, ``gpt-oss``, ``kimi``.

    Family, not provider, is what CLAUDE.md section 5's separation rule is
    actually about: the stated reason is to avoid *correlated failure* between
    attacker and agent, and correlation comes from shared training lineage, not
    from which company serves the HTTP endpoint. Groq hosts several unrelated
    families, so family-level separation is achievable on a single provider.

    An unrecognised model is given its own id as its family. That is the
    permissive choice - two unknown models will be treated as different - but
    refusing to run on any model this table has not heard of would break on
    every new release, and the separation check is a guard against an obvious
    mistake, not a proof of independence.
    """
    lowered = model.lower()
    for needle, family in _FAMILY_RULES:
        if needle in lowered:
            return family
    return lowered


@dataclass(frozen=True)
class ModelSpec:
    """A single model, identified as ``provider:model_name``."""

    provider: str
    model: str

    @property
    def family(self) -> str:
        """The model's family (see :func:`infer_family`)."""
        return infer_family(self.model)

    @property
    def family_is_known(self) -> bool:
        return self.family != self.model.lower()

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
                f"{self.api_key_env} is not set. Copy .env.example to .env and fill it in. "
                "Never hardcode keys (CLAUDE.md section 6)."
            )
        return key

    def base_url(self) -> str:
        return os.getenv(self.base_url_env, "").strip() or DEFAULT_BASE_URL[self.provider]

    def rpm(self) -> int:
        raw = os.getenv(f"{self.provider.upper()}_RPM", "").strip()
        return int(raw) if raw else DEFAULT_RPM[self.provider]


@dataclass(frozen=True)
class Settings:
    """Everything the harness needs that comes from the environment."""

    agent: ModelSpec
    attacker: ModelSpec
    policy: ModelSpec

    @classmethod
    def from_env(cls) -> "Settings":
        agent = ModelSpec.parse(os.getenv("INSIDEJOB_AGENT_MODEL", "groq:llama-3.3-70b-versatile"))
        attacker = ModelSpec.parse(os.getenv("INSIDEJOB_ATTACKER_MODEL", "groq:openai/gpt-oss-120b"))
        policy_raw = os.getenv("INSIDEJOB_POLICY_MODEL", "").strip()
        policy = ModelSpec.parse(policy_raw) if policy_raw else agent
        settings = cls(agent=agent, attacker=attacker, policy=policy)
        settings.validate_roles()
        return settings

    def validate_roles(self) -> None:
        """Enforce the separation CLAUDE.md section 5 requires between roles.

        The attacker must not be the same model *family* as the agent. If it
        were, an attack the attacker cannot imagine and a defence the agent
        cannot resist would share a cause, and a low ASR would be unreadable: we
        could not tell "the defence held" from "the attacker had the same blind
        spot as its target".

        Family rather than provider is the hard requirement because family is
        what the correlated-failure argument actually rests on (see
        :func:`infer_family`). Running both roles on one provider is permitted
        but is weaker separation than CLAUDE.md section 5's ideal, so
        :meth:`separation_note` reports it and the write-up must state it.

        The policy model is the opposite case. Progent's policy generator is
        part of the *system under test*, so it must never be the attacker's
        family - that would let the attacker's own lineage write the rules it is
        being scored against.
        """
        if self.agent.family == self.attacker.family:
            raise ValueError(
                f"Agent ({self.agent}) and attacker ({self.attacker}) are both model family "
                f"{self.agent.family!r}. CLAUDE.md section 5 requires different model families "
                "so attacker and agent blind spots cannot be correlated. On Groq, pair e.g. "
                "llama-3.3-70b-versatile (agent) with openai/gpt-oss-120b or "
                "moonshotai/kimi-k2-instruct (attacker)."
            )
        if self.policy.family == self.attacker.family:
            raise ValueError(
                f"Progent's policy model ({self.policy}) is the same family {self.policy.family!r} "
                f"as the attacker ({self.attacker}). The policy engine is part of the system "
                "under test and must not run on the attacker's model family."
            )

    def separation_note(self) -> str:
        """A one-line description of how well-separated the roles actually are.

        Printed at sweep start and meant to be quoted in the write-up. A run
        where attacker and agent share a provider is a real caveat on the
        cross-model claim, and it should be visible in the run log rather than
        discovered later by reading ``.env``.
        """
        parts = [
            f"agent={self.agent} (family {self.agent.family})",
            f"attacker={self.attacker} (family {self.attacker.family})",
            f"policy={self.policy} (family {self.policy.family})",
        ]
        if self.agent.provider == self.attacker.provider:
            parts.append(
                f"CAVEAT: agent and attacker share provider {self.agent.provider!r} - "
                "family-separated but not provider-separated (weaker than CLAUDE.md section 5's ideal)"
            )
        unknown = [s.model for s in (self.agent, self.attacker, self.policy) if not s.family_is_known]
        if unknown:
            parts.append(f"NOTE: family could not be inferred for {', '.join(unknown)}")
        return " | ".join(parts)


def bootstrap(
    *,
    policy: ModelSpec | None = None,
    suite: str | None = None,
    enable_progent: bool = False,
    policy_updates: bool = True,
) -> None:
    """Load ``.env`` and set the environment Progent reads at import time.

    Must be called **before** importing ``agentdojo`` or ``secagent``. Anything
    imported earlier will have already frozen these values.

    Args:
        policy: which model Progent uses to synthesise policies. Progent's
            ``api_request`` builds a bare ``openai.OpenAI()``, i.e. it reads
            ``OPENAI_API_KEY`` / ``OPENAI_BASE_URL`` from the ambient
            environment. Pointing those at a free-tier OpenAI-compatible
            endpoint is how we run Progent on free credits *without touching
            its code* - configuration through its supported interface, as
            CLAUDE.md section 11 requires. Our own clients pass keys
            explicitly, so they are unaffected by these variables.
        suite: the AgentDojo suite whose tools should be wrapped by Progent.
            Progent's fork only wraps the suite named in ``SECAGENT_SUITE``, so
            this doubles as the defence on/off switch per suite.
        enable_progent: ``False`` runs the undefended baseline (CLAUDE.md
            section 10, comparison 1).
        policy_updates: whether Progent may widen its policy mid-run from tool
            output (``SECAGENT_UPDATE``). Left on because that is Progent's own
            default configuration in ``run.sh``; :mod:`src.scope_check` tracks
            the resulting widenings so an attack that succeeds only because
            untrusted content moved the policy is reported separately rather
            than counted in the headline number.
    """
    load_dotenv(REPO_ROOT / ".env")

    if enable_progent and suite:
        os.environ["SECAGENT_SUITE"] = suite
        os.environ["SECAGENT_GENERATE"] = "True"
        os.environ["ENABLE_SECAGENT"] = "True"
        os.environ["SECAGENT_UPDATE"] = "True" if policy_updates else "False"
        # A malformed policy update must not abort the run; Progent's own
        # run.sh sets this, and we keep parity so our numbers stay comparable.
        os.environ["SECAGENT_IGNORE_UPDATE_ERROR"] = "True"
    else:
        os.environ.pop("SECAGENT_SUITE", None)
        os.environ["ENABLE_SECAGENT"] = "False"
        os.environ["SECAGENT_UPDATE"] = "False"
        # Critical: AgentDojo's InitQuery always calls
        # ``secagent.generate_security_policy`` regardless of whether the suite
        # tools were wrapped, and that function makes an LLM call whenever
        # ``SECAGENT_GENERATE`` is truthy (its default). For the undefended
        # baseline we must switch it off explicitly, or every "no defence" case
        # would still burn policy-model quota and require OpenAI-side
        # credentials we do not want in that arm.
        os.environ["SECAGENT_GENERATE"] = "False"

    if policy is not None:
        os.environ["SECAGENT_POLICY_MODEL"] = policy.model
        os.environ["OPENAI_API_KEY"] = policy.api_key()
        os.environ["OPENAI_BASE_URL"] = policy.base_url()
