"""OpenAI-compatible clients for Groq and Google AI Studio, with free-tier care.

Both providers speak the OpenAI wire protocol, which lets us reuse AgentDojo's
existing ``OpenAILLM`` pipeline element for the agent role rather than writing a
new one. That matters for comparability: a bug in a hand-rolled provider adapter
would show up as a change in agent behaviour and be indistinguishable from a
change in defence strength.

Everything here exists to satisfy the $0 ceiling in CLAUDE.md section 6:
a per-provider request-per-minute gate, and retry/backoff that *logs* rate-limit
hits rather than swallowing them (section 11).
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field

import openai

from src.config import ModelSpec

logger = logging.getLogger(__name__)


class RateLimiter:
    """A sliding-window request gate, shared by every caller of one provider.

    A token bucket would let a burst through at the start of each window, which
    is precisely when free tiers push back hardest. A sliding window over the
    last 60 seconds of request timestamps costs nothing and never bursts.

    Thread-safe because a sweep may fan out over user tasks while a single
    provider budget still has to be respected globally.
    """

    def __init__(self, rpm: int, name: str = "") -> None:
        if rpm <= 0:
            raise ValueError(f"rpm must be positive, got {rpm}")
        self.rpm = rpm
        self.name = name
        self._times: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Block until a request may be sent. Returns the seconds slept."""
        slept = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                while self._times and now - self._times[0] >= 60.0:
                    self._times.popleft()
                if len(self._times) < self.rpm:
                    self._times.append(now)
                    return slept
                wait = 60.0 - (now - self._times[0]) + 0.05
            logger.info("rate-limit gate: sleeping %.1fs for %s (%d rpm)", wait, self.name, self.rpm)
            time.sleep(wait)
            slept += wait


@dataclass
class CallStats:
    """Counters we report at the end of a run, so throttling is never silent."""

    requests: int = 0
    rate_limit_hits: int = 0
    other_errors: int = 0
    seconds_throttled: float = 0.0

    def as_dict(self) -> dict[str, float | int]:
        return {
            "requests": self.requests,
            "rate_limit_hits": self.rate_limit_hits,
            "other_errors": self.other_errors,
            "seconds_throttled": round(self.seconds_throttled, 1),
        }


@dataclass
class ProviderHandle:
    """A configured client plus the shared limiter and counters for a provider."""

    spec: ModelSpec
    client: openai.OpenAI
    limiter: RateLimiter
    stats: CallStats = field(default_factory=CallStats)


_HANDLES: dict[str, ProviderHandle] = {}
_HANDLES_LOCK = threading.Lock()


def get_handle(spec: ModelSpec) -> ProviderHandle:
    """Return the process-wide handle for ``spec``'s provider, creating it once.

    Keyed by provider rather than by model: the rate limit is enforced by the
    provider against the API key, so two models on the same key must share one
    budget or we would quietly double our request rate.
    """
    with _HANDLES_LOCK:
        handle = _HANDLES.get(spec.provider)
        if handle is None:
            handle = ProviderHandle(
                spec=spec,
                client=openai.OpenAI(
                    api_key=spec.api_key(),
                    base_url=spec.base_url(),
                    max_retries=0,  # we do our own, so we can count and log them
                    timeout=120.0,
                ),
                limiter=RateLimiter(spec.rpm(), name=spec.provider),
            )
            _HANDLES[spec.provider] = handle
            logger.info("provider %s ready: base_url=%s rpm=%d", spec.provider, spec.base_url(), spec.rpm())
        return handle


def reset_handles() -> None:
    """Drop cached handles. Used by tests and when credentials change."""
    with _HANDLES_LOCK:
        _HANDLES.clear()


def all_stats() -> dict[str, dict[str, float | int]]:
    with _HANDLES_LOCK:
        return {provider: handle.stats.as_dict() for provider, handle in _HANDLES.items()}


class RateLimitedClient:
    """Thin proxy over ``openai.OpenAI`` that gates and retries every request.

    AgentDojo's ``OpenAILLM`` only ever touches ``client.chat.completions.create``,
    so proxying that one path is enough and keeps the surface small. Presenting
    the same attribute chain means AgentDojo needs no changes at all.
    """

    def __init__(self, handle: ProviderHandle, max_attempts: int = 6, base_delay: float = 2.0) -> None:
        self._handle = handle
        self._max_attempts = max_attempts
        self._base_delay = base_delay
        self.chat = _Chat(self)

    # Some AgentDojo code paths read ``client.api_key`` / pass the client on.
    def __getattr__(self, item: str):
        return getattr(self._handle.client, item)

    @property
    def stats(self) -> CallStats:
        return self._handle.stats

    def _create(self, **kwargs):
        stats = self._handle.stats
        last_exc: Exception | None = None
        for attempt in range(1, self._max_attempts + 1):
            stats.seconds_throttled += self._handle.limiter.acquire()
            try:
                stats.requests += 1
                return self._handle.client.chat.completions.create(**kwargs)
            except openai.RateLimitError as exc:
                stats.rate_limit_hits += 1
                last_exc = exc
                delay = self._retry_after(exc) or self._base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "rate limited by %s (attempt %d/%d), backing off %.1fs",
                    self._handle.spec.provider, attempt, self._max_attempts, delay,
                )
                time.sleep(delay)
            except (openai.APIConnectionError, openai.APITimeoutError, openai.InternalServerError) as exc:
                stats.other_errors += 1
                last_exc = exc
                delay = self._base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "transient error from %s (%s), retrying in %.1fs",
                    self._handle.spec.provider, type(exc).__name__, delay,
                )
                time.sleep(delay)
        assert last_exc is not None
        raise last_exc

    @staticmethod
    def _retry_after(exc: openai.RateLimitError) -> float | None:
        """Honour the provider's own Retry-After when it sends one."""
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", None)
        if not headers:
            return None
        for key in ("retry-after", "Retry-After", "x-ratelimit-reset-requests"):
            raw = headers.get(key)
            if raw:
                try:
                    return min(float(str(raw).rstrip("s")), 90.0)
                except ValueError:
                    continue
        return None


class _Chat:
    def __init__(self, parent: RateLimitedClient) -> None:
        self.completions = _Completions(parent)


class _Completions:
    def __init__(self, parent: RateLimitedClient) -> None:
        self._parent = parent

    def create(self, **kwargs):
        return self._parent._create(**kwargs)


def build_client(spec: ModelSpec) -> RateLimitedClient:
    """Public entry point: a rate-limited, retrying client for ``spec``."""
    return RateLimitedClient(get_handle(spec))


def simple_completion(
    spec: ModelSpec,
    system_prompt: str,
    user_prompt: str,
    *,
    temperature: float = 1.0,
    max_tokens: int = 2048,
) -> str:
    """One-shot text completion. Used by the attacker, which needs no tools.

    Temperature defaults high on purpose: the attacker's job is to explore a
    space of phrasings, and a deterministic attacker would re-propose the same
    blocked payload every round, which is exactly the static baseline we are
    trying to improve on.
    """
    client = build_client(spec)
    completion = client.chat.completions.create(
        model=spec.model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    content = completion.choices[0].message.content
    return content or ""
