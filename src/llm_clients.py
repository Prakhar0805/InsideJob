"""OpenAI-compatible clients for Groq / Google AI Studio, with free-tier care.

Both providers speak the OpenAI wire protocol, which lets us reuse AgentDojo's
existing ``OpenAILLM`` pipeline element for the agent role rather than writing a
new one. That matters for comparability: a bug in a hand-rolled provider adapter
would show up as a change in agent behaviour and be indistinguishable from a
change in defence strength.

Everything here exists to satisfy the $0 ceiling in CLAUDE.md section 6. Three
facts about real free tiers shape the design:

1.  **Tokens per minute bind long before requests per minute.** Groq's free tier
    allows 30 requests/min but only ~8k tokens/min on the models we can use, and
    a single AgentDojo agent call carries thousands of tokens of tool schema. A
    request-counting limiter would let ~30 calls/min through and collect 429s.
    So the gate meters *estimated tokens* as well as requests.
2.  **Quotas are per model, not per provider.** Each Groq model has its own
    bucket, so keying the limiter by provider would needlessly serialise three
    independent budgets into one.
3.  **Daily caps exist and cannot be waited out.** A tokens-per-day 429 will not
    clear for hours, so retrying against it just burns the run. Those are
    detected and raised as :class:`DailyQuotaExhausted` so the sweep can stop
    cleanly and be resumed tomorrow (results already written are preserved).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

import openai

from src.config import ModelSpec

logger = logging.getLogger(__name__)

#: Rough characters-per-token. Only used to *pre-estimate* a request's size so
#: the gate can pace itself; the provider's own accounting is authoritative. We
#: deliberately keep the configured TPM below the real cap so this estimate does
#: not have to be accurate.
CHARS_PER_TOKEN = 4

#: Assumed completion size when a request does not cap it. Output counts toward
#: the same budget, so ignoring it would under-estimate every call.
DEFAULT_OUTPUT_RESERVE = 1024


class DailyQuotaExhausted(RuntimeError):
    """Raised when a provider reports a per-day limit rather than a per-minute one.

    Distinct from an ordinary rate limit because the response is different: a
    per-minute limit is worth sleeping through, a per-day limit means stop and
    resume tomorrow.
    """


class RateLimiter:
    """A sliding-window gate over both requests and tokens for one model.

    A token bucket would let a burst through at the start of each window, which
    is precisely when free tiers push back hardest. Sliding windows over the last
    60 seconds of requests and of estimated tokens cost nothing and never burst.

    Thread-safe because a sweep may fan out while a single model budget still has
    to be respected globally.
    """

    def __init__(
        self,
        rpm: int,
        tpm: int,
        name: str = "",
        *,
        clock: "Callable[[], float] | None" = None,
        sleeper: "Callable[[float], None] | None" = None,
    ) -> None:
        """
        Args:
            clock / sleeper: injectable time source, defaulting to the real one.
                Only exists so tests can exercise the pacing logic without
                actually sleeping for a minute per assertion - the pacing rules
                are what decide whether a sweep completes, so they need real
                tests rather than a hope that the arithmetic is right.
        """
        if rpm <= 0:
            raise ValueError(f"rpm must be positive, got {rpm}")
        if tpm <= 0:
            raise ValueError(f"tpm must be positive, got {tpm}")
        self.rpm = rpm
        self.tpm = tpm
        self.name = name
        self._clock = clock or time.monotonic
        self._sleep = sleeper or time.sleep
        self._requests: deque[float] = deque()
        self._tokens: deque[tuple[float, int]] = deque()
        self._token_sum = 0
        self._lock = threading.Lock()

    def _evict(self, now: float) -> None:
        while self._requests and now - self._requests[0] >= 60.0:
            self._requests.popleft()
        while self._tokens and now - self._tokens[0][0] >= 60.0:
            self._token_sum -= self._tokens.popleft()[1]

    def acquire(self, tokens: int) -> float:
        """Block until ``tokens`` may be sent. Returns the seconds slept.

        A single request larger than the whole per-minute token budget can never
        fit; rather than deadlock we let it through after the window drains and
        let the provider decide. That case means the configured TPM is too low
        for the workload, and the warning says so.
        """
        tokens = max(1, tokens)
        slept = 0.0
        while True:
            with self._lock:
                now = self._clock()
                self._evict(now)
                fits_requests = len(self._requests) < self.rpm
                fits_tokens = self._token_sum + tokens <= self.tpm
                oversized = tokens > self.tpm

                if fits_requests and (fits_tokens or (oversized and not self._tokens)):
                    if oversized:
                        logger.warning(
                            "single request (~%d tok) exceeds the whole %s TPM budget (%d); "
                            "sending anyway - lower the workload or raise the configured TPM",
                            tokens, self.name, self.tpm,
                        )
                    self._requests.append(now)
                    self._tokens.append((now, tokens))
                    self._token_sum += tokens
                    return slept

                waits = []
                if not fits_requests:
                    waits.append(60.0 - (now - self._requests[0]))
                if not fits_tokens and self._tokens:
                    waits.append(60.0 - (now - self._tokens[0][0]))
                wait = max(0.05, min(waits) + 0.05) if waits else 0.05

            logger.info(
                "pacing %s: sleeping %.1fs (window %d/%d req, ~%d/%d tok, need ~%d)",
                self.name, len(self._requests), self.rpm, self._token_sum, self.tpm, tokens,
            )
            self._sleep(wait)
            slept += wait

    def record_actual(self, estimated: int, actual: int) -> None:
        """Correct the window with the provider's real token count, if given.

        Keeps the estimate honest over a long run: if our chars/4 heuristic is
        consistently low, the window would otherwise drift into 429 territory.
        """
        delta = actual - estimated
        if not delta:
            return
        with self._lock:
            if self._tokens:
                stamp, value = self._tokens[-1]
                corrected = max(1, value + delta)
                self._tokens[-1] = (stamp, corrected)
                self._token_sum += corrected - value


@dataclass
class CallStats:
    """Counters we report at the end of a run, so throttling is never silent."""

    requests: int = 0
    rate_limit_hits: int = 0
    other_errors: int = 0
    seconds_throttled: float = 0.0
    tokens_used: int = 0

    def as_dict(self) -> dict[str, float | int]:
        return {
            "requests": self.requests,
            "rate_limit_hits": self.rate_limit_hits,
            "other_errors": self.other_errors,
            "seconds_throttled": round(self.seconds_throttled, 1),
            "tokens_used": self.tokens_used,
        }


@dataclass
class ModelHandle:
    """A configured client plus the limiter and counters for one *model*.

    Per model, not per provider: free-tier quotas are metered per model, so three
    roles on three different models get three independent budgets.
    """

    spec: ModelSpec
    client: openai.OpenAI
    limiter: RateLimiter
    stats: CallStats = field(default_factory=CallStats)


_HANDLES: dict[str, ModelHandle] = {}
_HANDLES_LOCK = threading.Lock()


def get_handle(spec: ModelSpec) -> ModelHandle:
    """Return the process-wide handle for ``spec``, creating it once."""
    key = str(spec)
    with _HANDLES_LOCK:
        handle = _HANDLES.get(key)
        if handle is None:
            handle = ModelHandle(
                spec=spec,
                client=openai.OpenAI(
                    api_key=spec.api_key(),
                    base_url=spec.base_url(),
                    max_retries=0,  # we do our own, so we can count and log them
                    timeout=180.0,
                ),
                limiter=RateLimiter(spec.rpm(), spec.tpm(), name=key),
            )
            _HANDLES[key] = handle
            logger.info(
                "model %s ready: base_url=%s rpm=%d tpm=%d",
                key, spec.base_url(), spec.rpm(), spec.tpm(),
            )
        return handle


def reset_handles() -> None:
    """Drop cached handles. Used by tests and when credentials change."""
    with _HANDLES_LOCK:
        _HANDLES.clear()


def all_stats() -> dict[str, dict[str, float | int]]:
    with _HANDLES_LOCK:
        return {key: handle.stats.as_dict() for key, handle in _HANDLES.items()}


def estimate_tokens(kwargs: dict) -> int:
    """Pre-estimate a chat-completion request's total token cost.

    Serialising the whole payload catches what dominates AgentDojo calls: the
    tool schemas, which are re-sent in full on every turn. Output is added
    because it counts toward the same budget.
    """
    try:
        payload = json.dumps(
            {k: v for k, v in kwargs.items() if k in ("messages", "tools", "tool_choice")},
            default=str,
        )
    except Exception:  # noqa: BLE001 - estimation must never break a run
        payload = str(kwargs)
    output = kwargs.get("max_tokens") or kwargs.get("max_completion_tokens") or DEFAULT_OUTPUT_RESERVE
    return len(payload) // CHARS_PER_TOKEN + int(output)


def _is_daily_limit(exc: Exception) -> bool:
    """Does this 429 refer to a per-day quota rather than a per-minute one?

    Groq's message names the dimension it tripped, e.g. "Rate limit reached ...
    on tokens per day (TPD)". Waiting that out is pointless.
    """
    text = str(exc).lower()
    return any(marker in text for marker in ("per day", "tpd", "rpd", "requests per day", "tokens per day"))


class RateLimitedClient:
    """Thin proxy over ``openai.OpenAI`` that paces and retries every request.

    AgentDojo's ``OpenAILLM`` only ever touches ``client.chat.completions.create``,
    so proxying that one path is enough and keeps the surface small. Presenting
    the same attribute chain means AgentDojo needs no changes at all.
    """

    def __init__(self, handle: ModelHandle, max_attempts: int = 6, base_delay: float = 2.0) -> None:
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
        limiter = self._handle.limiter
        estimated = estimate_tokens(kwargs)
        last_exc: Exception | None = None

        for attempt in range(1, self._max_attempts + 1):
            stats.seconds_throttled += limiter.acquire(estimated)
            try:
                stats.requests += 1
                completion = self._handle.client.chat.completions.create(**kwargs)
            except openai.RateLimitError as exc:
                stats.rate_limit_hits += 1
                last_exc = exc
                if _is_daily_limit(exc):
                    raise DailyQuotaExhausted(
                        f"{self._handle.spec} hit a per-DAY quota: {exc}. "
                        "Stop here and resume tomorrow - already-written results are kept "
                        "and re-running skips completed cases."
                    ) from exc
                delay = self._retry_after(exc) or self._base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "rate limited by %s (attempt %d/%d), backing off %.1fs",
                    self._handle.spec, attempt, self._max_attempts, delay,
                )
                time.sleep(delay)
                continue
            except (openai.APIConnectionError, openai.APITimeoutError, openai.InternalServerError) as exc:
                stats.other_errors += 1
                last_exc = exc
                delay = self._base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "transient error from %s (%s), retrying in %.1fs",
                    self._handle.spec, type(exc).__name__, delay,
                )
                time.sleep(delay)
                continue

            usage = getattr(completion, "usage", None)
            actual = getattr(usage, "total_tokens", None)
            if actual:
                stats.tokens_used += int(actual)
                limiter.record_actual(estimated, int(actual))
            else:
                stats.tokens_used += estimated
            return completion

        assert last_exc is not None
        raise last_exc

    @staticmethod
    def _retry_after(exc: openai.RateLimitError) -> float | None:
        """Honour the provider's own Retry-After when it sends one."""
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", None)
        if not headers:
            return None
        for key in ("retry-after", "Retry-After", "x-ratelimit-reset-tokens", "x-ratelimit-reset-requests"):
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
    """Public entry point: a paced, retrying client for ``spec``."""
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
