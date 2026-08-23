"""Tests for free-tier pacing.

On Groq's free tier the tokens-per-minute cap binds long before requests-per-
minute (8K TPM vs 30 RPM, against agent calls carrying 1k-4k tokens of tool
schema). A limiter that only counted requests would 429-storm, so the token
window is load-bearing for whether a sweep completes at all.

A fake clock is injected so these run instantly instead of really sleeping a
minute per assertion.
"""

from __future__ import annotations

from src.config import ModelSpec
from src.llm_clients import (
    DEFAULT_OUTPUT_RESERVE,
    RateLimiter,
    _is_daily_limit,
    estimate_tokens,
)


class FakeClock:
    """A monotonic clock that only advances when something sleeps."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def _limiter(rpm: int, tpm: int) -> tuple[RateLimiter, FakeClock]:
    clock = FakeClock()
    return RateLimiter(rpm, tpm, name="test", clock=clock.time, sleeper=clock.sleep), clock


def test_token_window_blocks_before_request_window():
    """With a generous RPM and a tight TPM, tokens must be what stops us."""
    limiter, clock = _limiter(rpm=30, tpm=1000)
    assert limiter.acquire(400) == 0.0
    assert limiter.acquire(400) == 0.0
    # Third 400-token call exceeds 1000 tok/min, though only 3 of 30 requests used.
    slept = limiter.acquire(400)
    assert slept > 0, "third call should have been paced by the token window"
    assert clock.slept, "limiter must actually wait, not just report a delay"


def test_token_window_reopens_after_a_minute():
    limiter, clock = _limiter(rpm=30, tpm=1000)
    limiter.acquire(900)
    assert limiter.acquire(900) > 0        # forced to wait for the window to roll
    assert clock.now >= 1060.0             # ...by roughly a full minute


def test_request_window_still_enforced():
    limiter, _ = _limiter(rpm=2, tpm=10_000_000)
    assert limiter.acquire(1) == 0.0
    assert limiter.acquire(1) == 0.0
    assert limiter.acquire(1) > 0, "third call should have been paced by the request window"


def test_oversized_request_does_not_deadlock():
    """A call bigger than the whole minute budget must still go out."""
    limiter, _ = _limiter(rpm=30, tpm=100)
    assert limiter.acquire(5000) == 0.0  # sent immediately, with a warning


def test_record_actual_corrects_the_window():
    """If our chars/4 estimate is low, the real count must correct the window."""
    limiter, _ = _limiter(rpm=30, tpm=1000)
    limiter.acquire(100)
    limiter.record_actual(estimated=100, actual=900)  # provider says it was 900
    assert limiter.acquire(200) > 0, "budget is spent; next call must wait"


def test_estimate_tokens_counts_tool_schemas():
    """Tool schemas dominate AgentDojo calls and must be in the estimate."""
    small = estimate_tokens({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 10})
    big = estimate_tokens(
        {
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"function": {"name": f"tool_{i}", "description": "x" * 200}} for i in range(24)],
            "max_tokens": 10,
        }
    )
    assert big > small * 10


def test_estimate_tokens_reserves_output():
    """Output counts toward the same budget, so it cannot be ignored."""
    assert estimate_tokens({"messages": []}) >= DEFAULT_OUTPUT_RESERVE
    assert estimate_tokens({"messages": [], "max_tokens": 4096}) >= 4096


def test_daily_limit_detection():
    """A per-day 429 must be told apart from a per-minute one: waiting out a
    daily cap is pointless, so the sweep should stop and resume tomorrow."""
    assert _is_daily_limit(Exception("Rate limit reached for model X on tokens per day (TPD)")) is True
    assert _is_daily_limit(Exception("Rate limit reached ... requests per day (RPD)")) is True
    assert _is_daily_limit(Exception("Rate limit reached for model X on tokens per minute (TPM)")) is False


def test_budgets_are_per_model_and_overridable(monkeypatch):
    """Quotas are metered per model, so each role must get its own budget."""
    monkeypatch.setenv("GROQ_TPM", "7000")
    monkeypatch.setenv("INSIDEJOB_TPM_OPENAI_GPT_OSS_120B", "5000")
    assert ModelSpec("groq", "openai/gpt-oss-120b").tpm() == 5000  # per-model wins
    assert ModelSpec("groq", "qwen/qwen3.6-27b").tpm() == 7000     # falls back to provider


def test_handles_are_keyed_per_model(monkeypatch):
    """Two roles on two models must not share one budget."""
    from src.llm_clients import get_handle, reset_handles

    monkeypatch.setenv("GROQ_API_KEY", "test")
    reset_handles()
    try:
        a = get_handle(ModelSpec("groq", "openai/gpt-oss-120b"))
        b = get_handle(ModelSpec("groq", "qwen/qwen3.6-27b"))
        again = get_handle(ModelSpec("groq", "openai/gpt-oss-120b"))
        assert a.limiter is not b.limiter
        assert a.limiter is again.limiter  # same model reuses one bucket
    finally:
        reset_handles()
