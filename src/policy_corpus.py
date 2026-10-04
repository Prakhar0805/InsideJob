"""Phase C: generate real least-privilege policies with an LLM, and cache them.

Every rate in Phases A/B/E comes from policies *we* constructed to model the
documented generation behaviour. This module produces the other kind — policies
an LLM actually writes — so the prevalence of each flawed idiom can be measured
on real output rather than assumed. It is the only part of the project that
spends an API budget, so it is cached and resumable: a run that stops (a daily
quota, a crash, a Ctrl-C) leaves every completed record on disk, and re-running
skips them.

**Parity with the systems under test.** The prompt is built exactly as Progent
builds it, so the policies are what a real Progent deployment would generate:

* the system prompt is `secagent.tool.get_SYS_PROMPT()` verbatim (for the model
  names we use, no output-format suffix is appended — matching the paper's
  gpt-4o default);
* the user message is `"TOOLS: " + json.dumps(get_available_tools()) +
  "\\nUSER_QUERY: " + user_task.PROMPT`, where the tools JSON is Progent's own
  `apply_secure_tool_wrapper` output (not AgentDojo's schema);
* the call is temperature 0, seed 0, no `max_tokens`, with Progent's own
  temperature-escalating retry ladder on a parse failure;
* the response is parsed with `secagent.utils.extract_json` and installed as
  `(100, 0, args, 0)` per `{"name", "args"}` item — the shape both engines use.

**Two-process discipline.** Generation must run with `SECAGENT_SUITE` set (that
is what makes Progent populate `get_available_tools()` for the suite), and the
harm oracle *refuses* a suite loaded that way. So generation and evaluation are
separate invocations: this module writes JSON; `src/gapfuzz/generated.py` reads
it back with `SECAGENT_SUITE` unset. Because `SECAGENT_SUITE` is read at import
time and only the named suite's tools are wrapped, `generate` handles **one
suite per invocation** — run it once per (model, suite).

The cache layout under `results/policy_corpus/<model_slug>/`:
* `<suite>.json`   — committed: the policies + metadata, no secrets;
* `<suite>.jsonl`  — gitignored append log (one record per line, crash-safe);
* `raw/<suite>/<task>.txt` — gitignored raw responses, for auditing a parse.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from src.config import ModelSpec, _env_slug

logger = logging.getLogger(__name__)

CORPUS_ROOT = Path("results/policy_corpus")


def model_slug(model: str) -> str:
    """`openai/gpt-oss-120b` -> `openai_gpt_oss_120b` (a filesystem-safe dir name)."""
    return _env_slug(model).lower()


@dataclass
class PolicyRecord:
    """One generated policy (or a recorded failure) for one (model, suite, task)."""

    suite: str
    user_task_id: str
    model: str
    prompt: str
    tools_json: list[dict] = field(default_factory=list)
    raw_response: str = ""
    policy: dict | None = None
    error: str | None = None
    attempts: int = 0
    temperature_used: float = 0.0
    prompt_tokens_est: int = 0
    generated_at: str = ""

    @property
    def ok(self) -> bool:
        return self.policy is not None and self.error is None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PolicyRecord":
        known = {k: d[k] for k in d if k in cls.__dataclass_fields__}
        return cls(**known)


def _install(generated: Any) -> dict | None:
    """Turn the LLM's JSON array of `{name, args}` into the engine policy shape.

    Mirrors `secagent.tool.generate_security_policy`: one `(100, 0, args, 0)`
    allow rule per tool. Returns None for a malformed shape so the caller records
    a failure rather than crashing.
    """
    if not isinstance(generated, list):
        return None
    policy: dict[str, list] = {}
    for item in generated:
        if not isinstance(item, dict) or "name" not in item:
            continue
        policy.setdefault(item["name"], []).append((100, 0, item.get("args", {}), 0))
    return policy or None


def generate_one(
    spec: ModelSpec,
    system_prompt: str,
    tools_json: list[dict],
    user_task_id: str,
    user_prompt: str,
    *,
    suite: str,
    extract_json: Callable[[str], Any],
    max_attempts: int = 6,
) -> PolicyRecord:
    """Generate one policy, replicating Progent's retry ladder.

    `extract_json` is injected (Progent's `secagent.utils.extract_json` in
    production) so this function is unit-testable with a fake client and a fake
    parser. On any exception the temperature is bumped by 0.2 and retried, up to
    `max_attempts`; the final failure is *recorded*, never raised, so one bad
    task cannot abort a whole suite. A `DailyQuotaExhausted` is re-raised so the
    caller can stop cleanly.
    """
    from src.llm_clients import DailyQuotaExhausted, build_client, estimate_tokens

    content = "TOOLS: " + json.dumps(tools_json) + "\nUSER_QUERY: " + user_prompt
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": content},
    ]
    record = PolicyRecord(
        suite=suite,
        user_task_id=user_task_id,
        model=spec.model,
        prompt=content,
        tools_json=tools_json,
        prompt_tokens_est=estimate_tokens({"messages": messages}),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    client = build_client(spec)
    temperature = 0.0
    for attempt in range(1, max_attempts + 1):
        record.attempts = attempt
        record.temperature_used = temperature
        try:
            completion = client.chat.completions.create(
                model=spec.model, messages=messages, temperature=temperature, seed=0
            )
            record.raw_response = completion.choices[0].message.content or ""
            parsed = extract_json(record.raw_response)
            policy = _install(parsed)
            if policy is None:
                raise ValueError(
                    "no installable policy in response"
                    + (" (model returned 'no'/None)" if parsed is None else "")
                )
            record.policy = policy
            record.error = None
            return record
        except DailyQuotaExhausted:
            record.error = "daily quota exhausted before this task completed"
            raise
        except Exception as exc:  # noqa: BLE001 - record, do not abort the suite
            record.error = f"{type(exc).__name__}: {exc}"
            temperature += 0.2
    return record


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


def _paths(model: str, suite: str) -> tuple[Path, Path, Path]:
    root = CORPUS_ROOT / model_slug(model)
    return root / f"{suite}.json", root / f"{suite}.jsonl", root / "raw" / suite


def load_records(model: str, suite: str) -> dict[str, PolicyRecord]:
    """Completed records for (model, suite), keyed by user_task_id.

    Reads the committed `.json` if present, else replays the `.jsonl` log (the
    crash-safe source of truth). Later lines win, so a retried task supersedes
    its earlier failure.
    """
    summary, jsonl, _ = _paths(model, suite)
    records: dict[str, PolicyRecord] = {}
    if summary.exists():
        for d in json.loads(summary.read_text(encoding="utf-8")).get("records", []):
            r = PolicyRecord.from_dict(d)
            records[r.user_task_id] = r
    if jsonl.exists():
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            r = PolicyRecord.from_dict(json.loads(line))
            records[r.user_task_id] = r
    return records


def _append_record(model: str, suite: str, record: PolicyRecord) -> None:
    summary, jsonl, raw_dir = _paths(model, suite)
    jsonl.parent.mkdir(parents=True, exist_ok=True)
    with jsonl.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record.as_dict(), default=str) + "\n")
    if record.raw_response:
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / f"{record.user_task_id}.txt").write_text(record.raw_response, encoding="utf-8")


def write_summary(model: str, suite: str) -> Path:
    """Fold the append log into the committed `<suite>.json` summary."""
    summary, _, _ = _paths(model, suite)
    records = load_records(model, suite)
    ok = sum(1 for r in records.values() if r.ok)
    payload = {
        "model": model,
        "suite": suite,
        "n_records": len(records),
        "n_ok": ok,
        "n_failed": len(records) - ok,
        "generation_failure_rate": round((len(records) - ok) / len(records), 4) if records else 0.0,
        "records": [r.as_dict() for r in sorted(records.values(), key=lambda r: r.user_task_id)],
    }
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return summary


# --------------------------------------------------------------------------
# Orchestration (imports secagent + agentdojo; call only from the CLI)
# --------------------------------------------------------------------------


def _load_suite_and_tools(suite_name: str):
    """Load one suite with Progent's tools wrapped, returning (suite, tools_json, system_prompt).

    Requires ``SECAGENT_SUITE`` to already name ``suite_name`` (set it before any
    import). Progent's ``get_available_tools()`` is populated as a side effect of
    the suite module import that ``get_suites`` triggers, and it is exactly the
    tools JSON Progent's own generator would see.
    """
    if os.getenv("SECAGENT_SUITE") != suite_name:
        raise RuntimeError(
            f"SECAGENT_SUITE must be {suite_name!r} before import (got "
            f"{os.getenv('SECAGENT_SUITE')!r}). Generation wraps one suite per process; "
            "set the variable at process start."
        )
    import secagent  # noqa: PLC0415
    from agentdojo.task_suite.load_suites import get_suites  # noqa: PLC0415

    suites = get_suites("v1")
    suite = suites[suite_name]
    tools_json = secagent.get_available_tools()
    system_prompt = secagent.tool.get_SYS_PROMPT()
    if not tools_json:
        raise RuntimeError(
            f"Progent's available_tools is empty for {suite_name!r}; the suite's tools were not "
            "wrapped. Is SECAGENT_SUITE set to this suite at import time?"
        )
    return suite, tools_json, system_prompt


def run_generation(spec: ModelSpec, suite_name: str, *, resume: bool = True, retry_failed: bool = False) -> Path:
    """Generate a policy for every user task in one suite; cache and resume."""
    import secagent  # noqa: PLC0415

    suite, tools_json, system_prompt = _load_suite_and_tools(suite_name)
    existing = load_records(spec.model, suite_name) if resume else {}

    def already_done(task_id: str) -> bool:
        rec = existing.get(task_id)
        if rec is None:
            return False
        return rec.ok or not retry_failed

    from src.llm_clients import DailyQuotaExhausted  # noqa: PLC0415

    todo = [t for tid, t in suite.user_tasks.items() if not already_done(tid)]
    logger.info("generating %d/%d tasks for %s/%s", len(todo), len(suite.user_tasks), spec.model, suite_name)
    try:
        for task in todo:
            record = generate_one(
                spec, system_prompt, tools_json, task.ID, task.PROMPT,
                suite=suite_name, extract_json=secagent.utils.extract_json,
            )
            _append_record(spec.model, suite_name, record)
            status = "ok" if record.ok else f"FAIL ({record.error})"
            logger.info("  %s: %s", task.ID, status)
    except DailyQuotaExhausted as exc:
        logger.warning("stopping: %s", exc)
    return write_summary(spec.model, suite_name)


def dry_run(spec: ModelSpec, suite_name: str) -> dict[str, Any]:
    """Build every prompt and report estimated tokens — no API call."""
    from src.llm_clients import estimate_tokens  # noqa: PLC0415

    suite, tools_json, system_prompt = _load_suite_and_tools(suite_name)
    rows = []
    for task in suite.user_tasks.values():
        content = "TOOLS: " + json.dumps(tools_json) + "\nUSER_QUERY: " + task.PROMPT
        est = estimate_tokens({"messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": content}]})
        rows.append({"task": task.ID, "prompt_tokens_est": est})
    tpm = spec.tpm()
    over = [r for r in rows if r["prompt_tokens_est"] > tpm]
    return {
        "model": spec.model,
        "suite": suite_name,
        "n_tasks": len(rows),
        "tpm_budget": tpm,
        "max_prompt_tokens": max((r["prompt_tokens_est"] for r in rows), default=0),
        "tasks_over_tpm": [r["task"] for r in over],
        "rows": rows,
    }


def status(models: list[str], suites: list[str]) -> dict[str, Any]:
    """Completed / failed / remaining per (model, suite), read from the cache."""
    out: dict[str, Any] = {}
    for model in models:
        for suite in suites:
            records = load_records(model, suite)
            ok = sum(1 for r in records.values() if r.ok)
            out[f"{model_slug(model)}/{suite}"] = {
                "cached": len(records),
                "ok": ok,
                "failed": len(records) - ok,
            }
    return out
