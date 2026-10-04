"""`python -m policy_corpus` — generate real LLM policies (Phase C), cached.

Subcommands:
    generate  Generate a policy per user task for ONE suite with ONE model.
              Cached and resumable; a daily-quota stop leaves partial results.
    dry-run   Build every prompt and report estimated tokens. No API call.
    status    Completed / failed / remaining per (model, suite) from the cache.

Generation wraps exactly one suite's tools (the one `SECAGENT_SUITE` names at
import), so `generate`/`dry-run` take a single `--suite` and set that variable
before any import. Evaluation is a separate step (`gapfuzz generated`) that must
run with `SECAGENT_SUITE` unset — the harm oracle refuses a suite loaded with it
set. Spends only a free-tier Groq budget; 429s are logged, a per-day cap stops
the run cleanly.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

SUITES = ["banking", "slack", "travel", "workspace"]


def _prepare_env(suite: str | None) -> None:
    """Load .env and, for generation, wrap exactly one suite — before any import."""
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    if suite is not None:
        os.environ["SECAGENT_SUITE"] = suite
    else:
        os.environ.pop("SECAGENT_SUITE", None)
    # Never let a suite import trigger a live policy-generation call.
    os.environ["SECAGENT_GENERATE"] = "False"
    os.environ["SECAGENT_UPDATE"] = "False"


def cmd_generate(args: argparse.Namespace) -> int:
    _prepare_env(args.suite)
    from src.config import ModelSpec
    from src.llm_clients import all_stats
    from src.policy_corpus import run_generation

    spec = ModelSpec.parse(args.model)
    path = run_generation(spec, args.suite, resume=not args.no_resume, retry_failed=args.retry_failed)
    print(f"wrote {path}")
    stats = all_stats().get(str(spec))
    if stats:
        print(f"rate-limit hits: {stats.get('rate_limit_hits', 0)}; tokens used: {stats.get('tokens_used', 0)}")
    return 0


def cmd_dry_run(args: argparse.Namespace) -> int:
    _prepare_env(args.suite)
    from src.config import ModelSpec
    from src.policy_corpus import dry_run

    spec = ModelSpec.parse(args.model)
    report = dry_run(spec, args.suite)
    print(f"dry-run {spec.model} / {args.suite}: {report['n_tasks']} tasks, "
          f"max prompt ~{report['max_prompt_tokens']} tokens, TPM budget {report['tpm_budget']}")
    if report["tasks_over_tpm"]:
        print(f"  ⚠ {len(report['tasks_over_tpm'])} task(s) exceed the per-minute budget: "
              f"{report['tasks_over_tpm']}. Set INSIDEJOB_TPM_<SLUG> higher.")
    else:
        print("  all tasks fit a single request under the TPM budget.")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    _prepare_env(None)
    from src.config import ModelSpec
    from src.policy_corpus import status

    models = [ModelSpec.parse(m).model for m in args.models]
    report = status(models, args.suites)
    for key, row in sorted(report.items()):
        print(f"{key:<40} cached={row['cached']:<3} ok={row['ok']:<3} failed={row['failed']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m policy_corpus", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate", help="Generate policies for one suite with one model.")
    p_gen.add_argument("--model", required=True, help="e.g. groq:openai/gpt-oss-120b")
    p_gen.add_argument("--suite", required=True, choices=SUITES)
    p_gen.add_argument("--no-resume", action="store_true", help="Regenerate even completed tasks.")
    p_gen.add_argument("--retry-failed", action="store_true", help="Retry tasks whose last attempt failed.")
    p_gen.set_defaults(func=cmd_generate)

    p_dry = sub.add_parser("dry-run", help="Report estimated prompt tokens; no API call.")
    p_dry.add_argument("--model", required=True)
    p_dry.add_argument("--suite", required=True, choices=SUITES)
    p_dry.add_argument("--json", type=Path, default=None)
    p_dry.set_defaults(func=cmd_dry_run)

    p_stat = sub.add_parser("status", help="Cache summary per (model, suite).")
    p_stat.add_argument("--models", nargs="+", default=["groq:openai/gpt-oss-120b", "groq:qwen/qwen3.8-27b"])
    p_stat.add_argument("--suites", nargs="+", default=SUITES, choices=SUITES)
    p_stat.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
