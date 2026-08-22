"""Fan a full experiment out across suites as separate processes.

Each ``python -m src.runner`` handles exactly one suite under one condition
(:mod:`src.runner` explains why one suite per process is mandatory for Progent).
This module launches those processes for a whole phase and then aggregates their
JSONL into one summary, so a phase is a single command.

Processes are run sequentially by default, not in parallel: the free-tier rate
budget (CLAUDE.md section 6) is per API key and shared across suites, so running
four suites at once would just multiply 429s. ``--parallel`` is offered for the
case where someone has raised their limits, but it is not the default.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from src.config import RESULTS_DIR, Settings
from src.runner import SUITES, default_out_path


@dataclass(frozen=True)
class Condition:
    """One arm of the experiment: a defence + attack-mode pairing."""

    defense: str
    attack_mode: str

    @property
    def state(self) -> str:
        if self.defense == "none":
            return "none"
        return "adaptive" if self.attack_mode == "adaptive" else "static"


#: The three per-model comparisons CLAUDE.md section 10 requires, in order.
PHASE1_CONDITIONS = (
    Condition("none", "static"),      # undefended ASR
    Condition("progent", "static"),   # Progent vs static attack
)
PHASE2_CONDITIONS = (Condition("progent", "adaptive"),)  # the measurement


def run_condition(
    condition: Condition,
    suite: str,
    *,
    max_rounds: int,
    limit: int | None,
    injection_limit: int | None,
    transcripts: bool,
    version: str,
    extra: list[str],
) -> tuple[str, str, int, Path]:
    """Launch one runner subprocess and return (suite, state, returncode, out)."""
    settings = Settings.from_env()
    out = default_out_path(settings, suite, condition.state)
    cmd = [
        sys.executable, "-m", "src.runner",
        "--suite", suite,
        "--defense", condition.defense,
        "--attack", condition.attack_mode,
        "--max-rounds", str(max_rounds),
        "--version", version,
        "--out", str(out),
        "--verbose",
    ]
    if limit is not None:
        cmd += ["--limit", str(limit)]
    if injection_limit is not None:
        cmd += ["--injection-limit", str(injection_limit)]
    if transcripts:
        cmd += ["--transcripts"]
    cmd += extra

    print(f"\n=== {suite} | {condition.defense}/{condition.attack_mode} (state={condition.state}) ===",
          file=sys.stderr)
    result = subprocess.run(cmd)
    return suite, condition.state, result.returncode, out


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.orchestrate",
        description="Run a full experiment phase across all suites and summarise it.",
    )
    parser.add_argument("--phase", choices=("1", "2", "all"), default="all",
                        help="1 = baselines (undefended + Progent-static); 2 = adaptive; all = both.")
    parser.add_argument("--suites", nargs="+", choices=SUITES, default=list(SUITES))
    parser.add_argument("--max-rounds", type=int, default=8)
    parser.add_argument("--limit", type=int, default=None, help="Cap user tasks per suite (smoke tests).")
    parser.add_argument("--injection-limit", type=int, default=None)
    parser.add_argument("--version", default="v1")
    parser.add_argument("--transcripts", action="store_true")
    parser.add_argument("--parallel", action="store_true",
                        help="Run suites concurrently. Off by default: the free-tier budget is shared per key.")
    parser.add_argument("--summary-csv", type=Path, default=None)
    parser.add_argument("extra", nargs="*", help="Extra flags passed through to each runner (after --).")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    conditions: list[Condition] = []
    if args.phase in ("1", "all"):
        conditions += list(PHASE1_CONDITIONS)
    if args.phase in ("2", "all"):
        conditions += list(PHASE2_CONDITIONS)

    jobs = [(condition, suite) for condition in conditions for suite in args.suites]

    def _run(job: tuple[Condition, str]):
        condition, suite = job
        return run_condition(
            condition, suite,
            max_rounds=args.max_rounds, limit=args.limit, injection_limit=args.injection_limit,
            transcripts=args.transcripts, version=args.version, extra=args.extra,
        )

    if args.parallel:
        with ThreadPoolExecutor(max_workers=len(args.suites)) as pool:
            results = list(pool.map(_run, jobs))
    else:
        results = [_run(job) for job in jobs]

    failures = [(s, st, rc) for s, st, rc, _ in results if rc != 0]
    out_paths = [out for *_, out in results if out.exists()]

    print("\n" + "=" * 72, file=sys.stderr)
    print("PHASE SUMMARY", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    if out_paths:
        from src.aggregate import summarize_paths

        table = summarize_paths(out_paths)
        print(table.render())
        if args.summary_csv:
            _write_csv(table, args.summary_csv)
    if failures:
        print(f"\n{len(failures)} job(s) exited non-zero: {failures}", file=sys.stderr)
        return 1
    return 0


def _write_csv(table, path: Path) -> None:
    import csv

    rows = [row.as_dict() for row in table.rows]
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            row["escape_kinds"] = ";".join(f"{k}={v}" for k, v in row["escape_kinds"].items())
            writer.writerow(row)
    print(f"\nwrote summary CSV -> {path}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
