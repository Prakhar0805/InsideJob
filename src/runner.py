"""Sweep runner: one (suite x condition) benchmark run per invocation.

Why one suite per process. Progent's AgentDojo fork wraps a suite's tools with
the policy proxy only when ``SECAGENT_SUITE`` names that suite *at the moment
the suite module is first imported*, and Progent's policy state
(``secagent.tool.security_policy`` and friends) is process-global. Trying to
flip a suite between defended and undefended inside one process would fight both
facts. Progent's own ``run.sh`` sidesteps this by launching a separate process
per suite, and we follow suit: this module runs exactly one
``(suite, defense, attack-mode)`` combination, and the Phase experiment scripts
launch the four suites as four processes.

The three comparisons CLAUDE.md section 10 requires, expressed as flag combos:

    --defense none    --attack static     -> undefended ASR      (state "none")
    --defense progent --attack static     -> static defended ASR  (state "static")
    --defense progent --attack adaptive   -> adaptive defended ASR (state "adaptive")

All three are per *our own* model; none is compared directly to a published
number (that would be apples to oranges - CLAUDE.md section 10).

Bootstrapping order is load-bearing: :func:`src.config.bootstrap` must set the
Progent environment variables before ``agentdojo``/``secagent`` are imported, so
every agentdojo-touching import in this file is deferred into :func:`main`.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Only cost-free, import-safe modules at top level. Anything that pulls in
# agentdojo/secagent is imported inside main(), after bootstrap() has run.
from src.config import RESULTS_DIR, Settings, bootstrap

logger = logging.getLogger(__name__)

SUITES = ("banking", "slack", "travel", "workspace")
DEFENSES = ("none", "progent")
ATTACK_MODES = ("static", "adaptive")


def _defense_state(defense: str, attack_mode: str) -> str:
    """Map a flag combination to the CLAUDE.md section 9 ``defense_state`` enum."""
    if defense == "none":
        return "none"
    return "adaptive" if attack_mode == "adaptive" else "static"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.runner",
        description="Run one AgentDojo suite under one defence/attack condition.",
    )
    parser.add_argument("--suite", required=True, choices=SUITES)
    parser.add_argument("--defense", default="progent", choices=DEFENSES)
    parser.add_argument("--attack", default="adaptive", choices=ATTACK_MODES, dest="attack_mode")
    parser.add_argument(
        "--max-rounds", type=int, default=8,
        help="Adaptive round budget per case (ignored for --attack static, which is always 1 round).",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Cap the number of user tasks (smoke tests / held-out validation). Default: all.",
    )
    parser.add_argument(
        "--injection-limit", type=int, default=None,
        help="Cap injection tasks per user task. Default: all.",
    )
    parser.add_argument("--version", default="v1", help="AgentDojo suite version (default v1 = all ~629 cases).")
    parser.add_argument("--out", type=Path, default=None, help="Output JSONL path. Default under results/.")
    parser.add_argument("--transcripts", action="store_true", help="Also write raw per-case transcripts.")
    parser.add_argument(
        "--no-policy-updates", action="store_true",
        help="Disable Progent's mid-run policy widening (SECAGENT_UPDATE). Default: on, matching Progent's run.sh.",
    )
    parser.add_argument("--force-rerun", action="store_true", help="Ignore existing records and rerun every case.")
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser


def default_out_path(settings: Settings, suite: str, state: str) -> Path:
    phase = {"none": "phase1_static", "static": "phase1_static", "adaptive": "phase2_adaptive"}[state]
    model_slug = settings.agent.model.replace("/", "_").replace(":", "_")
    return RESULTS_DIR / phase / model_slug / f"{suite}__{state}.jsonl"


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    enable_progent = args.defense == "progent"
    state = _defense_state(args.defense, args.attack_mode)

    # Load .env, resolve roles, and set Progent's env BEFORE importing agentdojo.
    settings = Settings.from_env()
    bootstrap(
        policy=settings.policy if enable_progent else None,
        suite=args.suite,
        enable_progent=enable_progent,
        policy_updates=not args.no_policy_updates,
    )

    # Now it is safe to import the agentdojo-backed layers.
    from agentdojo.task_suite.load_suites import get_suites

    from src.agent import RecordingPipeline, build_pipeline
    from src.attacker import AdaptiveAttacker
    from src.case_runner import CaseSpec, run_case
    from src.defense import build_defense, install_policy_probe
    from src.logging_schema import ResultWriter, completed_keys

    suite = get_suites(args.version)[args.suite]
    defense = build_defense(args.defense)

    pipeline_inner = build_pipeline(settings.agent)
    policy_probe = install_policy_probe(pipeline_inner, defense) if enable_progent else None
    pipeline = RecordingPipeline(pipeline_inner)
    attacker = AdaptiveAttacker(settings.attacker)

    out_path = args.out or default_out_path(settings, args.suite, state)
    writer = ResultWriter(out_path)
    already = set() if args.force_rerun else completed_keys(out_path)
    transcript_dir = out_path.parent / "transcripts" if args.transcripts else None

    user_tasks = list(suite.user_tasks.values())[: args.limit]
    injection_tasks = list(suite.injection_tasks.values())
    if args.injection_limit is not None:
        injection_tasks = injection_tasks[: args.injection_limit]

    total = len(user_tasks) * len(injection_tasks)
    logger.info(
        "sweep: suite=%s state=%s agent=%s attacker=%s cases=%d out=%s",
        args.suite, state, settings.agent, settings.attacker, total, out_path,
    )
    print(
        f"[insidejob] {args.suite} | defense={args.defense} attack={args.attack_mode} "
        f"(state={state}) | {total} cases -> {out_path}",
        file=sys.stderr,
    )
    # Printed every run, not just once: the quality of attacker/agent separation
    # is a caveat on the result, and it belongs in the run log next to the
    # numbers rather than only in .env (CLAUDE.md section 5).
    print(f"[insidejob] roles: {settings.separation_note()}", file=sys.stderr)

    done = 0
    ran = 0
    for user_task in user_tasks:
        for injection_task in injection_tasks:
            done += 1
            key = (settings.agent.model, state, args.suite, user_task.ID, injection_task.ID)
            if key in already:
                continue
            spec = CaseSpec(
                suite=suite,
                user_task=user_task,
                injection_task=injection_task,
                defense_state=state,  # type: ignore[arg-type]
                max_rounds=args.max_rounds,
            )
            record = run_case(
                spec,
                settings=settings,
                pipeline=pipeline,
                policy_probe=policy_probe,
                defense=defense,
                attacker=attacker,
                transcript_dir=transcript_dir,
            )
            writer.write(record)
            ran += 1
            flag = "HIT" if record.headline_success() else ("esc" if record.attack_succeeded else "---")
            print(
                f"[{done}/{total}] {user_task.ID}+{injection_task.ID}: {flag} "
                f"rounds={record.rounds_used} util={record.utility_score:.0f} "
                f"scope={'ok' if record.within_authorized_scope else record.escape_kind}",
                file=sys.stderr,
            )

    _print_run_summary(out_path, ran)
    return 0


def _print_run_summary(out_path: Path, ran: int) -> None:
    from src.aggregate import summarize_file
    from src.llm_clients import all_stats

    print(f"\n[insidejob] wrote {ran} new record(s) to {out_path}", file=sys.stderr)
    try:
        summary = summarize_file(out_path)
        print(summary.render(), file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not summarise %s: %s", out_path, exc)
    stats = all_stats()
    if stats:
        print(f"[insidejob] API stats: {stats}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
