"""`python -m gapfuzz` - the offline audit CLI.

The headline reproducibility feature: `python -m gapfuzz audit --enforcer progent`
reproduces the differential result in seconds, with no API key and no cost. That
is the property that makes the finding easy for a reviewer to check.

Subcommands:
    audit    differential sweep - how much larger is the admitted set than the
             policy reads, per policy style, per gap class.
    harm     reachable-harm sweep - which AgentDojo injection tasks have a
             validated bypass (admitted AND reference-rejected AND achieves the
             attacker's objective) under a canonical policy set.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _prepare_env() -> None:
    """Force the zero-cost configuration before any agentdojo/secagent import."""
    os.environ.setdefault("GROQ_API_KEY", "offline")
    os.environ["SECAGENT_GENERATE"] = "False"
    os.environ["SECAGENT_UPDATE"] = "False"
    os.environ.pop("SECAGENT_SUITE", None)


def _load_suites(version: str, only: list[str] | None):
    from agentdojo.task_suite.load_suites import get_suites

    suites = get_suites(version)
    if only:
        suites = {name: suites[name] for name in only}
    return suites


def cmd_audit(args: argparse.Namespace) -> int:
    from src.enforcers import build_enforcer
    from src.gapfuzz.sweep import run_sweep

    suites = _load_suites(args.version, args.suites)
    enforcer = build_enforcer(args.enforcer)
    report = run_sweep(suites, enforcer)

    print(report.render())
    if args.json:
        payload = {
            "enforcer": report.enforcer,
            "styles": {
                s: {
                    "fragments": r.fragments,
                    "bypassable_fragments": r.bypassable_fragments,
                    "bypass_rate": round(r.bypass_rate, 4),
                    "gap_counts": dict(r.gap_counts),
                }
                for s, r in report.styles.items()
            },
            "total_instances": len(report.instances),
            "invariant_violations": report.invariant_violations,
            "instances": [i.as_dict() for i in report.instances] if args.full else "omitted (use --full)",
        }
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 1 if report.invariant_violations else 0


def cmd_harm(args: argparse.Namespace) -> int:
    from src.enforcers import build_enforcer
    from src.gapfuzz.harm_sweep import run_harm_sweep

    suites = _load_suites(args.version, args.suites)
    enforcer = build_enforcer(args.enforcer)
    report = run_harm_sweep(suites, enforcer)

    print(report.render())
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(report.as_dict(), indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m gapfuzz", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--enforcer", default="progent", help="Engine under test (progent | janus | strict).")
    common.add_argument("--suites", nargs="+", default=None, choices=["banking", "slack", "travel", "workspace"])
    common.add_argument("--version", default="v1")
    common.add_argument("--json", type=Path, default=None, help="Write machine-readable results here.")

    p_audit = sub.add_parser("audit", parents=[common], help="Differential matcher-semantics sweep.")
    p_audit.add_argument("--full", action="store_true", help="Include every gap instance in the JSON.")
    p_audit.set_defaults(func=cmd_audit)

    p_harm = sub.add_parser("harm", parents=[common], help="Reachable-harm sweep over AgentDojo tasks.")
    p_harm.set_defaults(func=cmd_harm)

    return parser


def main(argv: list[str] | None = None) -> int:
    _prepare_env()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
