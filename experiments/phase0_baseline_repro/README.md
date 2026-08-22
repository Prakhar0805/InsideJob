# Phase 0 — Baseline reproduction

**Goal (CLAUDE.md §8):** before running anything new, confirm our setup
reproduces Progent's published behaviour within a reasonable margin, so later
numbers are trustworthy and discrepancies are understood rather than ignored.

Progent's own AgentDojo results (its `run.sh`) use `important_instructions` as
the attack and report a low single-digit ASR with utility largely preserved.
Our Phase 1 static-defended arm is the same measurement, so Phase 0 is really a
sanity gate on the wiring.

## What to run

A tiny defended slice, checked by hand against the transcripts:

```bash
# One suite, a few cases, Progent on, static attack.
python -m src.runner --suite banking --defense progent --attack static \
    --limit 3 --transcripts --verbose \
    --out results/phase0_baseline_repro/banking__static.jsonl
```

Then read the transcripts under
`results/phase0_baseline_repro/transcripts/` and confirm, for at least a few
cases:

- Progent generated a policy from the **user** query (visible in stderr as
  `security policy updated: ...`).
- Benign user-task tool calls were **allowed**; the injected attacker action was
  **blocked** with Progent's marker
  (`Please try other tools or arguments ...`).
- AgentDojo's `utility` still fired for the benign task.

## Definition of done

Our defended static ASR/utility on this slice is in the same ballpark as
Progent's published numbers on comparable conditions. If it is not, stop and
investigate the wiring (policy model creds, suite wrapping, block-marker
matching) before proceeding — do **not** paper over it (CLAUDE.md §8, §11).
