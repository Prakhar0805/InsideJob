# Phase 2 — Adaptive attacker (the measurement)

> **Do not start Phase 2 until `experiments/PREREGISTRATION.md` is locked and
> timestamped** (CLAUDE.md §3, §8). That is a hard gate.

**Goal:** run the evolutionary black-box attacker against Progent across the
full AgentDojo suite, per model, and produce the adaptive headline ASR that the
whole project turns on — comparison (3) in CLAUDE.md §10.

## Validate adaptation first (Phase 2 definition of done)

Before the full run, show the attacker *demonstrably improves over rounds* on a
held-out sample. A quick way:

```bash
python -m src.runner --suite workspace --defense progent --attack adaptive \
    --max-rounds 8 --limit 5 --transcripts --verbose \
    --out results/phase2_adaptive/_heldout/workspace__adaptive.jsonl
```

Then inspect the per-round records (`rounds[]` in the JSONL): the attacker's
strategy should change round to round, and any successes should tend to appear
at round > 0, not only at the seed. If every success is at round 0, the adaptive
loop is adding nothing and needs investigating before the full run.

## Full run

```bash
python -m src.orchestrate --phase 2 --max-rounds 8 --transcripts \
    --summary-csv results/phase2_adaptive/summary.csv
```

Repeat for the second agent model (swap roles in `.env`, keeping providers
distinct). Resume is automatic: re-running skips cases already in the JSONL, so
a throttled or interrupted sweep can just be relaunched.

## Definition of done

Complete results for all ~629 cases, **both** models, with the authorized-action
scope check applied to every successful attack (in-scope vs policy-escape split
recorded per case). Blocked attempts logged too, not just successes (§9).

## Reading the result

`src/aggregate.py` prints two rates side by side:

- `ASR` — in-scope successes only. **This is the headline number** compared to
  the pre-registered band.
- `ASR+esc` — includes policy-boundary escapes, reported alongside so the escape
  channel is never hidden.

Utility sits next to both. Judge against `PREREGISTRATION.md`, per model and per
domain, then in aggregate.
