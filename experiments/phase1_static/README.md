# Phase 1 — Static baselines (ours)

**Goal (CLAUDE.md §8):** clean undefended and Progent-defended *static* ASR /
Utility numbers, per model, across all four domains. These are comparisons (1)
and (2) of the per-model triple in CLAUDE.md §10 and the reference points the
adaptive number in Phase 2 is judged against.

## What to run

Both baseline arms, all four suites, for the agent model currently named in
`.env` as `INSIDEJOB_AGENT_MODEL`:

```bash
python -m src.orchestrate --phase 1 --max-rounds 8
```

That launches, per suite, two runner processes:

- `--defense none --attack static`   → `defense_state = none`   (undefended)
- `--defense progent --attack static`→ `defense_state = static` (Progent, static)

Results land under `results/phase1_static/<model>/` and a combined per-(model,
state, domain) table plus an aggregate row is printed at the end.

## Cross-model

Repeat with the second agent model to get its Phase 1 baselines (swap the two
role lines in `.env`, keeping agent and attacker on different providers):

```bash
# .env: INSIDEJOB_AGENT_MODEL=gemini:gemini-2.5-flash
#       INSIDEJOB_ATTACKER_MODEL=groq:llama-3.3-70b-versatile
python -m src.orchestrate --phase 1 --max-rounds 8
```

## Definition of done

Undefended and Progent-static ASR + Utility logged for **both** agent models,
all four domains, with per-domain breakdowns (never averaged away, §9).
