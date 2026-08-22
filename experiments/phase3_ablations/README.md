# Phase 3 — Ablations + cross-model comparison

**Goal (CLAUDE.md §8):** understand what drives the Phase 2 number and answer
the pre-registered secondary question explicitly.

## Ablations

Each varies one knob and re-runs a slice (or the full suite where cheap enough).
All are declared here *before* running so none is a post-hoc fishing trip.

1. **Round count.** Re-run Phase 2 at `--max-rounds` in {1, 2, 4, 8, 16} on a
   fixed sample and plot adaptive ASR vs rounds. Round 1 collapses to the static
   baseline by construction, so this isolates the marginal value of adaptation.

   ```bash
   for r in 1 2 4 8 16; do
     python -m src.runner --suite banking --defense progent --attack adaptive \
       --max-rounds "$r" --limit 8 \
       --out "results/phase3_ablations/rounds/banking__r${r}.jsonl"
   done
   python -m src.aggregate "results/phase3_ablations/rounds/*.jsonl"
   ```

2. **Attacker model strength.** Swap `INSIDEJOB_ATTACKER_MODEL` for a stronger /
   weaker model from the same non-agent provider and re-run a slice. Tests
   whether the result is sensitive to attacker capability.

3. **Per-domain breakdown.** Already emitted by `src/aggregate.py` for every
   run; Phase 3 just reads it out and discusses which domains, if any, move.

4. **Policy updates on/off.** Re-run with `--no-policy-updates` to see how much
   of any success came through Progent's mid-run policy-widening path. Because
   the scope check already separates policy escapes from in-scope successes,
   this ablation cross-checks that split.

## Cross-model comparison (pre-registered secondary hypothesis)

Run the *identical* pipeline for both agent models and place their adaptive
headline ASRs side by side, then resolve against `PREREGISTRATION.md`:
**consistent** (both hold or both crack) vs **model-dependent** (they diverge).

```bash
python -m src.aggregate \
  "results/phase2_adaptive/*/*.jsonl" \
  --csv results/phase3_ablations/cross_model.csv
```

## Definition of done

Ablation table complete; the cross-model consistency question **explicitly
answered**, not merely implied by the numbers (CLAUDE.md §8).
