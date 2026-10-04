# Results

Committed outputs of the runs that back the write-up, one directory per experiment.

- `phase_a_differential/` and `phase_d_crossengine/`: the differential sweep
  for Progent and Janus (`python -m gapfuzz audit --enforcer <name> --json`),
  plus the per-class cross-engine profile (`python -m gapfuzz crossengine`).
- `phase_b_harm/`: the reachable-harm sweep (`python -m gapfuzz harm --json`).
- `phase_semantic/`: the tool-side parser-differential sweep
  (`python -m gapfuzz semantic`). AgentDojo-scored and modeled harm are
  reported separately.
- `policy_corpus/<model_slug>/<suite>.json`: the cached LLM-generated policies,
  one summary per (model, suite). Generate with
  `python -m policy_corpus generate --model <spec> --suite <suite>`, one suite
  per invocation (the module docstring explains why).
- `phase_c_generated/`: the offline evaluation of that corpus
  (`python -m gapfuzz generated --corpus results/policy_corpus/<model_slug>`):
  which idiom the model used per argument kind, lint findings, and
  differential bypassability.

The append logs (`*.jsonl`) and raw model responses (`raw/`) are gitignored.
