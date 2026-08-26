# Results

Raw JSONL logs and aggregated CSVs land here, one subtree per phase.

- `gapfuzz audit --json` / `harm --json` write machine-readable differential and
  reachable-harm results here.
- `policy_corpus/` **(planned, does not exist yet)** will hold cached
  LLM-generated policies (Phase C) so the harm
  sweep can be re-run without re-spending budget.

Large raw dumps and `*.jsonl` are gitignored; commit the aggregated JSON/CSV and
any summary tables that back the write-up.
