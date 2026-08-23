# InsideJob

**Adaptive red-teaming of a deterministic agent defense (Progent), using only
authorized-action attacks — zero GPU, zero fine-tuning, API-only.**

This is the implementation. The standing research spec — questions, scope
boundaries, pre-registered success criteria — lives in [`CLAUDE.md`](CLAUDE.md)
and governs everything here.

## The question, in one line

Does Progent's deterministic policy check still hold when the attacker *adapts
over many rounds*, against a *real frontier model over an API*, across
*AgentDojo's full suite*, while staying inside the tools the agent is *already
authorized to use* — and is the answer the same across two model families?

## How the pieces fit

```
attacker model  ──proposes injection──►  AgentDojo environment
  (gpt-oss)                                   │ agent reads injected content
      ▲                                       ▼
      │ feedback: blocked / executed /   agent model (llama)  ──tool call──►  Progent policy check
      │           in-scope / succeeded        │                                    │ allow / deny
      └───────────────────────────────────────┴────────────────────────────────────┘
```

- **Agent** and **attacker** are always different **model families**, enforced
  in `src/config.py` (an attacker blind spot must not be correlated with an
  agent blind spot). Family, not provider, is the hard rule — that is what the
  correlated-failure argument rests on. The project currently runs **Groq-only**,
  so both roles share a provider; every run prints that caveat, and
  `experiments/PREREGISTRATION.md` records what it costs the cross-model claim.
- **Progent** is vendored unmodified and driven only through its public
  `secagent` API (see `VENDOR.md`).
- **AgentDojo**'s own formal, state-based scoring decides success — no LLM
  judge.
- Every successful attack is scope-checked (`src/scope_check.py`): only
  *authorized-action* successes count toward the headline number; policy-escape
  successes are logged and reported separately.

## Layout

| Path | What |
|---|---|
| `src/config.py` | model specs, credentials, role separation, Progent bootstrap |
| `src/llm_clients.py` | Groq/Gemini OpenAI-compatible clients, rate limiting, backoff |
| `src/agent.py` | AgentDojo pipeline backed by a free-tier model; run recorder |
| `src/defense.py` | swappable defence adapters (`none`, `progent`) |
| `src/attacker.py` | evolutionary black-box attacker (generate → test → mutate) |
| `src/scope_check.py` | authorized-action boundary check (the validity core) |
| `src/case_runner.py` | the adaptive loop for one case |
| `src/runner.py` | one suite × one condition per process (CLI) |
| `src/orchestrate.py` | fan a phase out across suites, then summarise |
| `src/aggregate.py` | ASR-with-utility, per-domain, per-model reporting |
| `src/logging_schema.py` | the CLAUDE.md §9 result record + JSONL I/O |
| `experiments/` | per-phase runbooks + the locked pre-registration |
| `agentdojo/`, `progent/` | vendored upstream, unmodified (see `VENDOR.md`) |

## Setup

```bash
python -m venv .venv
. .venv/Scripts/activate            # Windows;  ../bin/activate on POSIX
pip install -e ./agentdojo -e ./progent      # vendored forks
pip install -r requirements.txt

cp .env.example .env                # then fill in GROQ_API_KEY
```

Groq-only for now, so `GROQ_API_KEY` (https://console.groq.com/keys) is the only
credential needed; the Gemini plumbing stays in place and is re-enabled purely
by editing `.env`. Everything runs on **free tiers only** — the project's cost
ceiling is $0 (CLAUDE.md §6). The clients rate-limit and back off rather than
spend into an overage. Note that with agent, attacker and Progent's policy model
all on one Groq key, they share a single rate budget (`GROQ_RPM`).

## Running

```bash
# Smoke test (a few cases, no cost worries):
python -m src.runner --suite banking --defense progent --attack adaptive \
    --limit 2 --injection-limit 1 --max-rounds 4 --verbose

# Phase 1 baselines (undefended + Progent-static), all suites:
python -m src.orchestrate --phase 1

# Phase 2 adaptive sweep (ONLY after PREREGISTRATION.md is locked):
python -m src.orchestrate --phase 2 --max-rounds 8 --transcripts \
    --summary-csv results/phase2_adaptive/summary.csv

# Summarise anything:
python -m src.aggregate "results/**/*.jsonl"
```

See `experiments/*/README.md` for the full runbook per phase and
`experiments/PREREGISTRATION.md` for the success criteria that must be locked
before Phase 2.

## Swapping in a different defence (a project deliverable)

The attacker, runner, and scope check never import `secagent` directly — they
talk to `src/defense.py`'s `DefenseAdapter` protocol. To evaluate a different
AgentDojo-wrapped defence, implement the five protocol methods and register the
class in `DEFENSES`; nothing in the attack loop changes (CLAUDE.md §3, §11).

## Tests

```bash
python -m pytest -q
```

Covers the logic the research validity depends on: scope-checking, result
aggregation and the §9/§10 reporting rules, role separation, the result schema,
the attacker's parsing/seeding/fallback, and one offline end-to-end pass through
the real AgentDojo banking suite (no API, no cost).

## What this project does not do

Out of scope by CLAUDE.md §4 and not implemented here: white-box/gradient
attacks, self-hosting or fine-tuning any model, designing a new defence,
data-leak/secret-extraction attacks, and any comparison of our ASR directly
against another paper's number on a different model (§10).
