# Vendored upstream code

Both dependencies are **vendored, not modified**. They are checked in at a
pinned commit so results stay reproducible and so anyone can diff our tree
against upstream to confirm we did not quietly patch the defense or the
scoring (CLAUDE.md §11).

| Directory | Upstream | Commit | Date |
|---|---|---|---|
| `progent/` | https://github.com/sunblaze-ucb/progent | `8a8eb894b9d568a32b4e58252fea85b47f789c77` | 2026-05-13 |
| `agentdojo/` | same repo, `agentdojo/` subdirectory (Progent's instrumented fork of https://github.com/ethz-spylab/agentdojo, v0.1.29) | `8a8eb894b9d568a32b4e58252fea85b47f789c77` | 2026-05-13 |

`agentdojo/` was moved from `progent/agentdojo/` to the top level to match the
repository layout in CLAUDE.md §7. Its contents are byte-identical to upstream.

## Verifying we did not modify them

```bash
git clone https://github.com/sunblaze-ucb/progent /tmp/progent-upstream
cd /tmp/progent-upstream && git checkout 8a8eb894b9d568a32b4e58252fea85b47f789c77
diff -r /tmp/progent-upstream/agentdojo <repo>/agentdojo
diff -r --exclude=agentdojo /tmp/progent-upstream <repo>/progent
```

Both diffs should be empty apart from `.git/` and build artifacts. If either is
not empty, that is a bug — CLAUDE.md §11 forbids modifying AgentDojo's scoring
and Progent's policy engine. Everything InsideJob adds lives in `src/`.

## Why Progent's AgentDojo fork rather than stock AgentDojo

Progent ships its own instrumented AgentDojo because the policy engine has to
sit between the agent and tool execution. The hooks are:

- `agentdojo/src/agentdojo/default_suites/v1/*/task_suite.py` — wraps each
  suite's tools in `secagent.apply_secure_tool_wrapper` when
  `SECAGENT_SUITE` names that suite.
- `agentdojo/src/agentdojo/agent_pipeline/basic_elements.py` — `InitQuery`
  calls `secagent.generate_security_policy(query)`, deriving the policy from
  the *user's* task prompt before any untrusted content is seen.
- `agentdojo/src/agentdojo/agent_pipeline/tool_execution.py` — optionally
  calls `generate_update_security_policy` after each tool round when
  `SECAGENT_UPDATE=True`.
- `agentdojo/src/agentdojo/benchmark.py` — resets the policy between tasks.

Using stock AgentDojo instead would mean re-deriving those hooks ourselves,
which is exactly the kind of reimplementation CLAUDE.md §6 rules out.
