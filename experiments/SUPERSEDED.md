# Superseded

This directory (phase0–phase3 runbooks, `PREREGISTRATION.md`) belongs to the
project's original framing: an adaptive prompt-injection attack against Progent,
measured as attack-success-rate across AgentDojo with a live agent. That approach
was abandoned on 2026-08-24 because it required a full LLM agent rollout per data
point — infeasible on a $0 free-tier budget — and because the security-critical
component of a deterministic defense is the *matcher*, which is auditable for
free.

The current project audits the enforcement matcher directly. See `CLAUDE.md`
(§ pivot note) and `writeup/FINDINGS.md`. These files are kept for provenance and
for the pre-registration discipline they document; they do not describe the code
as it now stands.
