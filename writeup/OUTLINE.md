# Write-up outline

Fill in after Phase 2/3. The structure is fixed now so the write-up cannot be
quietly reshaped around whatever the numbers turn out to say (CLAUDE.md §3, §14).

1. **Question & gap.** LaunchSafe named this exact scenario as its open next
   question; state it and why static tests under-report (Zhan et al.; "The
   Attacker Moves Second").
2. **Setup.** Progent (unmodified) as the defence; AgentDojo (unmodified
   scoring) as the harness; two agent models from different providers; a
   separate-family evolutionary black-box attacker; the authorized-action
   constraint and how it is enforced (`src/scope_check.py`).
3. **Pre-registration.** Reproduce the locked `PREREGISTRATION.md` verbatim,
   with its lock timestamp. Any deviations, dated.
4. **Phase 0/1 baselines.** Reproduction check; per-model undefended and
   Progent-static ASR + Utility, per domain.
5. **Phase 2 result.** Adaptive headline ASR (in-scope only) vs the band, per
   model and per domain; the policy-escape channel reported alongside; Utility
   throughout. The decisive (3)-vs-(2) internal comparison.
6. **Phase 3.** Round-count and attacker-strength ablations; the explicit
   cross-model consistency answer.
7. **Honest conclusion.** Whichever combination of outcomes actually happened,
   stated plainly. The four §3 deliverables, checked off.
8. **Limitations & responsible disclosure.** Free-tier model choices; sandbox
   only; §12 disclosure posture if anything real surfaced.

## Deliverable checklist (CLAUDE.md §3)

- [ ] Timestamped threshold decision, committed before Phase 2 ran.
- [ ] Working, documented, reusable harness (swap-in defence demonstrated).
- [ ] Clear answer to the cross-model question.
- [ ] Honest write-up of whatever actually happened.
