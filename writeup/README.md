# Write-up

- **`FINDINGS.md`** — the technical report (abstract, taxonomy, results, mitigation, limitations).
- **`DISCLOSURE.md`** — draft responsible-disclosure notes to the Progent and Janus maintainers. **Drafts only — nothing has been sent.**
- **`demo.html`** — the interactive Policy Dissector. Ports both matcher semantics to JS and runs them live in the browser on whatever you type; no build step, no CDN scripts. It does pull IBM Plex from Google Fonts, so it is not *fully* offline — it degrades to system fonts without a network. Its stat tiles are currently hardcoded rather than read from `results/*.json`.

The abandoned adaptive-attack brief that this project pivoted away from is preserved at repo root as `CLAUDE.old.md`; the `experiments/` tree is from that phase and is retained for provenance (see `experiments/SUPERSEDED.md`).
