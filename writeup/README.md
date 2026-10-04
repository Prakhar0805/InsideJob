# Write-up

- `FINDINGS.md` is the technical report: taxonomy, results, mitigation, limitations.
- `DISCLOSURE.md` holds the per-engine notes for the Progent and Janus maintainers. Nothing has been sent yet.
- `demo.html` is an interactive page that ports both matcher semantics to JavaScript and runs them in the browser on whatever you type. There is no build step. It loads IBM Plex from Google Fonts and falls back to system fonts offline. Its stat tiles are hardcoded, not read from `results/*.json`.
