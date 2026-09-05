# Agent Notes — ScatterID App

## [2026-09-05] — Decommission legacy client portal UI
- Problem: The legacy HTML/CSS/JS client portal in `public/` is decommissioned per ecosystem audit directives; UI will be redesigned from scratch in a future phase.
- Fix:
  - Removed legacy UI files in `public/` (`index.html`, `styles.css`, `app.js`).
  - Removed static asset serving middleware from `server.js`.
  - Updated `Dockerfile` to avoid referencing `public/`.
- Files touched:
  - `public/*` (deleted)
  - `server.js`
  - `Dockerfile`
  - `AGENT_NOTES.md`
- Next steps / Deferred:
  - Design and build the new ScatterID client application and portal UI from scratch.
