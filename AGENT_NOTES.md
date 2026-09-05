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

## [2026-09-05] — Automated Unit Testing & Export Harness
- Scope: Backend API proxy and hashing service (`server.js`).
- Fix:
  - Guarded `app.listen()` with `isDirectRun` (`import.meta.url === pathToFileURL(process.argv[1]).href`) and `NODE_ENV !== 'test'`.
  - Exported `app` and `SAMPLE_PRESETS` for automated testing.
  - Added `"test": "node --test"` to `package.json`.
  - Created `test/server.test.js` covering health probes, preset queries, RFC 8785 canonical hash computation, salt validation, and issuance/verification input validation (6/6 tests passing).
- Files touched:
  - `package.json`
  - `server.js`
  - `test/server.test.js`
  - `AGENT_NOTES.md`
