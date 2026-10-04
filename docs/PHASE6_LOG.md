# Phase 6 implementation log — Exhibition polish

PRD sections 36-38, 40. Prior logs: PHASE2/3/4/5.

## Docs (PRD 37, matching implementation)
- `docs/ARCHITECTURE.md` — runtime layout, Flask-instead-of-FastAPI rationale,
  evidence-as-currency, per-scan data flow, test map.
- `docs/API_INTEGRATIONS.md` — all 10 providers: endpoint, auth, keyless status,
  what is sent, match→evidence mapping, state machine, origin labels.
- `docs/SECURITY.md` — secrets, password handling, uploads, I/O caps, headers,
  external-call discipline, never-implemented list.
- `docs/DEMO_GUIDE.md` — 3-minute script with safe inputs and expected outcomes,
  offline fallback path, failure handling, judge Q&A.
- README structure section rewritten to describe the finished tree.

## Product fixes from polish testing
1. **Silent outages (real bug):** failed providers leave no evidence rows, so the
   correlation explanation never mentioned the outage. Added
   `correlate.note_provider_gaps()` — consulted-but-failed sources are now named
   in every affected report ("…the score reflects only available evidence").
   Wired into all 6 pipelines; covered by `tests/test_offline.py` (3 tests: URL,
   password, file-upload total-outage survival with local-only 201s).
2. Verified 360° ring: all 8 dimensions report `ready` (honest full coverage).

## Final verification
- Full suite: **152 passing** (`python -m unittest discover -s tests -t .`).
- Live server smoke (`python -m app.main`, throwaway DB/port): `/api/health`,
  `/api/modules` (14 modules), full `/api/scans` round-trip, `%PDF` bytes from
  `/api/reports/:id.pdf`, SPA shell served for client routes — all 200.
- `frontend/dist` rebuilt from current `src` (no stale bundle).
- `run.bat` path intact: venv → requirements (incl. optional reportlab for PDF)
  → `.env` bootstrap → serve. First run needs internet; everything after works offline.

## Exhibition state
Every PRD module works; Demo Mode labels all synthetic output; offline =
local analysis + honest state chips. Known non-goals (unchanged): no antivirus
claims, no exploit instructions, no stored passwords, no executed uploads.
