# Phase 5 implementation log — Remaining modules + reports

Prior logs: PHASE2/3/4. PRD sections 7.6, 7.7, 7.8, 14.

## Built
- **Text Analyzer** (`analyzers/textstats.py`, `POST /api/scans/text`, Text page):
  sentence-rhythm CV, type-token ratio, AI-tell diction (+breadth bonus for many
  distinct tells), repetition, em-dash/hedge/impersonal/long-sentence signals.
  Output low/moderate/high/inconclusive (<40 words). Required limitation always
  attached; authorship never claimed. Universal Analyzer links long free text to /text.
- **Media Forensics** (`analyzers/media.py`, `POST /api/scans/media`, Media page):
  stdlib-only PNG/JPEG/GIF/BMP/WebP parsing (dimensions, text/EXIF/APP segments,
  software tags, JPEG quality estimate from DQT vs standard table). Never executes
  anything; non-images rejected 415. Hash intel (VT/MalwareBazaar by SHA-256) reused.
  Wording probabilistic throughout.
- **Threat Lab** (`app/lab/quizzes.py`, `/api/lab/*`, Lab page): 6 modules x 5
  questions, answers stay server-side, graded submit with explanations. No attack
  code of any kind - awareness questions only.
- **Reports**: PDF export (`reports/pdf.py`, reportlab, `GET /api/reports/:id.pdf`;
  501 without the optional dep) + Reports page (JSON/PDF per scan). JSON unchanged.
- Modules text/media/lab/reports flipped to available; all 14 modules listed.

## Bugs found and fixed (all via failing tests before merge)
1. `builder.py`: media/text tables inserted outside the dict (IndentationError).
2. JPEG SOF offset (dimensions at seg[1:5], not [3:7]) and DQT table count off-by-one.
3. Generic "Software" PNG tags ignored: any software tag now raises editor_tag.
4. Tell-word cap (25) muted blatant samples: cap 30 + breadth bonus (>=10 distinct).
5. Test-only: truncated-SHA style mistakes avoided; HUMAN fixture word-count bound relaxed.

## Tests / docs
- `test_phase5.py` (17): analyzer units incl. hand-built PNG/JPEG fixtures, lab
  grading/blindness, text/media/lab/PDF API, module availability. Suite: 149 passing.
- requirements.txt gains optional `reportlab>=3.6,<6` (PDF only).
