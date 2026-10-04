# Phase 4 implementation log — AI Security Analyst

PRD section 13. Prior logs: `docs/PHASE2_LOG.md`, `docs/PHASE3_LOG.md`.

## Design decision (budget-driven)
PRD budget is Rs 0 and names no LLM provider, so the analyst is a **local,
deterministic, template-based explanation layer** over structured evidence —
not a remote LLM call. This satisfies the PRD role exactly ("explanation
layer grounded in structured evidence") while working offline and making the
guardrails structural rather than prompt-based.

## Built
- `app/ai/analyst.py` — `build_assessment()` composes, strictly from the
  report's evidence rows + risk + recommendations:
  - `executive_summary` (risk, confidence, main driver, demo-labelled)
  - `observed` (local signals vs intel records, with counts and names)
  - `assessment` (how the score was reached; corroboration vs single-source caveats)
  - `key_findings` (top signals, each with `evidence_ref` index + `type: observed`)
  - `recommendations` (`type: recommendation`), `limitations`,
    `uncertainty` (`type: uncertain`: unavailable sources, not_found caveats, low confidence)
  - `grounding` (evidence count, sources, intel/local hit counts)
- Wording is probabilistic by construction (`suggest`, `consistent with`);
  forbidden-certainty words are covered by test.
- Attached in all 5 pipelines (URL, password, file, network, CVE) and persisted
  in `report_json`, so history reopen shows the same assessment.
- Frontend: "AI Security Analyst" panel (Observed / Assessment / Uncertainty +
  grounded/demo chip) on every report; graceful fallback for pre-AI saved scans.
- Tests: `test_ai.py` (7) — section labels, citation validity (every finding refs
  a real evidence index), no certainty language, gap disclosure, demo labelling,
  empty-evidence honesty, all-pipelines attachment. Suite: 132 passing.

## Guardrails (PRD 13) — how each is met
- Never invents API results/evidence/CVEs/sources: output strings are built
  only from evidence fields; test asserts every cited source exists in evidence.
- Never claims certainty: hedge table keyed by risk level; forbidden-word test.
- Never overrides providers: intel records are quoted, local-vs-intel separated.
- Observed / assessment / recommendation / uncertainty are distinct labelled blocks.
