# ARCHITECTURE

CyberShield X: **Detect → Correlate → Explain → Report**. One workflow for every
indicator type; providers and analyzers plug into shared evidence, correlation,
risk, AI-explanation and reporting layers.

## Runtime layout

```text
React 19 SPA (frontend/dist, served by Flask)
        │  JSON over /api/*
        ▼
Flask app (app/main.py) — thin HTTP layer only
        │
        ├─ app/api/routes.py      validation + serialisation, no analysis logic
        ├─ app/core/              config (.env), indicator identification, modules, security
        ├─ app/analyzers/         local engines (URL, password, file, network, CVE, text, media)
        │                         + scan pipelines (pipeline.py, intel.py)
        ├─ app/intelligence/      provider adapters, orchestrator, HTTP client, registry
        ├─ app/correlation/       evidence merge + transparent 0-100 risk model
        ├─ app/ai/                evidence-grounded analyst (local templates, no LLM calls)
        ├─ app/reports/           unified report builder + PDF renderer
        ├─ app/database/db.py     SQLite (scans, findings, reports, sources, settings)
        └─ app/lab/quizzes.py     static Threat Lab question bank
```

## Key design decisions

- **Flask instead of FastAPI.** The build environment could not install FastAPI,
  so Flask serves HTTP. All analysis code is framework-agnostic (no Flask imports
  outside `app/api/` and `app/main.py`); a future port touches only those files.
- **Evidence is the only currency.** Every local engine and every provider emits
  `Evidence` objects (source, source_type, indicator, finding, severity,
  confidence, evidence, reference, status, origin). Correlation, risk, AI text
  and reports only ever see Evidence — never raw provider JSON.
- **Provider adapters are isolated.** One file per provider under
  `app/intelligence/providers/`; each implements `check / normalize / health_check`
  and must never raise. The orchestrator (`service.py`) skips disabled and
  unconfigured sources and records per-provider status rows.
- **Risk and confidence are separate.** Risk 0–100 with per-point contributions;
  confidence from signal count, agreement and availability. Heuristics alone can
  never yield a `likely_malicious` verdict.
- **Passwords are special.** Plaintext lives only in request memory: hashed for
  k-anonymity inside the adapter, never logged, and replaced by a placeholder
  before database writes (`Database.save_scan`, `_redact`).
- **Uploads are untrusted bytes.** Hashed in memory, never written to disk,
  never executed; byte buffers are dropped after analysis. Size-capped.
- **Frontend is a prebuilt bundle.** `frontend/src` (React, no router lib — tiny
  hash-free history router) compiles via esbuild to `frontend/dist`, which Flask
  serves, including SPA fallback routes. Rebuild only after editing `src/`.

## Data flow of one scan (all modules)

```text
POST /api/scans {input} ──► identify() ──► module pipeline
      │                                        ├─ local analysis → Evidence (origin LOCAL)
      │                                        ├─ IntelService.query → Evidence (LIVE / ERROR…)
      │                                        ├─ correlate() → dedupe + weights + explanation
      │                                        ├─ risk model → score + contributions + verdict
      │                                        ├─ AI analyst → observed/assessment/uncertainty
      │                                        └─ report builder → unified JSON ──► SQLite
      └─ 201 {report} ◄── AI panel, findings, evidence, downloads rendered from it
```

## Configuration

Secrets live only in `.env` (see `.env.example`; every key optional). Missing key
⇒ source state `NOT_CONFIGURED` ⇒ skipped, never "clean". Runtime tunables
(`CYBERSHIELD_*`) cover host/port, upload cap, HTTP timeout/retries and API rate limit.

## Test map

`tests/`: `test_api` (routes, headers, leak guards), `test_core` (config, identify,
evidence model), `test_database`, `test_http_client` (timeouts, 429, malformed),
`test_phishing`, `test_risk`, `test_providers`, `test_scan`, `test_intel_*`,
`test_ai`, `test_phase5`. Real network is only touched by live-provider paths;
adapter unit tests use a fake HTTP layer.
