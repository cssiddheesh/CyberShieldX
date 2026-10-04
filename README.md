# CyberShield X

AI-powered 360° digital threat intelligence and security analysis platform.
**Detect → Correlate → Explain → Report.** Strictly defensive and educational.
The product definition is in [PRD.md](PRD.md).

## Build status

The project is built in phases. This table is kept in step with what actually works.

| Phase | Scope | Status |
|---|---|---|
| 1 | Architecture, backend, database, config, evidence model, source registry, Demo Mode flag, dashboard shell | **Done** |
| 2 | PhishGuard end to end (local URL analysis, intelligence, evidence, risk, report) | **Done** |
| 3 | Evidence normalization, correlation engine, risk engine | **Done (all scan types; reused by every module)** |
| 4 | Password, file/hash, IP/domain and CVE modules | **Done** |
| 5 | AI Security Analyst | **Done (local evidence-grounded analyst on every report)** |
| 6 | Reports (PDF/JSON) and history reopen | **Done (JSON + PDF export, Reports page, history reopen)** |
| 7 | Text analyzer, media forensics, Threat Lab | **Done** |
| 8 | Testing, polish, exhibition/demo dataset | **Done (152 tests, docs, demo guide, offline proof)** |

**What works now:** everything from Phase 1, plus PhishGuard end-to-end: paste a link (even defanged) in
PhishGuard or the Universal Analyzer and get local heuristic analysis, live checks against 5 configured
phishing/intelligence providers (URLhaus, PhishTank, urlscan.io, Google Safe Browsing, VirusTotal),
deduplicated evidence, an explained 0-100 risk score with separate confidence, verdict, recommendations,
a JSON report download, and saved history that reopens. Account Security rates password strength and checks
HIBP breach exposure via k-anonymity; File Forensics hashes uploads and checks hash intelligence; IP/Domain
adds context and reputation; Vulnerabilities explains CVEs in plain language. Every report now carries an
AI Security Analyst assessment (observed / assessment / recommendation / uncertainty) grounded strictly in
cited evidence. The Text Analyzer estimates AI-likeness, Media Forensics inspects image metadata, the Threat Lab
runs safe quizzes, and every report exports as JSON and PDF. Optionally, paste your own AI model key
(OpenAI-compatible, or local Ollama) in Settings and every report automatically includes a plain-prose
AI explanation —
the model only ever sees the evidence summary, never passwords or keys. Without API keys every scan still works on local
analysis alone; Demo Mode labels everything DEMONSTRATION DATA.

**What does not work yet:** text/media/lab analyzers are still marked "Soon".
All 10 catalogued sources have adapters. PDF export and the AI Security
Analyst are not started.

## Run on Windows

1. Install Python 3.10 or newer from python.org (tick "Add python.exe to PATH").
2. Double-click `run.bat` (first run needs internet to install packages).
3. Open http://localhost:8000

No API keys are needed. Keys are optional and go in `.env` (created automatically from `.env.example`).
Providers without a key show **Not configured** and are skipped. Not configured never means "no threat found".

The interface is built from `frontend/src` into `frontend/dist` with Node.js 18+.
Run `build_frontend.bat` after editing frontend source.

## Deploy to Cloudflare Pages

Pages hosts the static frontend; the Flask backend and SQLite database must
continue running on a computer or server. The included Pages Function proxies
same-origin `/api/*` calls to the backend through a Cloudflare Tunnel. Follow
[the Cloudflare Pages deployment guide](docs/CLOUDFLARE_PAGES.md) for GitHub,
Tunnel, Pages build settings, and the required access controls. The backend
does not currently authenticate users, so protect both public hostnames before
making the deployment available.

## Run tests

    python -m unittest discover -s tests -t .

## Structure

    app/
      main.py            Flask app factory and entry point
      api/               HTTP routes (validation only, no analysis logic)
      core/              config, security helpers, indicator identification, module catalog
      models/            common Evidence model, risk levels, scan record
      intelligence/      10 provider adapters, orchestrator, HTTP client, source registry
      analyzers/         local engines + scan pipelines (URL, password, file, network, CVE, text, media)
      correlation/       evidence merge + transparent risk model
      ai/                evidence-grounded analyst (local, no LLM calls)
      reports/           unified report builder + PDF export
      database/          SQLite layer (scans, findings, reports, sources, settings)
      lab/               Threat Lab question bank (static educational content)
    frontend/            React 19 interface (src/), bundled with esbuild into dist/
    functions/            Cloudflare Pages API proxy (Pages deployments only)
    tests/               unit and API tests (run: python -m unittest discover -s tests -t .)
    docs/                ARCHITECTURE, API_INTEGRATIONS, SECURITY, DEMO_GUIDE + per-phase logs

Analyzers, the evidence model, correlation, risk and AI code never import Flask, so the web layer is replaceable.

## Security notes

- API keys are read from `.env`, never hard-coded, and never appear in API responses or logs.
- Passwords are never stored: the database layer replaces a password indicator before saving.
- Uploaded files will be treated as untrusted data and never executed (file module arrives in phase 4).
- Error logs record the exception type and location only, never messages, request bodies or headers.
