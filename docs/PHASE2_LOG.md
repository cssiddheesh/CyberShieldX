# Phase 2 implementation log — PhishGuard end-to-end

Running record of what was built, verified, and fixed. PRD.md is the source of truth.

## Provider documentation verified (before coding)
- URLhaus: `POST https://urlhaus-api.abuse.ch/v1/url/` form `{url}`, header `Auth-Key`;
  `query_status` = `ok` / `no_results`. Host lookup via `/v1/host/`. (abuse.ch docs + abusech/URLhaus GitHub)
- PhishTank: `POST http://checkurl.phishtank.com/checkurl/` form `{url, format: json, app_key?}`,
  descriptive `User-Agent` required; `results.in_database/verified/valid`. (phishtank.com/api_info.php)
  `app_key` is optional → adapter works keyless (stricter limits), never NOT_CONFIGURED for missing key.
- urlscan.io: `GET https://urlscan.io/api/v1/search/?q=…` header `API-Key`, read-only search.
  Scan *submission* deliberately not used (async + quota side effects). (docs.urlscan.io)
- Google Safe Browsing v4: `POST …/v4/threatMatches:find?key=KEY` with `threatInfo` body.
- VirusTotal v3: `GET /api/v3/urls/{base64url_nopad}` header `x-apikey`; 404 = unknown, not safe.

## Built
- `app/analyzers/phishing.py` — normalization, refang, domain/port/entropy/subdomain/path-depth
  extraction, 20 heuristic indicators (IP host, no-HTTPS, punycode/IDN, confusable fold, shady TLD,
  length, entropy, subdomains, encoding, `@`, shortener, redirect params, unusual ports, keywords,
  brand-mismatch…), per-indicator Evidence. Heuristics cap at `high` severity, never `critical`.
- `app/correlation/engine.py` — dedupe, source weighting, corroboration bonus, plain-language explanation.
- `app/correlation/risk.py` — 0-100 score with per-point contributions, diminishing-returns caps,
  separate confidence, 4 verdicts; heuristics alone can never yield `likely_malicious`.
- `app/intelligence/providers/` — 5 adapters + `service.py` orchestrator (skips disabled/unconfigured,
  persists health, never raises, never returns raw bodies).
- `app/analyzers/pipeline.py` + `app/reports/builder.py` — full Detect→Correlate→Explain→Report pipeline,
  unified report layout (PRD 14/30), verdict-specific recommendations, limitations, demo dataset.
- `POST /api/scans` (201), `GET /api/reports/:id`; `phishing` + `analyze` modules flipped to available.
- Frontend: PhishGuard page, Universal Analyzer page, shared Report view (risk gauge, findings, evidence,
  score composition, sources, recommendations, JSON download), scan-detail route `/history/:id`,
  history rows link to reports, progress steps per PRD 17. `frontend/dist` rebuilt.
- Tests: `test_phishing` (19), `test_risk` (9), `test_providers` (11), `test_scan` (6). Suite: 89 passing.

## Bugs found and fixed during Phase 2
1. `@`-in-authority missed: normalization strips userinfo before detection → detect from raw input.
2. Confusable check skipped whenever IDN flag fired → run the fold independently on the raw host.
3. `ConnectTimeout` (refused/unreachable peer) misclassified as `timeout` → mapped to `network`
   (`test_connection_failure`); `ReadTimeout` still maps to `timeout`.
4. PhishTank endpoint follows official docs (`http://`, not `https://`).

## Bug carried over (pre-existing, environment-specific, not introduced here)
- None open: the single failing Phase-1 test on this machine was the timeout/network mapping above, fixed.

## Deliberate Phase-2 limits (for later phases)
- AI Security Analyst: rule-based summaries only; no LLM wiring.
- PDF export: JSON download only.
- Non-URL modules and their 5 providers: untouched, still "Soon".
