# SECURITY

CyberShield X is a defensive analysis tool. It follows these rules in its own
construction and testing (see `tests/test_api.py` leak guards).

## Secrets

- API keys live only in `.env`, loaded into `Settings._keys`. They are excluded
  from `public_dict()`, `repr()`, every API response and every log line.
- Request headers are never logged (the HTTP client returns errors as data).
- Exception **messages** are never logged — only exception type + code location —
  because messages can carry URLs, tokens or user input.

## Passwords (strictest handling in the app)

- Analyzed in memory only; only the first 5 SHA-1 characters leave the machine.
- Never stored: `Database.save_scan` replaces password indicators (scan + findings)
  with `[password - not stored]` before any write.
- Never embedded in evidence, reports, logs or error messages (tested).
- Dedicated `POST /api/scans/password` endpoint with a 512-char cap; the generic
  `/identify` path never classifies input as a password.

## Uploads

- Size-capped (default 25 MB, HTTP 413 beyond it); read once, hashed, then the
  byte buffer is dropped. Never written to disk, never executed, never scanned
  with shell commands. Non-image uploads to `/scans/media` are rejected (415).

## Input / output

- All JSON bodies size-capped; overlong indicators rejected with 400.
- Indicator length bounded (2048) and evidence fields truncated at the model layer,
  so provider responses can never bloat storage or the UI.
- Control characters stripped from display text; report PDF renders plain text only.
- Security headers on every response (`nosniff`, `DENY` framing, strict CSP,
  `no-referrer`); API responses are `no-store`.
- Per-client rate limiting (120/min default, 429 + `Retry-After`).
- Path traversal refused (static serving confined to `frontend/dist`).

## External calls

- Hard timeouts, bounded retries with backoff, 429 never retried, 2 MB cap,
  redirects never followed (no silent credential-bearing hops).
- Local-first: every module produces a real assessment with zero keys; provider
  outages degrade to `UNAVAILABLE`/`PROVIDER_ERROR` states, never crashes or
  fabricated clean verdicts.

## Optional AI key

- The user-supplied model key is stored server-side only (Settings → database,
  or `AI_API_KEY` in `.env`), shown in no response and written to no log.
- Enhancement prompts contain the report's evidence summary only — passwords
  never reach the model (stored reports carry placeholders), and the key travels
  in the request header, which the HTTP client never logs.
- Model output is schema-validated and labelled AI-generated; failures degrade
  to a plain error, never to fabricated content.

## Never implemented (by design)

No file execution, no shell scanning, no password storage/cracking, no exploit
instructions (CVE output is severity + remediation pointers only), no credential
harvesting, no unauthorized/active scanning, no attack automation. The Threat Lab
is static multiple-choice content with no live attack code.
