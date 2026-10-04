# Phase 3 implementation log — Intelligence modules

PRD.md is the source of truth. Phase 2 log: `docs/PHASE2_LOG.md`.

## Provider documentation verified (before coding)
- HIBP Pwned Passwords: `GET https://api.pwnedpasswords.com/range/{first5}` → `SUFFIX:count` text lines.
  Free, no key, User-Agent required. Only the 5-char SHA-1 prefix leaves the machine. (haveibeenpwned.com/API/v3)
- CIRCL Hashlookup: `GET https://hashlookup.circl.lu/lookup/{md5|sha1}/{hash}`. Free, no key, 404 = unknown.
  A match means "known file", never malicious. (circl.lu/services/hashlookup)
- MalwareBazaar: `POST https://mb-api.abuse.ch/api/v1/` form `{query: get_info, hash}`, `Auth-Key` header.
  `ok` vs `hash_not_found`. (bazaar.abuse.ch/api)
- CIRCL Vulnerability-Lookup: `GET https://vulnerability.circl.lu/api/vulnerability/{CVE}`. Free, no key.
  Numeric CVSS lives in ADP containers (CISA-ADP), not only CNA — found by testing the live API.
- IPinfo Lite: `GET https://api.ipinfo.io/lite/{ip}?token=` → country + ASN, free unlimited tier.
  Domains resolve to IP locally first. (ipinfo.io/developers)
- VirusTotal extended to `/ip_addresses/{ip}` and `/files/{hash}` (docs.virustotal.com, Phase-2 verified base).

## Built
- Analyzers (pure, framework-agnostic): `passwords.py` (length/diversity/sequences/common-patterns,
  ~bits estimate, strength 0-100 + dedicated risk where weak × breached compounds),
  `files.py` (md5/sha1/sha256, size, MIME, entropy, double-extension/executable signals),
  `network.py` (IP classification private/loopback/reserved/routable, domain facts),
  `vulnerabilities.py` (CVE parsing, CVSS→risk map, 3-entry offline reference for landmark CVEs).
- 5 adapters + `IntelService` reuse; all 10 catalogued sources now `implemented=True`.
- `analyzers/intel.py`: `run_password_scan` (plaintext never stored/logged/embedded),
  `run_file_scan` (+ `POST /api/scans/file` multipart; bytes hashed in memory then dropped),
  `run_network_scan`, `run_cve_scan` (live CVSS → reference → unknown ladder).
- `POST /api/scans` dispatches URL/hash/IP/domain/CVE; `POST /api/scans/password` dedicated endpoint.
- Reports: generic builder with module recommendations/verdict labels; file-status ladder
  (malicious > suspicious > known > unknown); CVE severity-only wording, no exploit instructions.
- Frontend: Account, Files (hash + upload), Network, Vulnerabilities pages; Report view renders
  facts/notes/plain-language for all modules; `api.upload()` for FormData; dist rebuilt.
- Tests: `test_intel_local` (14), `test_intel_providers` (12), `test_intel_api` (10). Suite: 125 passing.

## Bugs found and fixed
1. CVSS missing on live CIRCL records: scores sit in ADP containers; extractor now scans CNA + all ADP,
   with severity-word fallback. Verified live: CVE-2021-44228 → 10.0 Critical.
2. `severity_for_score(None)` lost ADP word severities → added word parameter.
3. CVE "unknown" verdict was unreachable (`risk_for_cvss(None)` → Low) → explicit unknown path.
4. `ConnectTimeout` fix from Phase 2 held; no regressions.
5. Test-only fixes: truncated SHA-1 fixture, "password" substring in pwnedpasswords hostname,
   common-password strength cap (now ≤10/Very weak), Phase-2 expectations for module availability.

## Deliberate limits (later phases)
- AI Security Analyst: rule-based summaries only. PDF export: JSON only.
- Text/Media/Lab modules untouched, still "Soon". No file content persisted; uploads capped at 25 MB.
