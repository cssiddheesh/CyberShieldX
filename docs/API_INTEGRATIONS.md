# API_INTEGRATIONS

Every provider was implemented against its official documentation (links below),
verified before coding. One adapter file each under `app/intelligence/providers/`.
All requests: hard timeout, ≤2 retries with backoff, 429 never retried, ≤2 MB bodies,
redirects never followed, failures returned as states — never raised, never logged
with secrets.

| Source | Endpoint | Auth | Keyless? | What is sent | Match → Evidence |
|---|---|---|---|---|---|
| URLhaus | `POST https://urlhaus-api.abuse.ch/v1/url/` form `{url}` (+`/v1/host/` for domains), header `Auth-Key` | abuse.ch Auth-Key (`URLHAUS_API_KEY`) | No | URL/host | `ok` → critical detected; `no_results` → not_found |
| PhishTank | `POST http://checkurl.phishtank.com/checkurl/` form `{url, format:json, app_key?}`, descriptive User-Agent | optional app key (`PHISHTANK_API_KEY`) | **Yes** (stricter limits) | URL | `in_database`+`valid` → critical/high; else not_found |
| urlscan.io | `GET https://urlscan.io/api/v1/search/?q=…` header `API-Key` (read-only search; scan submission deliberately unused) | API key (`URLSCAN_API_KEY`) | No | URL/domain | malicious-verdict scans → high detected |
| Google Safe Browsing | `POST …/v4/threatMatches:find?key=` + threatInfo body | API key (`GOOGLE_SAFE_BROWSING_API_KEY`) | No | URL | `matches[]` → critical detected |
| VirusTotal | `GET /api/v3/urls/{b64url}` `/domains/{d}` `/ip_addresses/{ip}` `/files/{hash}`, header `x-apikey` | API key (`VIRUSTOTAL_API_KEY`) | No | indicator | malicious>0 → critical; suspicious>0 → medium; 404 → not_found |
| HIBP Pwned Passwords | `GET https://api.pwnedpasswords.com/range/{5-char SHA-1 prefix}` (k-anonymity; suffix matched locally, rest discarded) | none | **Yes** | 5-char hash prefix only | count>0 → high/critical detected |
| CIRCL Hashlookup | `GET https://hashlookup.circl.lu/lookup/{md5,sha1}/{hash}` | none | **Yes** | hash | match → **informational** (known file, never malice); 404 → not_found |
| MalwareBazaar | `POST https://mb-api.abuse.ch/api/v1/` form `{query:get_info, hash}`, header `Auth-Key` | abuse.ch Auth-Key (`MALWAREBAZAAR_API_KEY`) | No | hash | `ok` → critical detected; `hash_not_found` → not_found |
| IPinfo Lite | `GET https://api.ipinfo.io/lite/{ip}?token=` (domains resolved locally first) | token (`IPINFO_TOKEN`) | No | IP address | country/ASN context → informational |
| CIRCL Vuln-Lookup | `GET https://vulnerability.circl.lu/api/vulnerability/{CVE}` (CVSS read from CNA **and** ADP containers) | none | **Yes** | CVE ID | record → severity from CVSS; 404 → not_found |

Docs: [URLhaus](https://urlhaus-api.abuse.ch/), [PhishTank](https://www.phishtank.com/api_info.php),
[urlscan](https://docs.urlscan.io/), [Safe Browsing](https://developers.google.com/safe-browsing/v4),
[VirusTotal](https://docs.virustotal.com/reference/overview), [HIBP](https://haveibeenpwned.com/API/v3),
[Hashlookup](https://www.circl.lu/services/hashlookup/), [MalwareBazaar](https://bazaar.abuse.ch/api/),
[IPinfo](https://ipinfo.io/developers/lite-api), [Vuln-Lookup](https://vulnerability.circl.lu/documentation/api.html).

## State machine (per source, shown on the Sources page)

`AVAILABLE` · `NOT_CONFIGURED` (no key — skipped, never "clean") · `UNAVAILABLE`
(timeout/unreachable/DNS fail) · `RATE_LIMITED` (429) · `ERROR` (bad response) ·
`DISABLED` (user toggle) · `UNCHECKED` (configured, no check yet).

Reports always show per-source origin labels: `LIVE_RESULT`, `LOCAL_ANALYSIS`,
`DEMO_DATA`, `NOT_CONFIGURED`, `PROVIDER_ERROR` — so a missing record is never
mistaken for a clean bill of health.
