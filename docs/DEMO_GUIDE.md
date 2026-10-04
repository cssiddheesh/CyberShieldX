# DEMO_GUIDE — 2–4 minute exhibition script

Story in one line: **DETECT → CORRELATE → EXPLAIN → REPORT** — many signals,
one explainable assessment. All demo inputs below are safe (documentation IPs,
well-known test values, public CVEs).

## Setup (1 min before visitors)

1. Double-click `run.bat`, open http://localhost:8000
2. If the venue has no internet: Settings → turn **Demo Mode ON** (banner shows
   `DEMO MODE`; every result is labelled `DEMONSTRATION DATA`).
3. With internet, leave Demo Mode OFF — local analysis + live keyless sources
   (PhishTank, HIBP, CIRCL, urlscan-reads) work with zero keys.

## The 3-minute run

| Time | Do | Say | Expect |
|---|---|---|---|
| 0:00 | Open Dashboard | "A 360° security command center — every ring segment is a working module." | All 8 segments lit; posture + source status live |
| 0:30 | PhishGuard → paste `http://192.0.2.10/paypal/login` → Analyze | "A login link on a bare IP mentioning PayPal." | IP-host + brand-mismatch evidence, High risk, explained points |
| 1:15 | Point at AI Security Analyst panel | "The AI only restates cited evidence — observed vs assessment vs uncertainty." | Grounded summary, key findings with evidence refs |
| 1:40 | Reports → download PDF | "One click to a handout-ready report." | PDF with risk, evidence, recommendations |
| 2:10 | File Forensics → paste EICAR `275a021bbfb6489e5a62c763859df87b4c8e1534458e96e041e9e209f98d882` | "The industry-standard harmless test file — every engine flags it on purpose." | Malware intel hit, safely |
| 2:40 | Threat Lab → one phishing question | "And visitors can test themselves — fully safe simulations." | Quiz + explanation |

Spare 30-second extras: Account Security with `password` (Critical, breached);
Vulnerabilities with `CVE-2021-44228` (CVSS 10.0, plain language, no exploits);
Text Analyzer with any article; Sources page to show provider states honestly.

## If something fails live

- Provider down/rate-limited: point at the per-source state chips — "it says
  *provider error*, keeps the local analysis, and never pretends clean."
- No internet at all: flip Demo Mode ON and continue the same script.
- Never present demo rows as live findings; the UI labels them throughout.

## Judge questions (30-second answers)

- *"Isn't this just API calls?"* — "No: heterogeneous signals are normalized to
  one evidence model, deduplicated, reliability-weighted, correlated, and scored
  transparently — the AI explains that assessment from cited evidence only."
- *"What if a source is wrong?"* — "Weighting + corroboration bonuses absorb
  single-source noise; confidence drops when sources disagree or are missing."
- *"Is the AI making things up?"* — "It can't: output is composed strictly from
  evidence rows, and tests assert every finding cites a real evidence index."
