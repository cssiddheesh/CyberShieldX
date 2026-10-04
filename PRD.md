# CyberShield X
## AI-Powered 360° Digital Threat Intelligence & Security Analysis Platform

**Project:** AI 360 — Computer Science Department Exhibition  
**Project Type:** Software-only cybersecurity intelligence platform  
**Primary Language:** Python  
**Recommended Backend:** FastAPI  
**Recommended Frontend:** React (or an equivalent modern frontend if already present)  
**MVP Database:** SQLite  
**Budget:** ₹0 core API budget  
**Deployment:** Local Windows laptop; optional LAN deployment

---

# 1. Executive Summary

CyberShield X is a unified defensive cybersecurity intelligence platform that combines local security analysis, public/free threat-intelligence sources, evidence normalization, threat correlation, risk assessment, explainable AI, and security reporting.

Instead of presenting unrelated cybersecurity tools, the platform provides one common workflow:

**Detect → Correlate → Explain → Report**

Users can analyze:

- URLs and phishing indicators
- passwords for local strength and exposure using privacy-preserving checking
- files and hashes
- IP addresses and domains
- software/CVEs
- text
- images/media

The central differentiator is the **Threat Correlation Engine**, which combines evidence from multiple sources rather than simply displaying raw API responses.

The **AI Security Analyst** is an explanation layer grounded in structured evidence. It must not invent findings or claim certainty where analysis is probabilistic.

The project is strictly defensive and educational.

---

# 2. Problem Statement

Digital threats occur across many different surfaces:

- phishing websites
- exposed passwords
- suspicious files
- malicious hashes
- vulnerable software
- suspicious IPs/domains
- manipulated or AI-generated content
- deceptive text

Existing services often specialize in individual categories.

CyberShield X provides a single interface for investigating multiple indicator types and correlating evidence into an understandable assessment.

### Core Question

How can multiple cybersecurity intelligence sources and local analysis techniques be combined into one explainable security assessment platform?

---

# 3. Product Vision

CyberShield X should feel like a simplified **Digital Security Command Center**.

It must be a coherent product, not a collection of unrelated API buttons.

The central architecture is:

```text
User Input
    ↓
Indicator Identification
    ↓
Local Analysis
    ↓
Threat Intelligence
    ↓
Evidence Normalization
    ↓
Threat Correlation Engine
    ↓
Risk Engine
    ↓
AI Security Analyst
    ↓
Security Report
```

---

# 4. AI 360 Alignment

The platform demonstrates 360° security analysis by examining multiple dimensions:

| Dimension | Capability |
|---|---|
| Web | URL and phishing analysis |
| Identity | Password security/exposure |
| Files | Hash and file intelligence |
| Infrastructure | IP/domain intelligence |
| Vulnerabilities | CVE/software intelligence |
| Content | Text and media analysis |
| Intelligence | Evidence correlation |
| Reporting | Unified security reports |

360° means viewing a digital-security problem from multiple intelligence perspectives.

---

# 5. Objectives

1. Build a unified cybersecurity analysis platform.
2. Integrate multiple public/free intelligence sources.
3. Implement useful local security analysis.
4. Normalize heterogeneous findings into one evidence model.
5. Build an explainable correlation engine.
6. Generate transparent risk assessments.
7. Provide AI-grounded security explanations.
8. Generate professional reports.
9. Maintain scan history.
10. Provide a polished live exhibition experience.
11. Remain functional without API keys through local analysis and Demo Mode.

---

# 6. Target Users

Primary:

- school exhibition visitors
- students
- teachers
- judges

Secondary:

- cybersecurity learners
- beginner security researchers
- educators

The interface must be understandable to non-experts while providing technical details for advanced viewers.

---

# 7. Core Modules

## 7.1 PhishGuard — URL & Phishing Analysis

### Input

URL.

### Local analysis

Check where appropriate:

- URL length
- HTTPS usage
- domain structure
- subdomain count
- suspicious characters
- encoded characters
- IP address instead of domain
- suspicious keywords
- login/payment/security keywords
- path depth
- suspicious query parameters
- URL-shortening indicators
- punycode/IDN indicators
- unusual ports
- hostname characteristics
- brand/domain mismatch heuristics

### External intelligence

Potential providers:

- PhishTank
- URLhaus
- urlscan.io
- optional VirusTotal
- other verified free/public providers

### Output

- URL
- domain
- protocol
- local indicators
- external findings
- evidence
- risk
- confidence
- recommendations

Never state that a URL is definitely malicious solely from heuristics.

Use evidence-based language such as:

> Multiple indicators suggest elevated risk.

---

## 7.2 Account Security

### Password analyzer

Analyze locally:

- length
- character diversity
- repeated patterns
- sequential patterns
- common-pattern indicators
- local strength category

### Exposure

Use a privacy-preserving Pwned Passwords approach where applicable.

The actual password must never be transmitted as plaintext.

### Output

- strength category
- exposure status
- recommendations

Never store plaintext passwords.

Never store passwords in scan history.

---

## 7.3 File Forensics

### Input

User-selected file.

### Static processing

Calculate:

- MD5
- SHA-1
- SHA-256
- file size
- extension
- MIME/type

Optional:

- entropy
- metadata
- PE metadata
- archive information

### Intelligence

Potential providers:

- CIRCL Hashlookup
- MalwareBazaar
- optional VirusTotal

### Interpretation

A hash match does not automatically mean a file is malicious.

Distinguish:

- known file
- informational match
- suspicious evidence
- malicious evidence
- no intelligence
- unknown

### Safety

Never execute uploaded files.

Treat all uploaded files as untrusted data.

---

## 7.4 IP & Domain Intelligence

### Input

- IPv4
- IPv6
- domain

### Local processing

Validate syntax and classify indicator type.

### Intelligence

Where available:

- country
- ASN
- organization
- network
- DNS information
- reputation/threat signals
- historical information

Potential provider:

- IPinfo or another verified free-tier provider

### Output

- indicator
- type
- contextual information
- threat signals
- sources
- risk
- recommendations

---

## 7.5 Vulnerability Intelligence

### Input

- CVE identifier
- software/version where supported

### Output

- CVE
- description
- affected software
- affected versions
- severity
- references
- remediation information
- publication/update information

Primary candidate:

- CIRCL Vulnerability-Lookup

Technical terminology should have simple explanations.

Do not provide exploit instructions.

---

## 7.6 AI/Human Text Analyzer

Analyze supplied text for characteristics associated with AI-generated writing.

Possible local features:

- sentence length variation
- vocabulary diversity
- repetition
- punctuation patterns
- structural consistency
- lexical/statistical characteristics

Output:

- low/moderate/high/inconclusive AI-likeness
- supporting characteristics
- limitations

Required limitation:

> AI-text detection is probabilistic and cannot establish authorship with certainty.

Never claim definitive authorship.

---

## 7.7 Media Forensics

Analyze images for:

- file information
- EXIF/metadata
- dimensions
- format
- compression characteristics
- metadata anomalies
- basic forensic indicators

Optional AI-image analysis may be added.

Use language such as:

> Possible AI-generated/manipulated indicators

Never claim definitive proof from probabilistic analysis.

---

## 7.8 Cyber Threat Lab

Educational, safe simulations covering:

- phishing awareness
- password security
- social engineering awareness
- malware/hash concepts
- network-security concepts
- CVE/vulnerability concepts

Do not implement real attacks, exploitation, credential harvesting, or malware execution.

---

# 8. Universal Analyzer

Provide a unified scan interface.

The system should identify inputs such as:

- URL
- domain
- IPv4
- IPv6
- MD5
- SHA-1
- SHA-256
- CVE

and route them to the relevant analyzer.

Example:

```text
Input
 ↓
Type Detection
 ↓
URL
 ↓
PhishGuard
```

---

# 9. Threat Correlation Engine

This is the central differentiator.

The system must not simply display API results.

All results must be normalized into a common evidence model.

### Example evidence object

```json
{
  "indicator": "example.com",
  "indicator_type": "domain",
  "source": "PhishTank",
  "source_type": "phishing_intelligence",
  "finding": "Possible phishing record",
  "severity": "high",
  "confidence": 0.90,
  "evidence": "Matched threat intelligence record",
  "timestamp": "...",
  "reference": "...",
  "status": "detected"
}
```

Required fields should include:

- source
- source_type
- indicator
- indicator_type
- finding
- severity
- confidence
- evidence
- timestamp
- reference
- status

---

# 10. Evidence Normalization

Each provider must convert its native response into the common evidence model.

The application should support:

- deduplication
- normalization
- source weighting
- confidence
- severity
- timestamps
- references

Provider-specific logic must remain isolated in adapters.

---

# 11. Risk Engine

Use a transparent internal 0–100 score.

Suggested categories:

| Score | Level |
|---:|---|
| 0–19 | Minimal |
| 20–39 | Low |
| 40–59 | Moderate |
| 60–79 | High |
| 80–100 | Critical |

The exact implementation may be configurable.

The score is an internal CyberShield X assessment and must not be represented as an official industry rating.

The risk model may combine:

- local indicators
- evidence severity
- source reliability
- number of independent signals
- confidence
- corroboration

Risk and confidence are separate.

Example:

> Risk: HIGH  
> Confidence: MODERATE

---

# 12. Source Reliability

Each provider should have configurable metadata such as:

```json
{
  "source": "ExampleProvider",
  "category": "phishing",
  "default_reliability": 0.90
}
```

This is an internal weighting mechanism, not a claim that the provider is always correct.

---

# 13. AI Security Analyst

AI operates after evidence collection and correlation.

Preferred flow:

```text
Local Analysis
+
Threat Intelligence
+
Evidence
 ↓
Correlation Engine
 ↓
Risk Assessment
 ↓
AI Security Analyst
```

AI receives structured evidence.

It should generate:

- executive summary
- key findings
- explanation
- recommendations
- limitations

### AI guardrails

The AI must never:

- invent API results
- invent evidence
- invent CVEs
- invent sources
- claim certainty where evidence is probabilistic
- override actual provider findings with unsupported claims

Clearly distinguish:

- observed evidence
- assessment/inference
- recommendation
- uncertainty

---

# 14. Unified Security Report

Every completed scan should be capable of producing a structured report.

### Report sections

1. CyberShield X header
2. target
3. indicator type
4. analysis time
5. scan ID
6. overall risk
7. risk score
8. confidence
9. executive summary
10. findings
11. evidence
12. correlation explanation
13. recommendations
14. limitations
15. sources consulted

Export targets:

- PDF
- JSON
- optional CSV

---

# 15. Dashboard

Main dashboard should include:

- CyberShield X branding
- overall security status
- total scans
- high/critical findings
- recent scans
- threat distribution
- intelligence source status
- module navigation
- Universal Scan entry point

---

# 16. Web UI / UX

The frontend is a major product requirement.

It must be a functional, modern, exhibition-ready web interface.

### Visual direction

- dark professional security-console aesthetic
- clean typography
- strong visual hierarchy
- modern cards
- clear risk indicators
- charts where useful
- evidence panels
- expandable technical details
- subtle animations
- polished loading states
- polished error states
- responsive layout

Avoid:

- excessive neon
- fake hacker animations
- skull-heavy graphics
- Matrix-style effects
- clutter
- childish styling

### Recommended pages

```text
/
Dashboard

/analyze
Universal Analyzer

/phishing
PhishGuard

/account
Account Security

/files
File Forensics

/network
IP / Domain Intelligence

/vulnerabilities
Vulnerability Intelligence

/text
AI/Human Text Analyzer

/media
Media Forensics

/lab
Cyber Threat Lab

/history
Scan History

/reports
Reports

/sources
Threat Intelligence Sources

/settings
Settings
```

Use reusable UI components such as:

- AppShell
- Sidebar
- TopBar
- RiskBadge
- RiskScore
- ConfidenceIndicator
- FindingCard
- EvidenceCard
- SourceStatus
- ScanProgress
- ThreatChart
- RecentScans
- LoadingState
- ErrorState
- EmptyState
- ReportPreview
- TechnicalDetails

---

# 17. Scan Progress UX

Do not freeze the interface during analysis.

Show meaningful progress:

```text
✓ Input validated
✓ Local analysis completed
⟳ Querying threat intelligence...
○ Correlating evidence
○ Generating assessment
```

If a provider fails:

> Provider unavailable. Continuing with local analysis and available sources.

---

# 18. Intelligence Providers

The architecture must support independent provider adapters.

Potential providers:

### Core candidates

- HIBP Pwned Passwords
- CIRCL Hashlookup
- CIRCL Vulnerability-Lookup
- PhishTank
- URLhaus
- MalwareBazaar

### Optional

- urlscan.io
- IPinfo
- VirusTotal
- Google Safe Browsing
- other verified providers

Current API credentials are not available during initial development.

Do not make API credentials a prerequisite.

---

# 19. API-Key Architecture

Never hard-code keys.

Use `.env`.

Example:

```env
PHISHTANK_API_KEY=
URLHAUS_API_KEY=
MALWAREBAZAAR_API_KEY=
URLSCAN_API_KEY=
IPINFO_TOKEN=
VIRUSTOTAL_API_KEY=
```

Provide `.env.example`.

If credentials are missing:

- provider status = `NOT_CONFIGURED`
- do not crash
- do not fabricate results
- continue with other analysis

Provider states:

- AVAILABLE
- NOT_CONFIGURED
- UNAVAILABLE
- RATE_LIMITED
- ERROR
- DISABLED

---

# 20. No-Key Development Requirement

The application must work without external API keys.

Implement local functionality first:

### URL

- parsing
- heuristic analysis
- suspicious-pattern detection

### Password

- local strength analysis

### File

- hashing
- metadata/type analysis

### Network

- IP/domain validation

### CVE

- input parsing
- safe local demo dataset

### Text

- statistical analysis

### Image

- metadata analysis

### Platform

- evidence model
- correlation
- risk engine
- reports
- history
- dashboard
- Demo Mode

---

# 21. Demo Mode

Create a first-class Demo Mode.

Demo Mode must use safe prepared demonstration data.

The interface must visibly identify:

> DEMO MODE

and report data as:

> DEMONSTRATION DATA

Demo Mode must allow the exhibition to function even if:

- Internet is unavailable
- an API is down
- API keys are missing
- a provider is rate limited

Never present demo results as live intelligence.

---

# 22. Offline/Graceful Fallback

External failures must not crash the application.

Behavior:

```text
API available
 → use live result

API unavailable
 → local analysis

API rate-limited
 → cached result if available

API key missing
 → NOT_CONFIGURED

API timeout
 → mark provider unavailable
```

The final report must distinguish:

- LIVE RESULT
- CACHED RESULT
- LOCAL ANALYSIS
- DEMO DATA
- NOT CONFIGURED
- PROVIDER ERROR

---

# 23. API Adapter Architecture

Recommended conceptual interface:

```python
class ThreatIntelProvider:

    def check(self, indicator):
        pass

    def normalize(self, response):
        pass

    def health_check(self):
        pass
```

Provider-specific logic must not spread across the application.

---

# 24. Caching and Rate Limiting

Use caching for appropriate non-sensitive intelligence results.

Never cache passwords.

External API requests should use:

- timeouts
- retry limits
- exponential backoff
- provider-specific rate limiting

Do not spam external services.

---

# 25. Database

Use SQLite for MVP.

Suggested tables:

```text
scans
findings
reports
sources
settings
```

Example `scans` fields:

```text
id
created_at
indicator
indicator_type
risk_score
risk_level
confidence
summary
```

Example `findings` fields:

```text
id
scan_id
source
finding
severity
confidence
evidence
reference
```

Do not store plaintext passwords.

---

# 26. Scan History

Store scan results that are safe to retain.

Display:

- date/time
- indicator
- type
- risk
- score
- confidence
- status

Clicking a scan should reopen its report.

Do not store sensitive password content.

---

# 27. Security Requirements

The application itself must follow secure-development principles.

Required:

- input validation
- output sanitization
- API-key protection
- request timeouts
- rate limiting
- safe file handling
- restricted upload size
- file-type validation
- safe error logging
- no secret leakage

Never:

- execute uploaded files
- run arbitrary shell commands against uploads
- store plaintext passwords
- expose API keys
- implement credential harvesting
- implement password cracking
- implement exploitation
- implement unauthorized scanning
- implement attack automation

The application is strictly defensive and educational.

---

# 28. File Upload Security

For uploaded files:

```text
Validate
 ↓
Limit size
 ↓
Identify type
 ↓
Hash
 ↓
Static analysis
 ↓
Threat intelligence
```

Never execute unknown files.

---

# 29. Privacy

Collect only data necessary for analysis.

Clearly distinguish:

> Local Analysis

from:

> External Analysis

When external services are used, inform the user that relevant indicator data may be sent to that provider.

Passwords must receive special privacy protection.

---

# 30. Universal Result Layout

All analyzer results should use a consistent structure:

```text
Target

Risk
Risk Score
Confidence

AI Security Assessment

Key Findings

Evidence

Sources

Recommended Actions

Limitations
```

This creates a unified product experience.

---

# 31. Architecture

Recommended:

```text
                    CYBERSHIELD X
                          │
                          ▼
                    WEB FRONTEND
                          │
                          ▼
                     FASTAPI API
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
        LOCAL ENGINE   API MANAGER   DATABASE
             │            │
             │       PROVIDER ADAPTERS
             │            │
             └──────┬─────┘
                    ▼
             EVIDENCE NORMALIZER
                    │
                    ▼
             CORRELATION ENGINE
                    │
                    ▼
                RISK ENGINE
                    │
                    ▼
             AI SECURITY ANALYST
                    │
                    ▼
               REPORT ENGINE
```

---

# 32. Recommended Project Structure

```text
CyberShieldX/
│
├── README.md
├── PRD.md
├── requirements.txt
├── .env.example
├── .gitignore
│
├── app/
│   ├── main.py
│   ├── api/
│   ├── core/
│   ├── analyzers/
│   ├── intelligence/
│   ├── correlation/
│   ├── ai/
│   ├── reports/
│   ├── database/
│   └── models/
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── demo/
├── tests/
└── docs/
```

The exact structure may be adapted to the chosen stack.

---

# 33. Development Priority

Build in this order:

## Phase 1 — Foundation

- backend
- frontend shell
- database
- configuration
- common models
- dashboard
- navigation
- Demo Mode

## Phase 2 — First Vertical Slice

Build PhishGuard end-to-end:

```text
URL
 ↓
Local Analysis
 ↓
Threat Intelligence
 ↓
Evidence
 ↓
Correlation
 ↓
Risk
 ↓
Explanation
 ↓
Report
```

This is the first major success milestone.

## Phase 3 — Intelligence

Add:

- password exposure
- hash intelligence
- MalwareBazaar
- CVE intelligence
- IP/domain intelligence
- optional providers

## Phase 4 — AI

Implement the AI Security Analyst after the evidence/correlation system works.

## Phase 5 — Remaining modules

- Text Analyzer
- Media Forensics
- Threat Lab
- Scan History
- Reports

## Phase 6 — Exhibition polish

- charts
- animations
- error states
- loading states
- demo dataset
- offline fallback
- documentation
- final testing

---

# 34. Five-Day MVP

If development time is limited:

### Day 1
Foundation + dashboard + frontend/backend architecture.

### Day 2
PhishGuard + local URL analysis + first threat-intelligence integrations.

### Day 3
Hash/File + Password + CVE modules.

### Day 4
Correlation Engine + AI Security Analyst + reports.

### Day 5
UI polish + Demo Mode + testing + exhibition preparation.

The first complete vertical slice is more important than having many unfinished modules.

---

# 35. Testing

Test:

- normal input
- invalid input
- empty input
- large input
- malformed provider response
- API timeout
- rate limit
- missing API key
- provider failure
- database failure where practical

Unit tests should cover:

- URL analyzer
- hashing
- password analyzer
- IP validation
- evidence normalization
- risk engine
- provider adapters

---

# 36. Performance

Local analysis should be fast where practical.

External operations should display progress.

Use asynchronous operations where appropriate.

Never leave the interface apparently frozen.

---

# 37. Documentation

Maintain:

```text
README.md
ARCHITECTURE.md
API_INTEGRATIONS.md
SECURITY.md
DEMO_GUIDE.md
```

Documentation must match actual implementation.

Include Windows setup instructions.

---

# 38. Exhibition Demonstration

Target demonstration time:

**2–4 minutes**

Suggested sequence:

1. Open dashboard.
2. Explain CyberShield X as a 360° cybersecurity intelligence platform.
3. Open Universal Scan/PhishGuard.
4. Enter a prepared safe demonstration indicator.
5. Show local analysis.
6. Show intelligence-source results/status.
7. Show evidence correlation.
8. Show risk score and confidence.
9. Show AI Security Analyst explanation.
10. Generate security report.
11. Briefly show another module.

The main story is:

> **DETECT → CORRELATE → EXPLAIN → REPORT**

---

# 39. Judge-Facing Differentiator

The project must emphasize:

> The innovation is not simply connecting APIs. CyberShield X normalizes heterogeneous security signals, correlates independent evidence, produces an explainable internal risk assessment, and uses AI to communicate that assessment.

The AI is an intelligence/explanation layer, not merely a chatbot.

---

# 40. Limitations

The application must clearly communicate:

- It is not an antivirus.
- It is not a replacement for professional security products.
- Threat-intelligence databases may be incomplete.
- No intelligence result does not prove safety.
- AI-generated-content detection is probabilistic.
- Risk scores are internal assessments.
- External services may have rate limits, outages, or changing terms.
- API availability can change.

---

# 41. Success Criteria

The project is successful when:

### Functionality

- at least four core workflows operate end-to-end
- local analysis works
- optional intelligence providers work when configured
- reports can be generated
- history works

### Intelligence

- multiple evidence sources can be correlated
- evidence is normalized
- risk is explainable

### AI

- AI receives structured evidence
- AI does not invent findings
- AI communicates uncertainty

### UX

- a judge can understand the purpose quickly
- a scan can be demonstrated in several minutes
- results are visually understandable
- the UI looks like a coherent product

### Reliability

- missing API keys do not crash the app
- API failure does not crash the app
- Demo Mode works without Internet
- unknown files are never executed

---

# 42. Final Product Definition

CyberShield X is:

> **An AI-powered 360° cybersecurity intelligence platform that combines local security analysis, public threat intelligence, evidence correlation and explainable AI to help users understand digital threats.**

Core product philosophy:

# DETECT → CORRELATE → EXPLAIN → REPORT

Central engineering concept:

# MULTI-SOURCE THREAT CORRELATION

Central AI concept:

# EVIDENCE-GROUNDED SECURITY EXPLANATION

Central exhibition concept:

# 360° DIGITAL SECURITY INTELLIGENCE

---

# 43. Master Development Principle

Do not add features merely because they sound impressive.

Every feature must contribute to the common security-intelligence architecture.

Prioritize:

1. Reliability
2. Security
3. Evidence correctness
4. Explainability
5. Clean architecture
6. Exhibition UX
7. Feature breadth

A smaller, reliable system is better than a large collection of unfinished features.

---

# 44. Acceptance Definition

The final application should allow a user to:

```text
Enter an indicator
      ↓
Identify its type
      ↓
Perform local analysis
      ↓
Query configured intelligence sources
      ↓
Normalize findings
      ↓
Correlate evidence
      ↓
Calculate risk
      ↓
Generate an evidence-grounded explanation
      ↓
View recommendations
      ↓
Generate a report
      ↓
Save/review the scan
```

The complete system must remain usable when external APIs are unavailable through local analysis and clearly labelled Demo Mode.
