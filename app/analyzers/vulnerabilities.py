"""Vulnerability Intelligence: CVE parsing + local reference data (PRD section 7.5).

Pure functions - no network (live records come from the CIRCL adapter).
Includes a tiny, clearly-labelled local reference set for famous CVEs so the
module stays educational offline. Never provide exploit instructions.
"""
from __future__ import annotations

import re
from typing import Any

from app.models.evidence import Evidence, IndicatorType, ResultOrigin

SOURCE = "Vulnerability Analyzer"
SOURCE_TYPE = "local_vulnerability_analysis"

_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,19})$", re.IGNORECASE)

# Stable, well-established facts about landmark vulnerabilities, used only when
# live intelligence is unavailable. Labelled LOCAL_REFERENCE in evidence.
LOCAL_REFERENCE: dict[str, dict[str, Any]] = {
    "CVE-2021-44228": {
        "title": "Log4Shell (Apache Log4j remote code execution)",
        "severity": "critical", "cvss": 10.0,
        "summary": ("A flaw in the widely used Log4j Java logging library lets a remote attacker "
                    "run their own code by getting a crafted text string logged. It affected a huge "
                    "number of servers and cloud services in December 2021."),
        "affected": "Apache Log4j 2.x versions 2.0 to 2.14.1 (Java applications embedding it).",
        "remediation": "Upgrade Log4j to 2.17.1 or later (or apply vendor patches) and review logs for compromise.",
    },
    "CVE-2017-0144": {
        "title": "EternalBlue (Windows SMB remote code execution)",
        "severity": "critical", "cvss": 8.1,
        "summary": ("A flaw in Windows file sharing (SMBv1) lets attackers run code on unpatched machines "
                    "without any login. It powered the WannaCry ransomware outbreak of May 2017."),
        "affected": "Windows Vista through Server 2016 without MS17-010.",
        "remediation": "Install Microsoft security update MS17-010 and disable SMBv1.",
    },
    "CVE-2014-0160": {
        "title": "Heartbleed (OpenSSL memory disclosure)",
        "severity": "high", "cvss": 7.5,
        "summary": ("A bug in OpenSSL's heartbeat feature lets attackers read chunks of server memory, "
                    "potentially exposing private keys, passwords and session cookies."),
        "affected": "OpenSSL 1.0.1 through 1.0.1f.",
        "remediation": "Upgrade to OpenSSL 1.0.1g or later, replace certificates and rotate secrets.",
    },
}

PLAIN_LANGUAGE = {
    "critical": "Fix urgently: attackers can likely take over or deeply compromise affected systems.",
    "high": "Fix soon: serious real-world impact, often with working attack methods.",
    "medium": "Plan a fix: meaningful risk, usually needing specific conditions to exploit.",
    "low": "Fix in routine maintenance: limited impact on its own.",
}


def parse_cve(value: str) -> dict[str, Any]:
    """Validate and split a CVE identifier. Never raises."""
    text = (value or "").strip().upper()
    match = _CVE_RE.match(text)
    if not match:
        return {"valid": False, "normalized": text, "year": None, "number": None}
    return {"valid": True, "normalized": text, "year": int(match.group(1)), "number": match.group(2)}


def analyze_cve(cve_id: str) -> dict[str, Any]:
    """Local CVE analysis: validation + reference lookup. JSON-serializable."""
    parsed = parse_cve(cve_id)
    indicator = parsed["normalized"]
    reference = LOCAL_REFERENCE.get(indicator)
    indicators: list[dict[str, Any]] = []

    if not parsed["valid"]:
        indicators.append({"id": "invalid_cve", "title": "Not a valid CVE identifier",
                           "detail": "Expected format like CVE-2021-44228.", "severity": "info",
                           "weight": 0, "confidence": 0.9})
    elif reference:
        indicators.append({"id": "known_reference", "title": f"Known vulnerability: {reference['title']}",
                           "detail": reference["summary"], "severity": reference["severity"],
                           "weight": 0, "confidence": 0.9})

    evidence = []
    for item in indicators:
        origin = ResultOrigin.LOCAL
        source, stype = SOURCE, SOURCE_TYPE
        evidence.append(Evidence(
            indicator, IndicatorType.CVE, source, stype,
            item["title"], item["severity"], item["confidence"], item["detail"],  # type: ignore[arg-type]
            "", "informational", origin))
    if reference:
        evidence.append(Evidence(
            indicator, IndicatorType.CVE, "CyberShield X CVE reference", "local_reference",
            f"{indicator}: {reference['title']}", reference["severity"], 0.85,  # type: ignore[arg-type]
            f"LOCAL REFERENCE (offline): {reference['summary']} Affected: {reference['affected']} "
            f"Fix: {reference['remediation']}",
            "https://cve.mitre.org", "informational", ResultOrigin.LOCAL))
    if not evidence:
        evidence.append(Evidence(
            indicator, IndicatorType.CVE, SOURCE, SOURCE_TYPE,
            "Identifier format is valid", "info", 0.7,
            "The CVE ID parses correctly. Live vulnerability records come from CIRCL Vulnerability-Lookup.",
            "", "informational", ResultOrigin.LOCAL))

    return {
        "cve": indicator, "parsed": parsed, "reference": reference,
        "plain_language": PLAIN_LANGUAGE.get((reference or {}).get("severity", ""), ""),
        "indicators": indicators,
        "evidence": [e.to_dict() for e in evidence],
        "local_weights": [],
    }


def risk_for_cvss(score: float | None) -> tuple[int, str]:
    """Map a CVSS base score to (0-100 risk, level). None = unknown."""
    if score is None:
        return 30, "Low"
    points = max(0, min(100, int(round(score * 10))))
    level = ("Critical" if score >= 9.0 else "High" if score >= 7.0 else
             "Moderate" if score >= 4.0 else "Low" if score > 0 else "Minimal")
    return points, level
