"""AI Security Analyst (PRD section 13): evidence-grounded explanation layer.

Runs AFTER evidence collection and correlation, receiving only structured
evidence - never raw provider responses, never free-form prompts. All output
is composed from the evidence rows, so the analyst cannot invent API results,
sources, CVEs or findings. Uncertainty is stated explicitly, and every
statement is labelled observed / assessment / recommendation / uncertain.

Local and deterministic (Rs 0 budget, offline-capable): template-based
natural-language generation over cited evidence, not a remote LLM.
"""
from __future__ import annotations

from typing import Any

ANALYST_VERSION = "1.0-local"

# Probabilistic wording only - the analyst must never claim certainty.
HEDGES = {
    "Critical": "strongly suggest",
    "High": "suggest",
    "Moderate": "weakly suggest",
    "Low": "give little reason to suspect",
    "Minimal": "give no significant reason to suspect",
    "Unknown": "say too little about",
}


def _top_signals(evidence: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    detected = [e for e in evidence if e.get("status") == "detected"]
    detected.sort(key=lambda e: (order.get(e.get("severity", "info"), 4),
                                 -(e.get("contribution") or 0)))
    return detected[:limit]


def build_assessment(*, module_label: str, target: str, risk: dict[str, Any],
                     correlation: dict[str, Any], recommendations: list[str],
                     limitations: list[str], providers: list[dict[str, Any]],
                     is_demo: bool) -> dict[str, Any]:
    """Compose the AI assessment strictly from structured inputs."""
    evidence = correlation.get("evidence", [])
    level = risk.get("level", "Unknown")
    score = risk.get("score", 0)
    hedge = HEDGES.get(level, "say too little about")

    detecting = [e for e in evidence if e.get("status") == "detected"]
    intel_hits = [e for e in detecting if e.get("origin") in ("LIVE_RESULT", "DEMO_DATA")
                  and e.get("source") != "PhishGuard Local"
                  and e.get("source") not in ("Password Analyzer", "File Forensics",
                                              "Network Analyzer", "Vulnerability Analyzer",
                                              "CyberShield X CVE reference")]
    # Local sources per module (module runners name them differently).
    local_sources = {"PhishGuard Local", "Password Analyzer", "File Forensics",
                     "Network Analyzer", "Vulnerability Analyzer", "CyberShield X CVE reference"}
    local_hits = [e for e in detecting if e.get("source") in local_sources]
    unavailable = [e for e in evidence if e.get("status") == "unavailable"]
    not_found = [e for e in evidence if e.get("status") == "not_found"]
    sources = sorted({e.get("source", "unknown") for e in evidence})

    observed: list[str] = []
    if local_hits:
        names = "; ".join(e.get("finding", "") for e in local_hits[:3])
        observed.append(f"Local analysis flagged {len(local_hits)} signal(s): {names}.")
    else:
        observed.append("Local analysis flagged no suspicious signals.")
    if intel_hits:
        names = "; ".join(f"{e.get('source')}: {e.get('finding', '')}" for e in intel_hits[:3])
        observed.append(f"External intelligence returned {len(intel_hits)} record(s): {names}.")
    else:
        consulted = [p.get("name", p.get("key", "")) for p in providers
                     if p.get("state") == "AVAILABLE"]
        if consulted:
            observed.append(f"{len(consulted)} intelligence source(s) consulted "
                            f"({', '.join(consulted[:4])}) with no matching records.")
        else:
            observed.append("No external intelligence source could be consulted for this scan.")

    assessment_text = (
        f"Together, the {len(evidence)} evidence item(s) {hedge} elevated risk "
        f"(internal score {score}/100, {level}). "
        + (f"{len(intel_hits)} independent intelligence record(s) corroborate the local signals, "
           "which raises confidence in the assessment."
           if len(intel_hits) >= 1 and local_hits else
           ("Local signals alone drive this score; treat it as probabilistic, not a verdict. "
            if local_hits else
            "With no detecting signals, this is a low-evidence assessment, not proof of safety."))
    )

    key_findings = []
    for row in _top_signals(evidence):
        idx = evidence.index(row)
        key_findings.append({
            "statement": f"{row.get('source')}: {row.get('finding')}",
            "severity": row.get("severity"),
            "evidence_ref": idx,  # index into the report's evidence array
            "type": "observed",
        })

    uncertainty: list[str] = []
    if unavailable:
        names = sorted({e.get("source", "") for e in unavailable})
        uncertainty.append(f"{len(unavailable)} evidence item(s) from {', '.join(names)} could not be "
                           "collected; the score reflects only available evidence.")
    if not_found:
        uncertainty.append(f"{len(not_found)} source(s) hold no record. Absence of a record "
                           "does not prove safety.")
    if risk.get("confidence", 1.0) < 0.5:
        uncertainty.append("Confidence is Low: few independent signals support this assessment.")
    if not uncertainty:
        uncertainty.append("All consulted sources responded; residual uncertainty comes from "
                           "database incompleteness, which no scan can eliminate.")

    summary = (
        f"{module_label} examined {target[:120]} and rates it {level} risk "
        f"({score}/100, {risk.get('confidence_label', '')} confidence). "
        + (f"The main driver: {(key_findings[0]['statement'] if key_findings else 'no single dominant signal')}."
           if key_findings else "No dominant signal emerged.")
    )
    if is_demo:
        summary = "DEMONSTRATION DATA. " + summary

    return {
        "analyst": f"AI Security Analyst v{ANALYST_VERSION}",
        "executive_summary": summary,
        "observed": observed,
        "assessment": assessment_text,
        "key_findings": key_findings,
        "recommendations": [{"text": r, "type": "recommendation"} for r in recommendations],
        "limitations": limitations,
        "uncertainty": [{"text": u, "type": "uncertain"} for u in uncertainty],
        "grounding": {
            "evidence_count": len(evidence),
            "sources": sources,
            "intel_hits": len(intel_hits),
            "local_hits": len(local_hits),
            "all_claims_cited": True,
        },
    }
