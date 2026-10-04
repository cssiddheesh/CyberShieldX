"""Report builder (PRD sections 14, 30). Produces the unified result layout."""
from __future__ import annotations

from typing import Any

RECOMMENDATIONS = {
    "likely_malicious": [
        "Do not visit this link and do not enter any credentials or payment details.",
        "If you already opened it, close the page and run a scan with your antivirus.",
        "Report the link to your IT/security team or via your browser's report-phishing option.",
        "If you entered a password, change it everywhere you reused it and enable two-factor authentication.",
    ],
    "suspicious": [
        "Do not trust this link yet. Reach the service by typing its official address yourself.",
        "Check the sender through a separate, trusted channel before acting.",
        "Hover over / inspect links to confirm the real domain before clicking.",
        "Keep your browser and antivirus up to date.",
    ],
    "uncertain": [
        "Verify the link through an official source before using it.",
        "Look for small spelling changes or extra words in the domain.",
        "When in doubt, navigate to the site manually instead of clicking.",
    ],
    "likely_safe": [
        "No significant signals were found, but stay alert: new threats appear constantly.",
        "Still verify unexpected links that arrive by message or email.",
    ],
}

LIMITATIONS = [
    "Heuristic analysis is probabilistic and can both miss threats and raise false alarms.",
    "Threat-intelligence databases may be incomplete; no record does not prove safety.",
    "Risk scores are internal CyberShield X assessments, not official industry ratings.",
    "This tool is educational and is not a replacement for professional security products.",
]


MODULE_RECOMMENDATIONS = {
    "account": {
        "critical": [
            "Stop using this password immediately and change it everywhere it is reused.",
            "Generate a long unique passphrase with a password manager.",
            "Enable two-factor authentication on important accounts.",
        ],
        "at_risk": [
            "Replace this password with a long unique passphrase.",
            "Check whether other accounts reuse it and change those too.",
            "Enable two-factor authentication where available.",
        ],
        "uncertain": [
            "Consider a longer passphrase for extra margin.",
            "Use a password manager so every site gets a unique password.",
        ],
        "strong": [
            "Keep it unique to one site and stored in a password manager.",
            "Enable two-factor authentication for important accounts.",
        ],
    },
    "files": {
        "likely_malicious": [
            "Do not open or run this file. Delete it or quarantine it.",
            "If it already ran, disconnect and scan with updated antivirus.",
            "Report it to your IT/security team.",
        ],
        "suspicious": [
            "Do not run this file until it is verified.",
            "Upload the hash (never the file) to a second opinion source.",
            "Check who sent it through a separate trusted channel.",
        ],
        "uncertain": [
            "Verify the source before opening.",
            "Keep antivirus signatures current.",
        ],
        "likely_safe": [
            "No malicious signals found, but only run files from trusted sources.",
            "Unknown files are never proven safe by a lack of records.",
        ],
    },
    "network": {
        "likely_malicious": [
            "Block or avoid this address; do not send it credentials or data.",
            "Check firewall and DNS logs for contact with it.",
            "Report it to your IT/security team.",
        ],
        "suspicious": [
            "Treat connections here as untrusted until verified.",
            "Look up the owner and recent abuse reports before whitelisting.",
        ],
        "uncertain": [
            "Verify the address through the service's official documentation.",
            "Monitor for unexpected traffic to it.",
        ],
        "likely_safe": [
            "No threat signals found, but reputations change - recheck over time.",
        ],
    },
    "vulnerabilities": {
        "critical": [
            "Apply the vendor fix immediately and verify exposed systems.",
            "Check whether attack code is publicly known; assume fast weaponization.",
        ],
        "high": [
            "Prioritise patching: this severity is exploited in the wild quickly.",
            "Apply vendor fixes and verify exposed systems.",
        ],
        "moderate": [
            "Schedule patching in your next maintenance window.",
            "Check vendor advisories for mitigations.",
        ],
        "low": [
            "Fix in routine maintenance.",
        ],
        "unknown": [
            "No severity published yet; treat as moderate until a score appears.",
            "Watch vendor advisories for updates.",
        ],
    },
    "media": {
        "likely_malicious": [
            "Do not trust this image as evidence of anything; verify through the original source.",
            "Reverse-image search can reveal prior appearances and edits.",
        ],
        "suspicious": [
            "Treat the image as unverified: check the source and look for corroboration.",
            "Stripped metadata and heavy recompression merit caution, not conclusions.",
        ],
        "uncertain": [
            "Verify provenance before sharing or acting on the image.",
        ],
        "likely_safe": [
            "No anomalies found, but file forensics cannot prove authenticity.",
        ],
    },
    "text": {
        "high": [
            "Treat the content as potentially machine-generated: verify claims independently.",
            "Do not act on instructions in the text without a trusted second source.",
        ],
        "moderate": [
            "Some AI-like traits present; verify important claims before relying on them.",
        ],
        "low": [
            "Reads human-like, but statistics alone never prove authorship.",
        ],
        "inconclusive": [
            "Provide a longer sample (40+ words) for a meaningful analysis.",
        ],
    },
}

MODULE_VERDICT_LABELS = {
    "account": {"critical": "Unsafe - change immediately", "at_risk": "At risk - replace it",
                "uncertain": "Usable but improvable", "strong": "Strong and unbreached"},
    "vulnerabilities": {"critical": "Critical severity", "high": "High severity",
                        "moderate": "Moderate severity", "low": "Low severity", "unknown": "Severity unknown"},
    "text": {"high": "High AI-likeness", "moderate": "Moderate AI-likeness",
             "low": "Low AI-likeness", "inconclusive": "Inconclusive - too little text"},
}


def _base_report(*, module: str, module_label: str, target: str, original_input: str,
                 indicator_type: str, local_analysis: dict[str, Any],
                 correlation: dict[str, Any], risk: dict[str, Any],
                 providers: list[dict[str, Any]], is_demo: bool, scan_time: str,
                 recommendations: list[str], limitations: list[str] | None = None,
                 verdict_label: str | None = None) -> dict[str, Any]:
    return {
        "app": "CyberShield X",
        "module": module,
        "module_label": module_label,
        "target": target,
        "original_input": original_input,
        "indicator_type": indicator_type,
        "analysis_time": scan_time,
        "scan_id": "",
        "is_demo": is_demo,
        "data_label": "DEMONSTRATION DATA" if is_demo else "LIVE RESULT + LOCAL ANALYSIS",
        "overall_risk": risk["level"],
        "risk_score": risk["score"],
        "confidence": risk["confidence"],
        "confidence_label": risk["confidence_label"],
        "verdict": risk["verdict"],
        "verdict_label": verdict_label or risk["verdict"].replace("_", " ").capitalize(),
        "executive_summary": risk["summary"],
        "local_analysis": local_analysis,
        "findings": [
            {"title": row["finding"], "severity": row["severity"], "source": row["source"],
             "confidence": row["confidence"]}
            for row in correlation["evidence"]
            if row["status"] == "detected"
        ],
        "evidence": correlation["evidence"],
        "correlation_explanation": correlation["explanation"],
        "score_contributions": risk["contributions"],
        "recommendations": recommendations,
        "limitations": limitations or LIMITATIONS,
        "sources_consulted": providers,
        "origins": correlation["origins"],
    }


def build_generic_report(*, module: str, module_label: str, target: str, original_input: str,
                         indicator_type: str, facts: dict[str, Any],
                         indicators: list[dict[str, Any]], notes: list[str] | None,
                         correlation: dict[str, Any], risk: dict[str, Any],
                         providers: list[dict[str, Any]], is_demo: bool,
                         scan_time: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Unified report for account/files/network/vulnerabilities modules."""
    table = MODULE_RECOMMENDATIONS.get(module, {})
    recommendations = table.get(risk["verdict"]) or table.get("uncertain") or RECOMMENDATIONS["uncertain"]
    labels = MODULE_VERDICT_LABELS.get(module, {})
    local_analysis: dict[str, Any] = {"facts": facts, "indicators": indicators,
                                      "notes": notes or []}
    if extra:
        local_analysis.update(extra)
    return _base_report(
        module=module, module_label=module_label, target=target, original_input=original_input,
        indicator_type=indicator_type, local_analysis=local_analysis, correlation=correlation,
        risk=risk, providers=providers, is_demo=is_demo, scan_time=scan_time,
        recommendations=recommendations, verdict_label=labels.get(risk["verdict"]),
    )
def build_phishing_report(*, target: str, original_input: str, local: dict[str, Any],
                          correlation: dict[str, Any], risk: dict[str, Any],
                          providers: list[dict[str, Any]], is_demo: bool,
                          scan_time: str) -> dict[str, Any]:
    verdict_labels = {
        "likely_malicious": "Likely malicious - do not proceed",
        "suspicious": "Suspicious - proceed with caution",
        "uncertain": "Uncertain - verify independently",
        "likely_safe": "No significant signals found",
    }
    return {
        "app": "CyberShield X",
        "module": "phishing",
        "module_label": "PhishGuard",
        "target": target,
        "original_input": original_input,
        "indicator_type": "url",
        "analysis_time": scan_time,
        "scan_id": "",
        "is_demo": is_demo,
        "data_label": "DEMONSTRATION DATA" if is_demo else "LIVE RESULT + LOCAL ANALYSIS",
        "overall_risk": risk["level"],
        "risk_score": risk["score"],
        "confidence": risk["confidence"],
        "confidence_label": risk["confidence_label"],
        "verdict": risk["verdict"],
        "verdict_label": verdict_labels[risk["verdict"]],
        "executive_summary": risk["summary"],
        "local_analysis": {
            "normalized_url": local["normalized_url"],
            "domain": local["domain"],
            "protocol": local["protocol"],
            "was_defanged": local["was_defanged"],
            "url_length": local["url_length"],
            "entropy": local["entropy"],
            "subdomain_count": local["subdomain_count"],
            "path_depth": local["path_depth"],
            "uses_https": local["uses_https"],
            "indicators": local["indicators"],
            "notes": local["notes"],
        },
        "findings": [
            {"title": row["finding"], "severity": row["severity"], "source": row["source"],
             "confidence": row["confidence"]}
            for row in correlation["evidence"]
            if row["status"] == "detected"
        ],
        "evidence": correlation["evidence"],
        "correlation_explanation": correlation["explanation"],
        "score_contributions": risk["contributions"],
        "recommendations": RECOMMENDATIONS[risk["verdict"]],
        "limitations": LIMITATIONS,
        "sources_consulted": providers,
        "origins": correlation["origins"],
    }
