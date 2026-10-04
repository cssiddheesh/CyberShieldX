"""Risk engine (PRD section 11): transparent 0-100 internal assessment.

The score combines local-indicator weights, evidence severity, source
reliability, the number of independent signals and corroboration. Every
contribution is listed so the UI can explain the score line by line.

Risk and confidence are separate: risk = how bad it looks, confidence = how
sure we are given the amount and agreement of evidence.
"""
from __future__ import annotations

from typing import Any

from app.models.evidence import confidence_label, risk_level_for

# Verdict wording: heuristics alone must never claim certainty (PRD 7.1).
VERDICTS = ("likely_safe", "uncertain", "suspicious", "likely_malicious")


def _verdict_for(score: int, has_intel_hit: bool) -> str:
    if score >= 80 and has_intel_hit:
        return "likely_malicious"
    if score >= 80:
        return "suspicious"  # heuristics alone: never state certainty
    if score >= 60:
        return "suspicious"
    if score >= 40:
        return "uncertain"
    return "likely_safe"


def assess_risk(local_weights: list[dict[str, Any]],
                correlation: dict[str, Any],
                provider_hits: int = 0,
                subject: str = "link") -> dict[str, Any]:
    contributions: list[dict[str, Any]] = []

    local_total = 0
    for item in local_weights:
        points = max(0, min(40, int(item.get("weight", 0))))
        if points <= 0:
            continue
        local_total += points
        contributions.append({
            "source": "PhishGuard Local",
            "detail": f"Local indicator '{item.get('id', 'signal')}' adds {points} points.",
            "points": points,
        })
    # Diminishing returns: many weak signals should not auto-max the score.
    if local_total > 60:
        capped = 60 + int((local_total - 60) * 0.5)
        contributions.append({
            "source": "Risk Engine",
            "detail": (f"Local signals summed to {local_total}; capped to {capped} because many weak "
                       "signals together are less conclusive than independent confirmations."),
            "points": capped - local_total,
        })
        local_total = capped

    intel_total = 0
    for row in correlation.get("evidence", []):
        if row.get("source") == "PhishGuard Local":
            continue
        if row.get("status") != "detected":
            continue
        points = max(0, min(40, int(round(row.get("contribution", 0)))))
        if points <= 0:
            continue
        intel_total += points
        contributions.append({
            "source": row.get("source", "provider"),
            "detail": (f"{row.get('source')}: {row.get('finding')} "
                       f"(severity {row.get('severity')}, confidence {row.get('confidence')}) adds {points} points."),
            "points": points,
        })
    if intel_total > 50:
        capped = 50 + int((intel_total - 50) * 0.5)
        contributions.append({
            "source": "Risk Engine",
            "detail": f"Provider signals summed to {intel_total}; capped to {capped} to reward agreement, not volume.",
            "points": capped - intel_total,
        })
        intel_total = capped

    bonus = int(correlation.get("corroboration_bonus", 0))
    if bonus:
        contributions.append({
            "source": "Correlation Engine",
            "detail": f"Independent sources agree: +{bonus} points. {correlation.get('corroboration_reason', '')}",
            "points": bonus,
        })

    base = 5  # a scanned indicator always carries minimal residual uncertainty
    score = max(0, min(100, base + local_total + intel_total + bonus))
    contributions.insert(0, {"source": "Risk Engine",
                             "detail": "Every scan starts at 5 points: no scan can prove absolute safety.",
                             "points": 5})
    level = risk_level_for(score)

    # Confidence grows with independent signals and agreement, shrinks with gaps.
    n_sources = len({r.get("source") for r in correlation.get("evidence", [])})
    n_detecting = correlation.get("detecting", 0)
    unavailable = correlation.get("unavailable", 0)
    confidence = 0.35 + 0.1 * min(n_sources, 4) + 0.08 * min(n_detecting, 3)
    if provider_hits > 0:
        confidence += 0.1
    confidence -= 0.08 * min(unavailable, 3)
    confidence = round(max(0.05, min(0.95, confidence)), 3)

    verdict = _verdict_for(score, provider_hits > 0)

    if verdict == "likely_malicious":
        summary = ("Multiple indicators suggest elevated risk, and at least one threat-intelligence "
                   f"source holds a matching record for this {subject}.")
    elif verdict == "suspicious":
        summary = (f"Multiple indicators suggest elevated risk. Treat this {subject} with suspicion, "
                   "but note this assessment is probabilistic, not a definitive verdict.")
    elif verdict == "uncertain":
        summary = ("Some weak signals were found, but the evidence is inconclusive. "
                   f"Verify through a trusted channel before trusting this {subject}.")
    else:
        summary = ("No significant risk signals were found. This does not prove safety - "
                   "threat-intelligence databases may be incomplete.")

    return {
        "score": score,
        "level": level,
        "confidence": confidence,
        "confidence_label": confidence_label(confidence),
        "verdict": verdict,
        "summary": summary,
        "contributions": contributions,
        "signals": {"local_points": local_total, "intel_points": intel_total,
                    "corroboration": bonus, "sources": n_sources,
                    "detecting": n_detecting, "provider_hits": provider_hits},
    }
