"""Threat correlation engine (PRD sections 9-10).

Merges local-analysis Evidence with provider Evidence into one deduplicated,
source-weighted view. Providers stay isolated in adapters; this module only
sees Evidence objects.
"""
from __future__ import annotations

from typing import Any

from app.models.evidence import Evidence, Severity

_SEVERITY_SCORE = {"info": 0, "low": 15, "medium": 35, "high": 65, "critical": 90}


def severity_score(severity: str | Severity) -> int:
    value = severity.value if isinstance(severity, Severity) else str(severity).lower()
    return _SEVERITY_SCORE.get(value, 0)


def deduplicate(evidence: list[Evidence]) -> tuple[list[Evidence], int]:
    """Drop exact duplicates (same source + indicator + finding)."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[Evidence] = []
    removed = 0
    for item in evidence:
        key = item.dedupe_key()
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        unique.append(item)
    return unique, removed


def corroboration_bonus(evidence: list[Evidence]) -> tuple[int, str]:
    """Extra weight when independent sources agree something was found."""
    detecting_sources = {e.source.lower() for e in evidence if e.status.value == "detected"
                         and e.severity.value in ("medium", "high", "critical")}
    count = len(detecting_sources)
    if count >= 3:
        return 15, f"{count} independent sources report suspicious signals."
    if count == 2:
        return 8, "Two independent sources report suspicious signals."
    return 0, ""


def correlate(evidence: list[Evidence], reliability: dict[str, float] | None = None) -> dict[str, Any]:
    """Normalize + deduplicate + weigh evidence. Returns a JSON-serializable summary."""
    reliability = reliability or {}
    unique, duplicates_removed = deduplicate(list(evidence))

    weighted: list[dict[str, Any]] = []
    for item in unique:
        weight = reliability.get(item.source, reliability.get(item.source.lower(), 0.7))
        contribution = round(severity_score(item.severity) * item.confidence * weight, 2)
        row = item.to_dict()
        row["source_weight"] = round(weight, 3)
        row["contribution"] = contribution
        weighted.append(row)

    weighted.sort(key=lambda r: (-r["contribution"],
                                 {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[r["severity"]]))

    bonus, bonus_reason = corroboration_bonus(unique)
    detecting = sum(1 for e in unique if e.status.value == "detected")
    not_found = sum(1 for e in unique if e.status.value == "not_found")
    unavailable = sum(1 for e in unique if e.status.value == "unavailable")

    origins = sorted({e.origin.value for e in unique})
    severities = [e.severity.value for e in unique]
    highest = "info"
    for level in ("critical", "high", "medium", "low", "info"):
        if level in severities:
            highest = level
            break

    return {
        "total": len(unique),
        "duplicates_removed": duplicates_removed,
        "detecting": detecting,
        "not_found": not_found,
        "unavailable": unavailable,
        "highest_severity": highest,
        "origins": origins,
        "corroboration_bonus": bonus,
        "corroboration_reason": bonus_reason,
        "evidence": weighted,
        "explanation": _explain(unique, bonus, bonus_reason, duplicates_removed),
    }


def _explain(unique: list[Evidence], bonus: int, bonus_reason: str, duplicates_removed: int) -> str:
    if not unique:
        return "No evidence was collected, so no assessment is possible."
    parts = [f"{len(unique)} evidence item(s) were combined after removing {duplicates_removed} duplicate(s)."]
    by_source: dict[str, int] = {}
    for item in unique:
        by_source[item.source] = by_source.get(item.source, 0) + 1
    parts.append("Sources: " + ", ".join(f"{name} ({n})" for name, n in sorted(by_source.items())) + ".")
    if bonus:
        parts.append(bonus_reason + " Independent agreement raises confidence in the assessment.")
    if any(e.status.value == "not_found" for e in unique):
        parts.append("Some sources hold no record for this indicator; absence of a record does not prove safety.")
    if any(e.status.value == "unavailable" for e in unique):
        parts.append("Some sources could not be consulted; the score reflects only available evidence.")
    return " ".join(parts)


GAP_STATES = frozenset({"ERROR", "UNAVAILABLE", "RATE_LIMITED"})


def note_provider_gaps(correlation: dict[str, Any], providers: list[dict[str, Any]]) -> dict[str, Any]:
    """Name consulted-but-failed providers in the explanation.

    Failed providers leave no evidence rows, so without this the explanation
    would stay silent about the outage. Returns the same dict for chaining.
    """
    gaps = sorted({str(p.get("name") or p.get("key", "")) for p in providers
                   if p.get("state") in GAP_STATES})
    if gaps:
        correlation["explanation"] += (" Some sources could not be consulted "
                                       f"({', '.join(gaps)}); the score reflects only available evidence.")
    return correlation
