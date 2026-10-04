"""PhishGuard scan pipeline: Detect -> Correlate -> Explain -> Report.

Framework-agnostic (no Flask). The API layer calls ``run_phishing_scan``
and persists the returned ScanRecord + report.
"""
from __future__ import annotations

from typing import Any

from app.analyzers.phishing import analyze_url
from app.ai.analyst import build_assessment
from app.correlation.engine import correlate, note_provider_gaps
from app.correlation.risk import assess_risk
from app.core.config import Settings
from app.database.db import Database
from app.intelligence.providers import PHISHING_ADAPTERS
from app.intelligence.registry import ProviderRegistry, SOURCES
from app.intelligence.service import IntelService
from app.models.evidence import (
    Evidence, IndicatorType, ResultOrigin, ScanRecord, utc_now,
)
from app.reports.builder import build_phishing_report


def ensure_adapters_registered(registry: ProviderRegistry) -> None:
    for adapter in PHISHING_ADAPTERS:
        if registry.adapter(adapter.info.key) is None:
            try:
                registry.register(adapter)
            except ValueError:
                continue


def reliability_map(registry: ProviderRegistry) -> dict[str, float]:
    """Source-name -> internal weight for the correlation engine (PRD 12)."""
    mapping = {info.key: info.default_reliability for info in SOURCES}
    for info in SOURCES:
        mapping.setdefault(info.name.lower(), info.default_reliability)
    return mapping


DEMO_SCANS: dict[str, dict[str, Any]] = {}


def _demo_evidence(indicator: str) -> list[Evidence]:
    return [
        Evidence(indicator, IndicatorType.URL, "PhishGuard Local", "local_url_analysis",
                 "Brand name 'paypal' appears outside the domain", "high", 0.75,
                 "DEMONSTRATION DATA: the link mentions paypal but is hosted on an unrelated host.",
                 "", "detected", ResultOrigin.DEMO),
        Evidence(indicator, IndicatorType.URL, "PhishTank", "phishing_intelligence",
                 "PhishTank phishing record", "critical", 0.90,
                 "DEMONSTRATION DATA: community-verified phishing report.",
                 "https://phishtank.org", "detected", ResultOrigin.DEMO),
        Evidence(indicator, IndicatorType.URL, "URLhaus", "malware_url_intelligence",
                 "No URLhaus record for this indicator", "info", 0.75,
                 "DEMONSTRATION DATA: URLhaus holds no record.",
                 "https://urlhaus.abuse.ch", "not_found", ResultOrigin.DEMO),
    ]


def run_phishing_scan(raw_input: str, settings: Settings, db: Database,
                      registry: ProviderRegistry,
                      demo: bool = False) -> dict[str, Any]:
    """Run a full PhishGuard scan and persist it. Returns the report dict."""
    from app.core.indicators import identify  # local import: keeps module dependency-light

    ensure_adapters_registered(registry)
    identification = identify(raw_input)
    target = identification.normalized or identification.original
    if not target:
        raise ValueError("Empty indicator.")

    local = analyze_url(target)
    evidence: list[Evidence] = [Evidence.from_dict(e) for e in local["evidence"]]
    provider_rows: list[dict[str, Any]] = []
    origins_note = "LOCAL_ANALYSIS"

    if demo:
        demo_evidence = _demo_evidence(local["normalized_url"] or target)
        # keep the real local findings, mark them as demo for honesty
        for item in evidence:
            item.origin = ResultOrigin.DEMO
        evidence = evidence + demo_evidence
        provider_rows = [
            {"key": "phishtank", "name": "PhishTank", "state": "AVAILABLE",
             "origin": "DEMO_DATA", "message": "Demonstration data.", "latency_ms": 0, "evidence_count": 1},
            {"key": "urlhaus", "name": "URLhaus", "state": "AVAILABLE",
             "origin": "DEMO_DATA", "message": "Demonstration data.", "latency_ms": 0, "evidence_count": 1},
        ]
        origins_note = "DEMO_DATA"
    else:
        service = IntelService(settings, registry)
        outcome = service.query(local["normalized_url"] or target, IndicatorType.URL)
        evidence.extend(outcome["evidence"])
        provider_rows = outcome["providers"]
        for row in provider_rows:
            if row["state"] in ("AVAILABLE",) and row["evidence_count"]:
                origins_note = "LIVE_RESULT"
                break

    reliability = reliability_map(registry)
    correlation = note_provider_gaps(correlate(evidence, reliability), provider_rows)
    provider_hits = sum(1 for e in evidence
                        if e.status.value == "detected" and e.source != "PhishGuard Local")
    risk = assess_risk(local["local_weights"], correlation, provider_hits)

    scan_time = utc_now()
    report = build_phishing_report(
        target=local["normalized_url"] or target,
        original_input=identification.original,
        local=local, correlation=correlation, risk=risk,
        providers=provider_rows, is_demo=demo, scan_time=scan_time,
    )
    report["ai_analysis"] = build_assessment(
        module_label="PhishGuard", target=report["target"], risk=risk,
        correlation=correlation, recommendations=report["recommendations"],
        limitations=report["limitations"], providers=provider_rows, is_demo=demo)
    record = ScanRecord(
        indicator=local["normalized_url"] or target,
        indicator_type=IndicatorType.URL,
        risk_score=risk["score"], confidence=risk["confidence"],
        summary=risk["summary"], evidence=evidence, report=report,
        module="phishing", is_demo=demo,
    )
    record.report["scan_id"] = record.id
    db.save_scan(record)
    report["scan_id"] = record.id
    return report
