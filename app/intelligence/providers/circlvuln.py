"""CIRCL Vulnerability-Lookup adapter.

Docs: https://vulnerability.circl.lu/documentation/api.html
  GET https://vulnerability.circl.lu/api/vulnerability/{CVE-ID}
Free, no key. Returns the CVE 5.x record JSON (cveMetadata + containers.cna
with descriptions, affected products, metrics, references).
"""
from __future__ import annotations

from typing import Any

from app.intelligence.base import (
    HealthResult, ProviderResult, SourceInfo, ThreatIntelProvider,
)
from app.models.evidence import Evidence, IndicatorType, ProviderState, ResultOrigin

INFO = SourceInfo(
    key="circl_vuln", name="CIRCL Vulnerability-Lookup", category="vulnerability",
    source_type="vulnerability_intelligence", default_reliability=0.90,
    indicator_types=(IndicatorType.CVE,),
    description="Public vulnerability records (CVEs) with severity and references.",
    data_sent="The CVE identifier you look up is sent to CIRCL.",
    homepage="https://vulnerability.circl.lu",
    env_var=None, implemented=True,
)

BASE = "https://vulnerability.circl.lu/api/vulnerability"


_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
_SEVERITY_WORDS = ("critical", "high", "medium", "low", "none")


def _containers(record: dict[str, Any]) -> list[dict[str, Any]]:
    containers = record.get("containers") or {}
    found = []
    for key in ("cna",):
        if isinstance(containers.get(key), dict):
            found.append(containers[key])
    adp = containers.get("adp")
    if isinstance(adp, list):
        found.extend(item for item in adp if isinstance(item, dict))
    return found


def cvss_from_record(record: dict[str, Any]) -> tuple[float | None, str]:
    """Extract (baseScore, severityWord) scanning CNA + ADP containers.

    Numeric CVSS wins; otherwise a published severity word (e.g. CISA ADP
    ``other`` metrics) is used so the record is still classified correctly.
    """
    word: str = ""
    try:
        for container in _containers(record if isinstance(record, dict) else {}):
            metrics = container.get("metrics") or []
            if isinstance(metrics, dict):
                metrics = [metrics]
            best: tuple[float, str] | None = None
            for metric in metrics:
                if not isinstance(metric, dict):
                    continue
                for key in _CVSS_KEYS:
                    data = metric.get(key)
                    if isinstance(data, dict) and isinstance(data.get("baseScore"), (int, float)):
                        score = float(data["baseScore"])
                        sev = str(data.get("baseSeverity") or "").lower()
                        if best is None or score > best[0]:
                            best = (score, sev)
                other = metric.get("other")
                if isinstance(other, dict):
                    content = other.get("content")
                    text = ""
                    if isinstance(content, dict):
                        text = " ".join(str(v) for v in content.values()).lower()
                    elif isinstance(content, str):
                        text = content.lower()
                    for candidate in _SEVERITY_WORDS:
                        if candidate in text and (not word or _SEVERITY_WORDS.index(candidate)
                                                  < _SEVERITY_WORDS.index(word)):
                            word = candidate
            if best:
                return best
    except (AttributeError, TypeError, ValueError):
        pass
    return None, word


def severity_for_score(score: float | None, word: str = "") -> str:
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"
    if word in ("critical", "high", "medium", "low"):
        return word
    return "medium"


class CirclVulnProvider(ThreatIntelProvider):
    info = INFO

    def check(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        try:
            result = self.http.get(f"{BASE}/{indicator.upper()}")
            return self._interpret(indicator.upper(), indicator_type, result)
        except Exception:
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="Vulnerability lookup failed.")

    def _interpret(self, indicator: str, indicator_type: IndicatorType, result) -> ProviderResult:
        if result.error == "rate_limited":
            return ProviderResult(INFO.name, ProviderState.RATE_LIMITED,
                                  ResultOrigin.PROVIDER_ERROR, message="Vulnerability-Lookup rate limit reached.",
                                  latency_ms=result.latency_ms)
        if result.error in ("timeout", "network"):
            return ProviderResult(INFO.name, ProviderState.UNAVAILABLE,
                                  ResultOrigin.PROVIDER_ERROR, message="Vulnerability-Lookup could not be reached.",
                                  latency_ms=result.latency_ms)
        if result.status == 404:
            evidence = [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                                 f"No record for {indicator}", "info", 0.6,
                                 "CIRCL holds no record. The ID may be reserved, rejected, or too new.",
                                 "https://vulnerability.circl.lu", "not_found", ResultOrigin.LIVE)]
            return ProviderResult(INFO.name, ProviderState.AVAILABLE, ResultOrigin.LIVE,
                                  evidence=evidence, message="No record for this CVE.",
                                  latency_ms=result.latency_ms)
        if not result.ok or not isinstance(result.data, dict):
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="Vulnerability-Lookup returned an unreadable response.",
                                  latency_ms=result.latency_ms)
        evidence = self.normalize(indicator, indicator_type, result.data)
        return ProviderResult(INFO.name, ProviderState.AVAILABLE, ResultOrigin.LIVE,
                              evidence=evidence, message=f"Record found for {indicator}.",
                              latency_ms=result.latency_ms)

    def normalize(self, indicator: str, indicator_type: IndicatorType, response: Any) -> list[Evidence]:
        if not isinstance(response, dict):
            return []
        cna = ((response.get("containers") or {}).get("cna")) or {}
        descriptions = cna.get("descriptions") or []
        summary = next((str(d.get("value", "")) for d in descriptions
                       if isinstance(d, dict) and d.get("lang") == "en" and d.get("value")), "")
        score, word = cvss_from_record(response)
        severity = severity_for_score(score, word)
        affected = cna.get("affected") or []
        products = []
        for item in affected if isinstance(affected, list) else []:
            if isinstance(item, dict):
                vendor = str(item.get("vendor") or "").strip()
                product = str(item.get("product") or "").strip()
                if product:
                    products.append(f"{vendor} {product}".strip())
        score_text = f"CVSS {score}" if score is not None else (
            f"severity {severity} (no numeric score published)" if word else "severity unrated")
        detail = summary[:600] or "No description published yet."
        detail = f"{score_text}. " + detail
        if products:
            detail += " Affected: " + "; ".join(products[:5]) + "."
        refs = [str(r.get("url")) for r in (cna.get("references") or [])
                if isinstance(r, dict) and r.get("url")][:3]
        return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                         f"{indicator}: {score_text}", severity, 0.9,  # type: ignore[arg-type]
                         detail, refs[0] if refs else "https://vulnerability.circl.lu",
                         "detected", ResultOrigin.LIVE)]

    def health_check(self) -> HealthResult:
        return HealthResult(ProviderState.UNCHECKED, "No key needed. Not checked yet.")
