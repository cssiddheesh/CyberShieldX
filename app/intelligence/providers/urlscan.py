"""urlscan.io adapter (read-only search). Docs: https://docs.urlscan.io/."""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

from app.intelligence.base import (
    HealthResult, ProviderResult, SourceInfo, ThreatIntelProvider,
)
from app.models.evidence import Evidence, IndicatorType, ProviderState, ResultOrigin

INFO = SourceInfo(
    key="urlscan", name="urlscan.io", category="phishing",
    source_type="url_scan_intelligence", default_reliability=0.70,
    indicator_types=(IndicatorType.URL, IndicatorType.DOMAIN),
    description="Public scans of websites, including how a page looked and behaved.",
    data_sent="The URL or domain you analyze is sent to urlscan.io.",
    homepage="https://urlscan.io", env_var="URLSCAN_API_KEY",
    implemented=True,
)

SEARCH_URL = "https://urlscan.io/api/v1/search/"


class UrlScanProvider(ThreatIntelProvider):
    info = INFO

    def check(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        key = self.settings.key("urlscan")
        if not key:
            return ProviderResult(INFO.name, ProviderState.NOT_CONFIGURED,
                                  ResultOrigin.NOT_CONFIGURED, message="Add URLSCAN_API_KEY to .env.")
        try:
            if indicator_type == IndicatorType.DOMAIN:
                query = f"page.domain:{indicator}"
            else:
                query = f'page.url:"{indicator}"'
            result = self.http.get(SEARCH_URL, params={"q": query, "size": 5},
                                   headers={"API-Key": key})
            return self._interpret(indicator, indicator_type, result)
        except Exception:
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="urlscan.io request failed.")

    def _interpret(self, indicator: str, indicator_type: IndicatorType, result) -> ProviderResult:
        if result.error == "rate_limited":
            return ProviderResult(INFO.name, ProviderState.RATE_LIMITED,
                                  ResultOrigin.PROVIDER_ERROR, message="urlscan.io rate limit reached.",
                                  latency_ms=result.latency_ms)
        if result.error in ("timeout", "network"):
            return ProviderResult(INFO.name, ProviderState.UNAVAILABLE,
                                  ResultOrigin.PROVIDER_ERROR, message="urlscan.io could not be reached.",
                                  latency_ms=result.latency_ms)
        if not result.ok or not isinstance(result.data, dict):
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="urlscan.io returned an unreadable response.",
                                  latency_ms=result.latency_ms)
        evidence = self.normalize(indicator, indicator_type, result.data)
        hit = any(e.status.value == "detected" for e in evidence)
        return ProviderResult(INFO.name, ProviderState.AVAILABLE, ResultOrigin.LIVE,
                              evidence=evidence,
                              message="urlscan.io holds scans flagging this indicator." if hit
                              else "No urlscan.io scans flag this indicator.",
                              latency_ms=result.latency_ms)

    def normalize(self, indicator: str, indicator_type: IndicatorType, response: Any) -> list[Evidence]:
        if not isinstance(response, dict):
            return []
        total = int(response.get("total") or 0)
        results = response.get("results") or []
        malicious = 0
        examples: list[str] = []
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                verdicts = item.get("verdicts") or {}
                overall = verdicts.get("overall") or {}
                if overall.get("malicious"):
                    malicious += 1
                    scan_url = str(item.get("result") or item.get("task", {}).get("url") or "")
                    if scan_url:
                        examples.append(scan_url)
        if malicious:
            ref = f"https://urlscan.io/search/#page.url%3A%22{quote(indicator, safe='')}%22"
            return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                             f"urlscan.io: {malicious} scan(s) flagged malicious", "high", 0.75,
                             f"{malicious} of {total} public urlscan.io scan(s) carry a malicious verdict. "
                             "Scan verdicts are third-party assessments, not proof.",
                             ref, "detected", ResultOrigin.LIVE)]
        if total:
            return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                             f"urlscan.io: {total} scan(s), none flagged malicious", "info", 0.6,
                             "Public scans exist but none carry a malicious verdict. "
                             "This does not prove safety.", "https://urlscan.io",
                             "informational", ResultOrigin.LIVE)]
        return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                         "No urlscan.io scans for this indicator", "info", 0.5,
                         "No public scans found. Absence of scans says nothing about safety.",
                         "https://urlscan.io", "not_found", ResultOrigin.LIVE)]

    def health_check(self) -> HealthResult:
        if not self.settings.key("urlscan"):
            return HealthResult(ProviderState.NOT_CONFIGURED, "Add URLSCAN_API_KEY to .env.")
        return HealthResult(ProviderState.UNCHECKED, "Configured. Not checked yet.")
