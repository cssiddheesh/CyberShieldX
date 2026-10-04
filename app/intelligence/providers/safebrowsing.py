"""Google Safe Browsing v4 adapter. Docs: developers.google.com/safe-browsing/v4."""
from __future__ import annotations

from typing import Any

from app.intelligence.base import (
    HealthResult, ProviderResult, SourceInfo, ThreatIntelProvider,
)
from app.models.evidence import Evidence, IndicatorType, ProviderState, ResultOrigin

INFO = SourceInfo(
    key="safebrowsing", name="Google Safe Browsing", category="phishing",
    source_type="browser_safety_intelligence", default_reliability=0.90,
    indicator_types=(IndicatorType.URL,),
    description="Google's lists of unsafe websites.",
    data_sent="The URL you analyze is sent to Google.",
    homepage="https://safebrowsing.google.com", env_var="GOOGLE_SAFE_BROWSING_API_KEY",
    implemented=True,
)

FIND_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


class SafeBrowsingProvider(ThreatIntelProvider):
    info = INFO

    def _body(self, indicator: str) -> dict[str, Any]:
        return {
            "client": {"clientId": "cybershield-x", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": indicator}],
            },
        }

    def check(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        key = self.settings.key("safebrowsing")
        if not key:
            return ProviderResult(INFO.name, ProviderState.NOT_CONFIGURED,
                                  ResultOrigin.NOT_CONFIGURED,
                                  message="Add GOOGLE_SAFE_BROWSING_API_KEY to .env.")
        try:
            result = self.http.post(FIND_URL, params={"key": key}, json_body=self._body(indicator))
            return self._interpret(indicator, indicator_type, result)
        except Exception:
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="Safe Browsing request failed.")

    def _interpret(self, indicator: str, indicator_type: IndicatorType, result) -> ProviderResult:
        if result.error == "rate_limited":
            return ProviderResult(INFO.name, ProviderState.RATE_LIMITED,
                                  ResultOrigin.PROVIDER_ERROR, message="Safe Browsing quota reached.",
                                  latency_ms=result.latency_ms)
        if result.error in ("timeout", "network"):
            return ProviderResult(INFO.name, ProviderState.UNAVAILABLE,
                                  ResultOrigin.PROVIDER_ERROR, message="Safe Browsing could not be reached.",
                                  latency_ms=result.latency_ms)
        if not result.ok or not isinstance(result.data, dict):
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="Safe Browsing returned an unreadable response.",
                                  latency_ms=result.latency_ms)
        evidence = self.normalize(indicator, indicator_type, result.data)
        hit = any(e.status.value == "detected" for e in evidence)
        return ProviderResult(INFO.name, ProviderState.AVAILABLE, ResultOrigin.LIVE,
                              evidence=evidence,
                              message="Google Safe Browsing flags this URL." if hit
                              else "No Safe Browsing match. This does not prove safety.",
                              latency_ms=result.latency_ms)

    def normalize(self, indicator: str, indicator_type: IndicatorType, response: Any) -> list[Evidence]:
        matches = response.get("matches") if isinstance(response, dict) else None
        if matches:
            kinds = sorted({str(m.get("threatType", "UNSAFE")) for m in matches if isinstance(m, dict)})
            return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                             f"Safe Browsing match: {', '.join(kinds)}", "critical", 0.93,
                             f"Google Safe Browsing lists this URL ({', '.join(kinds)}).",
                             "https://safebrowsing.google.com", "detected", ResultOrigin.LIVE)]
        return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                         "No Safe Browsing match", "info", 0.7,
                         "Google Safe Browsing holds no match. Lists may be incomplete.",
                         "https://safebrowsing.google.com", "not_found", ResultOrigin.LIVE)]

    def health_check(self) -> HealthResult:
        if not self.settings.key("safebrowsing"):
            return HealthResult(ProviderState.NOT_CONFIGURED, "Add GOOGLE_SAFE_BROWSING_API_KEY to .env.")
        return HealthResult(ProviderState.UNCHECKED, "Configured. Not checked yet.")
