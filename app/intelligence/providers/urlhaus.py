"""URLhaus adapter. Docs: https://urlhaus-api.abuse.ch/ and abusech/URLhaus on GitHub."""
from __future__ import annotations

from typing import Any

from app.intelligence.base import (
    HealthResult, ProviderResult, SourceInfo, ThreatIntelProvider,
)
from app.models.evidence import Evidence, IndicatorType, ProviderState, ResultOrigin

INFO = SourceInfo(
    key="urlhaus", name="URLhaus", category="phishing",
    source_type="malware_url_intelligence", default_reliability=0.90,
    indicator_types=(IndicatorType.URL, IndicatorType.DOMAIN),
    description="Community database of URLs that distribute malware, run by abuse.ch.",
    data_sent="The URL or host you analyze is sent to abuse.ch.",
    homepage="https://urlhaus.abuse.ch", env_var="URLHAUS_API_KEY",
    implemented=True,
)

LOOKUP_URL = "https://urlhaus-api.abuse.ch/v1/url/"
HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"


class UrlHausProvider(ThreatIntelProvider):
    info = INFO

    def check(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        key = self.settings.key("urlhaus")
        if not key:
            return ProviderResult(INFO.name, ProviderState.NOT_CONFIGURED,
                                  ResultOrigin.NOT_CONFIGURED, message="Add URLHAUS_API_KEY to .env.")
        try:
            if indicator_type == IndicatorType.DOMAIN:
                result = self.http.post(HOST_URL, data={"host": indicator},
                                        headers={"Auth-Key": key})
            else:
                result = self.http.post(LOOKUP_URL, data={"url": indicator},
                                        headers={"Auth-Key": key})
            return self._interpret(indicator, indicator_type, result)
        except Exception:
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="URLhaus request failed.")

    def _interpret(self, indicator: str, indicator_type: IndicatorType, result) -> ProviderResult:
        if result.error == "rate_limited":
            return ProviderResult(INFO.name, ProviderState.RATE_LIMITED,
                                  ResultOrigin.PROVIDER_ERROR, message="URLhaus rate limit reached.",
                                  latency_ms=result.latency_ms)
        if result.error in ("timeout", "network"):
            return ProviderResult(INFO.name, ProviderState.UNAVAILABLE,
                                  ResultOrigin.PROVIDER_ERROR, message="URLhaus could not be reached.",
                                  latency_ms=result.latency_ms)
        if not result.ok or not isinstance(result.data, dict):
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="URLhaus returned an unreadable response.",
                                  latency_ms=result.latency_ms)
        evidence = self.normalize(indicator, indicator_type, result.data)
        state = ProviderState.AVAILABLE
        origin = ResultOrigin.LIVE
        message = "URLhaus record found." if any(e.status.value == "detected" for e in evidence) \
            else "No URLhaus record. This does not prove safety."
        return ProviderResult(INFO.name, state, origin, evidence=evidence,
                              message=message, latency_ms=result.latency_ms)

    def normalize(self, indicator: str, indicator_type: IndicatorType, response: Any) -> list[Evidence]:
        if not isinstance(response, dict):
            return []
        status = str(response.get("query_status", "")).lower()
        if status == "no_results":
            return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                             "No URLhaus record for this indicator", "info", 0.75,
                             "URLhaus holds no record. Absence of a record does not prove safety.",
                             "https://urlhaus.abuse.ch", "not_found", ResultOrigin.LIVE)]
        if status != "ok":
            return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                             "URLhaus query returned an unexpected status", "info", 0.3,
                             f"URLhaus answered with query_status '{response.get('query_status')}'.",
                             "https://urlhaus.abuse.ch", "unavailable", ResultOrigin.PROVIDER_ERROR)]
        threat = str(response.get("threat") or "malware distribution")
        parts = [f"URLhaus lists this indicator (threat: {threat})."]
        if response.get("malware"):
            parts.append(f"Associated malware: {response.get('malware')}.")
        if response.get("firstseen"):
            parts.append(f"First seen {response.get('firstseen')}.")
        ref = str(response.get("urlhaus_reference") or "https://urlhaus.abuse.ch")
        return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                         f"URLhaus record: {threat}", "critical", 0.92,
                         " ".join(parts), ref, "detected", ResultOrigin.LIVE)]

    def health_check(self) -> HealthResult:
        if not self.settings.key("urlhaus"):
            return HealthResult(ProviderState.NOT_CONFIGURED, "Add URLHAUS_API_KEY to .env.")
        return HealthResult(ProviderState.UNCHECKED, "Configured. Not checked yet.")
