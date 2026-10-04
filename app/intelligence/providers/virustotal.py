"""VirusTotal v3 URL adapter. Docs: docs.virustotal.com/reference/url-info."""
from __future__ import annotations

import base64
from typing import Any

from app.intelligence.base import (
    HealthResult, ProviderResult, SourceInfo, ThreatIntelProvider,
)
from app.models.evidence import Evidence, IndicatorType, ProviderState, ResultOrigin

INFO = SourceInfo(
    key="virustotal", name="VirusTotal", category="multi",
    source_type="multi_engine_intelligence", default_reliability=0.85,
    indicator_types=(IndicatorType.URL, IndicatorType.DOMAIN,
                     IndicatorType.IPV4, IndicatorType.IPV6,
                     IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256),
    description="Results from many security engines combined.",
    data_sent="The URL, domain, IP address or file hash you analyze is sent to VirusTotal.",
    homepage="https://www.virustotal.com", env_var="VIRUSTOTAL_API_KEY",
    implemented=True,
)

API_BASE = "https://www.virustotal.com/api/v3"


def url_id(url: str) -> str:
    """VirusTotal URL identifier: base64url of the URL without padding."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _gui_link(indicator: str, indicator_type: IndicatorType) -> str:
    if indicator_type == IndicatorType.URL:
        return f"https://www.virustotal.com/gui/url/{url_id(indicator)}/detection"
    if indicator_type == IndicatorType.DOMAIN:
        return f"https://www.virustotal.com/gui/domain/{indicator}/detection"
    if indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6):
        return f"https://www.virustotal.com/gui/ip-address/{indicator}/detection"
    return f"https://www.virustotal.com/gui/file/{indicator.lower()}/detection"


class VirusTotalUrlProvider(ThreatIntelProvider):
    info = INFO

    def check(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        key = self.settings.key("virustotal")
        if not key:
            return ProviderResult(INFO.name, ProviderState.NOT_CONFIGURED,
                                  ResultOrigin.NOT_CONFIGURED, message="Add VIRUSTOTAL_API_KEY to .env.")
        try:
            if indicator_type == IndicatorType.URL:
                endpoint = f"{API_BASE}/urls/{url_id(indicator)}"
            elif indicator_type == IndicatorType.DOMAIN:
                endpoint = f"{API_BASE}/domains/{indicator}"
            elif indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6):
                endpoint = f"{API_BASE}/ip_addresses/{indicator}"
            elif indicator_type in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256):
                endpoint = f"{API_BASE}/files/{indicator.lower()}"
            else:
                return ProviderResult(INFO.name, ProviderState.UNAVAILABLE,
                                      ResultOrigin.PROVIDER_ERROR,
                                      message="This indicator type is not covered by VirusTotal lookups.")
            result = self.http.get(endpoint, headers={"x-apikey": key})
            return self._interpret(indicator, indicator_type, result)
        except Exception:
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="VirusTotal request failed.")

    def _interpret(self, indicator: str, indicator_type: IndicatorType, result) -> ProviderResult:
        if result.error == "rate_limited":
            return ProviderResult(INFO.name, ProviderState.RATE_LIMITED,
                                  ResultOrigin.PROVIDER_ERROR, message="VirusTotal quota reached.",
                                  latency_ms=result.latency_ms)
        if result.error in ("timeout", "network"):
            return ProviderResult(INFO.name, ProviderState.UNAVAILABLE,
                                  ResultOrigin.PROVIDER_ERROR, message="VirusTotal could not be reached.",
                                  latency_ms=result.latency_ms)
        if result.status == 404:
            evidence = [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                                 "No VirusTotal record for this indicator", "info", 0.6,
                                 "VirusTotal has never seen this indicator. This does not prove safety.",
                                 "https://www.virustotal.com", "not_found", ResultOrigin.LIVE)]
            return ProviderResult(INFO.name, ProviderState.AVAILABLE, ResultOrigin.LIVE,
                                  evidence=evidence, message="No VirusTotal record.",
                                  latency_ms=result.latency_ms)
        if not result.ok or not isinstance(result.data, dict):
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="VirusTotal returned an unreadable response.",
                                  latency_ms=result.latency_ms)
        evidence = self.normalize(indicator, indicator_type, result.data)
        hit = any(e.status.value == "detected" for e in evidence)
        return ProviderResult(INFO.name, ProviderState.AVAILABLE, ResultOrigin.LIVE,
                              evidence=evidence,
                              message="VirusTotal engines flag this indicator." if hit
                              else "VirusTotal engines do not flag this indicator.",
                              latency_ms=result.latency_ms)

    def normalize(self, indicator: str, indicator_type: IndicatorType, response: Any) -> list[Evidence]:
        attrs = response.get("data", {}).get("attributes", {}) if isinstance(response, dict) else {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        ref = _gui_link(indicator, indicator_type)
        if malicious:
            return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                             f"VirusTotal: {malicious} engine(s) flag malicious", "critical", 0.88,
                             f"{malicious} malicious, {suspicious} suspicious, {harmless} harmless, "
                             f"{undetected} undetected. Engine votes disagree often; treat as one weighted signal.",
                             ref, "detected", ResultOrigin.LIVE)]
        if suspicious:
            return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                             f"VirusTotal: {suspicious} engine(s) flag suspicious", "medium", 0.6,
                             f"{suspicious} suspicious, {harmless} harmless, {undetected} undetected. "
                             "Suspicious votes alone are weak evidence.",
                             ref, "detected", ResultOrigin.LIVE)]
        return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                         "VirusTotal: no engines flag this indicator", "info", 0.65,
                         f"Known to VirusTotal ({harmless} harmless, {undetected} undetected) with no "
                         "malicious votes. Clean votes do not prove safety.",
                         ref, "informational", ResultOrigin.LIVE)]

    def health_check(self) -> HealthResult:
        if not self.settings.key("virustotal"):
            return HealthResult(ProviderState.NOT_CONFIGURED, "Add VIRUSTOTAL_API_KEY to .env.")
        return HealthResult(ProviderState.UNCHECKED, "Configured. Not checked yet.")
