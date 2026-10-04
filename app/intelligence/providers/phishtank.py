"""PhishTank adapter. Docs: https://www.phishtank.com/api_info.php."""
from __future__ import annotations

from typing import Any

from app.intelligence.base import (
    HealthResult, ProviderResult, SourceInfo, ThreatIntelProvider,
)
from app.models.evidence import Evidence, IndicatorType, ProviderState, ResultOrigin

INFO = SourceInfo(
    key="phishtank", name="PhishTank", category="phishing",
    source_type="phishing_intelligence", default_reliability=0.85,
    indicator_types=(IndicatorType.URL,),
    description="Community-verified list of phishing URLs.",
    data_sent="The URL you analyze is sent to PhishTank.",
    homepage="https://phishtank.org", env_var="PHISHTANK_API_KEY",
    implemented=True,
)

CHECK_URL = "http://checkurl.phishtank.com/checkurl/"
USER_AGENT = "CyberShieldX/0.1 (educational defensive scanner)"


class PhishTankProvider(ThreatIntelProvider):
    info = INFO

    def check(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        try:
            form: dict[str, str] = {"url": indicator, "format": "json"}
            key = self.settings.key("phishtank")
            if key:  # app_key is optional; without it limits are stricter
                form["app_key"] = key
            result = self.http.post(CHECK_URL, data=form,
                                    headers={"User-Agent": USER_AGENT})
            return self._interpret(indicator, indicator_type, result)
        except Exception:
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="PhishTank request failed.")

    def _interpret(self, indicator: str, indicator_type: IndicatorType, result) -> ProviderResult:
        if result.error == "rate_limited":
            return ProviderResult(INFO.name, ProviderState.RATE_LIMITED,
                                  ResultOrigin.PROVIDER_ERROR, message="PhishTank rate limit reached.",
                                  latency_ms=result.latency_ms)
        if result.error in ("timeout", "network"):
            return ProviderResult(INFO.name, ProviderState.UNAVAILABLE,
                                  ResultOrigin.PROVIDER_ERROR, message="PhishTank could not be reached.",
                                  latency_ms=result.latency_ms)
        if not result.ok or not isinstance(result.data, dict):
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="PhishTank returned an unreadable response.",
                                  latency_ms=result.latency_ms)
        evidence = self.normalize(indicator, indicator_type, result.data)
        hit = any(e.status.value == "detected" for e in evidence)
        return ProviderResult(INFO.name, ProviderState.AVAILABLE, ResultOrigin.LIVE,
                              evidence=evidence,
                              message="PhishTank lists this URL as phishing." if hit
                              else "No PhishTank record. This does not prove safety.",
                              latency_ms=result.latency_ms)

    def normalize(self, indicator: str, indicator_type: IndicatorType, response: Any) -> list[Evidence]:
        results = response.get("results", {}) if isinstance(response, dict) else {}
        if not isinstance(results, dict):
            return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                             "PhishTank returned an unexpected shape", "info", 0.3,
                             "The response could not be interpreted.",
                             "https://phishtank.org", "unavailable", ResultOrigin.PROVIDER_ERROR)]
        in_db = bool(results.get("in_database"))
        verified = str(results.get("verified", "n")).lower() == "y"
        valid = str(results.get("valid", "n")).lower() == "y"
        detail_page = str(results.get("phish_detail_page") or "https://phishtank.org")
        if in_db and valid:
            sev: str = "critical" if verified else "high"
            conf = 0.90 if verified else 0.75
            extra = "Community-verified phishing report." if verified else "Reported as phishing (awaiting verification)."
            return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                             "PhishTank phishing record", sev, conf,  # type: ignore[arg-type]
                             f"{extra} See {detail_page}.", detail_page,
                             "detected", ResultOrigin.LIVE)]
        if in_db:
            return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                             "PhishTank record but marked not valid", "low", 0.4,
                             "PhishTank holds a record that is currently marked as not a valid phish.",
                             detail_page, "informational", ResultOrigin.LIVE)]
        return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                         "No PhishTank record for this URL", "info", 0.7,
                         "PhishTank holds no record. Absence of a record does not prove safety.",
                         "https://phishtank.org", "not_found", ResultOrigin.LIVE)]

    def health_check(self) -> HealthResult:
        return HealthResult(ProviderState.UNCHECKED, "Configured. Not checked yet.")
