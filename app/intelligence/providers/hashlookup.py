"""CIRCL Hashlookup adapter (known-file intelligence, NOT a malice verdict).

Docs: https://www.circl.lu/services/hashlookup/
  GET https://hashlookup.circl.lu/lookup/md5/{hash}
  GET https://hashlookup.circl.lu/lookup/sha1/{hash}
Free, no key. A match means "this file is known" (e.g. common software) and
is reported as informational - never as malicious (PRD 7.3).
"""
from __future__ import annotations

from typing import Any

from app.intelligence.base import (
    HealthResult, ProviderResult, SourceInfo, ThreatIntelProvider,
)
from app.models.evidence import Evidence, IndicatorType, ProviderState, ResultOrigin

INFO = SourceInfo(
    key="circl_hashlookup", name="CIRCL Hashlookup", category="file",
    source_type="known_file_intelligence", default_reliability=0.80,
    indicator_types=(IndicatorType.MD5, IndicatorType.SHA1),
    description="Identifies files that are known, such as common software, by their hash.",
    data_sent="The file hash (not the file) is sent to CIRCL.",
    homepage="https://www.circl.lu/services/hashlookup/",
    env_var=None, implemented=True,
)

BASE = "https://hashlookup.circl.lu/lookup"


class CirclHashlookupProvider(ThreatIntelProvider):
    info = INFO

    def check(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        try:
            kind = "md5" if indicator_type == IndicatorType.MD5 else "sha1"
            result = self.http.get(f"{BASE}/{kind}/{indicator.lower()}")
            return self._interpret(indicator, indicator_type, result)
        except Exception:
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="Hashlookup request failed.")

    def _interpret(self, indicator: str, indicator_type: IndicatorType, result) -> ProviderResult:
        if result.error == "rate_limited":
            return ProviderResult(INFO.name, ProviderState.RATE_LIMITED,
                                  ResultOrigin.PROVIDER_ERROR, message="Hashlookup rate limit reached.",
                                  latency_ms=result.latency_ms)
        if result.error in ("timeout", "network"):
            return ProviderResult(INFO.name, ProviderState.UNAVAILABLE,
                                  ResultOrigin.PROVIDER_ERROR, message="Hashlookup could not be reached.",
                                  latency_ms=result.latency_ms)
        if result.status == 404:
            evidence = [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                                 "Hash unknown to CIRCL Hashlookup", "info", 0.6,
                                 "CIRCL holds no record for this hash. Unknown does not mean malicious - "
                                 "most new or uncommon files are simply not catalogued.",
                                 "https://hashlookup.circl.lu", "not_found", ResultOrigin.LIVE)]
            return ProviderResult(INFO.name, ProviderState.AVAILABLE, ResultOrigin.LIVE,
                                  evidence=evidence, message="Hash unknown to CIRCL.",
                                  latency_ms=result.latency_ms)
        if not result.ok or not isinstance(result.data, dict):
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="Hashlookup returned an unreadable response.",
                                  latency_ms=result.latency_ms)
        evidence = self.normalize(indicator, indicator_type, result.data)
        return ProviderResult(INFO.name, ProviderState.AVAILABLE, ResultOrigin.LIVE,
                              evidence=evidence, message="CIRCL knows this file.",
                              latency_ms=result.latency_ms)

    def normalize(self, indicator: str, indicator_type: IndicatorType, response: Any) -> list[Evidence]:
        if not isinstance(response, dict):
            return []
        name = str(response.get("FileName") or response.get("FileNameComplete") or "known file")
        source = str(response.get("source") or "NSRL/known-file dataset")
        return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                         f"Known file: {name[:120]}", "info", 0.85,
                         f"CIRCL Hashlookup recognises this hash ({source}). A known-file match is "
                         "context only: it says the file is catalogued, not that it is safe or malicious.",
                         "https://hashlookup.circl.lu", "informational", ResultOrigin.LIVE)]

    def health_check(self) -> HealthResult:
        return HealthResult(ProviderState.UNCHECKED, "No key needed. Not checked yet.")
