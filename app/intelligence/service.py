"""Intelligence service: runs every relevant adapter for one indicator.

- Skips adapters the user disabled (DISABLED) or that lack credentials
  (NOT_CONFIGURED) without treating that as "clean".
- Never raises and never returns raw provider bodies: only Evidence plus a
  per-provider status row for the Sources/explanation UI.
"""
from __future__ import annotations

from typing import Any

from app.core.config import Settings
from app.database.db import Database
from app.intelligence.base import ProviderResult, ThreatIntelProvider
from app.intelligence.http import HttpClient
from app.intelligence.registry import ProviderRegistry
from app.models.evidence import Evidence, IndicatorType, ProviderState, ResultOrigin


class IntelService:
    def __init__(self, settings: Settings, registry: ProviderRegistry,
                 http: HttpClient | None = None) -> None:
        self.settings = settings
        self.registry = registry
        self.http = http

    def _adapters_for(self, indicator_type: IndicatorType) -> list[ThreatIntelProvider]:
        adapters: list[ThreatIntelProvider] = []
        disabled = self.registry.disabled_keys()
        for info in self.registry.describe_all():
            if info["key"] in disabled or info.get("user_disabled"):
                continue
            cls = self.registry.adapter(info["key"])
            if cls is None:
                continue
            try:
                adapter = cls(self.settings, self.http) if self.http else cls(self.settings)
            except Exception:
                continue
            if adapter.supports(indicator_type):
                adapters.append(adapter)
        return adapters

    def query(self, indicator: str, indicator_type: IndicatorType) -> dict[str, Any]:
        evidence: list[Evidence] = []
        providers: list[dict[str, Any]] = []
        for adapter in self._adapters_for(indicator_type):
            try:
                result: ProviderResult = adapter.check(indicator, indicator_type)
            except Exception:
                result = ProviderResult(adapter.info.name, ProviderState.ERROR,
                                        ResultOrigin.PROVIDER_ERROR, message="Adapter failed.")
            evidence.extend(result.evidence)
            providers.append({
                "key": adapter.info.key, "name": adapter.info.name,
                "state": result.state.value, "origin": result.origin.value,
                "message": result.message, "latency_ms": result.latency_ms,
                "evidence_count": len(result.evidence),
            })
            if result.state.value not in ("NOT_CONFIGURED", "DISABLED"):
                try:
                    self.registry.db.save_source_health(
                        adapter.info.key, result.state.value,
                        result.message, result.latency_ms)
                except Exception:
                    pass
        return {"evidence": evidence, "providers": providers}
