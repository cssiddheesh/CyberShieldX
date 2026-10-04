"""Provider adapter contract (PRD section 23).

Every external intelligence source is wrapped in a ``ThreatIntelProvider``.
Provider-specific endpoints, auth and response formats stay inside the adapter;
the rest of the application only sees ``Evidence``.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from app.core.config import Settings
from app.intelligence.http import HttpClient
from app.models.evidence import Evidence, IndicatorType, ProviderState, ResultOrigin


@dataclass(frozen=True)
class SourceInfo:
    """Static metadata about a provider (PRD section 12)."""
    key: str
    name: str
    category: str                 # e.g. "phishing", "malware", "password", "vulnerability", "network"
    source_type: str              # value written to Evidence.source_type
    default_reliability: float    # internal weighting only - not a claim the provider is always right
    indicator_types: tuple[IndicatorType, ...]
    description: str
    data_sent: str                # plain-language privacy note shown to the user
    homepage: str
    env_var: Optional[str] = None  # credential variable; None when the provider needs no key
    implemented: bool = False      # True only once the adapter exists and is tested


@dataclass
class HealthResult:
    state: ProviderState
    message: str = ""
    latency_ms: Optional[int] = None


@dataclass
class ProviderResult:
    """Outcome of consulting one provider for one indicator."""
    source: str
    state: ProviderState
    origin: ResultOrigin
    evidence: list[Evidence] = field(default_factory=list)
    message: str = ""
    latency_ms: Optional[int] = None
    raw_summary: dict[str, Any] = field(default_factory=dict)


class ThreatIntelProvider(ABC):
    info: SourceInfo

    def __init__(self, settings: Settings, http: Optional[HttpClient] = None) -> None:
        self.settings = settings
        self.http = http or HttpClient(timeout=settings.http_timeout, retries=settings.http_retries)

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in self.info.indicator_types

    @abstractmethod
    def check(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        """Query the provider. Must never raise: failures become a ProviderResult state."""

    @abstractmethod
    def normalize(self, indicator: str, indicator_type: IndicatorType, response: Any) -> list[Evidence]:
        """Convert the provider's native response into common Evidence objects."""

    @abstractmethod
    def health_check(self) -> HealthResult:
        """Cheap reachability/credential check used by the Sources page."""
