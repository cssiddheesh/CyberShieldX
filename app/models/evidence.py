"""Common data model shared by every analyzer, provider, the correlation and risk
engines, the AI analyst, reports and the database.

Every finding from every source - local analysis or external intelligence - is
expressed as an ``Evidence`` object (PRD section 9).
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class StrEnum(str, Enum):
    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class IndicatorType(StrEnum):
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    FILE = "file"
    PASSWORD = "password"
    TEXT = "text"
    IMAGE = "image"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class EvidenceStatus(StrEnum):
    DETECTED = "detected"          # the source reported a relevant match / signal
    INFORMATIONAL = "informational"  # context only (e.g. a known-file match)
    NOT_FOUND = "not_found"        # source has no record. This does NOT prove safety.
    UNAVAILABLE = "unavailable"    # source could not be consulted


class ProviderState(StrEnum):
    AVAILABLE = "AVAILABLE"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNAVAILABLE = "UNAVAILABLE"
    RATE_LIMITED = "RATE_LIMITED"
    ERROR = "ERROR"
    DISABLED = "DISABLED"
    # Internal addition: configured and implemented, but no health check has run yet.
    UNCHECKED = "UNCHECKED"


class ResultOrigin(StrEnum):
    """How a piece of evidence was obtained. Reports must always show this (PRD 22)."""
    LIVE = "LIVE_RESULT"
    CACHED = "CACHED_RESULT"
    LOCAL = "LOCAL_ANALYSIS"
    DEMO = "DEMO_DATA"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    PROVIDER_ERROR = "PROVIDER_ERROR"


# PRD section 11: transparent 0-100 internal score. Thresholds are configurable here.
RISK_LEVELS: list[tuple[int, int, str]] = [
    (0, 19, "Minimal"),
    (20, 39, "Low"),
    (40, 59, "Moderate"),
    (60, 79, "High"),
    (80, 100, "Critical"),
]
RISK_LEVEL_NAMES = [name for _, _, name in RISK_LEVELS]


def risk_level_for(score: float) -> str:
    value = max(0, min(100, int(round(score))))
    for low, high, name in RISK_LEVELS:
        if low <= value <= high:
            return name
    return "Minimal"  # pragma: no cover


def confidence_label(confidence: float) -> str:
    """Confidence is reported separately from risk (PRD section 11)."""
    if confidence < 0.4:
        return "Low"
    if confidence < 0.7:
        return "Moderate"
    return "High"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_scan_id() -> str:
    return f"CSX-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(3).upper()}"


def _coerce(enum_cls: type[Enum], value: Any):
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(value)
    except ValueError:
        # accept the enum member name too ("LIVE" -> LIVE_RESULT)
        return enum_cls[str(value).upper()]


@dataclass
class Evidence:
    indicator: str
    indicator_type: IndicatorType
    source: str
    source_type: str
    finding: str
    severity: Severity
    confidence: float
    evidence: str
    reference: str = ""
    status: EvidenceStatus = EvidenceStatus.DETECTED
    origin: ResultOrigin = ResultOrigin.LOCAL
    timestamp: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        self.indicator_type = _coerce(IndicatorType, self.indicator_type)
        self.severity = _coerce(Severity, self.severity)
        self.status = _coerce(EvidenceStatus, self.status)
        self.origin = _coerce(ResultOrigin, self.origin)
        if not str(self.source).strip():
            raise ValueError("Evidence.source is required")
        if not str(self.finding).strip():
            raise ValueError("Evidence.finding is required")
        try:
            self.confidence = max(0.0, min(1.0, float(self.confidence)))
        except (TypeError, ValueError):
            raise ValueError("Evidence.confidence must be a number between 0 and 1")
        # Bound sizes so provider responses can never bloat storage or the UI.
        self.indicator = str(self.indicator)[:2048]
        self.source = str(self.source)[:80]
        self.source_type = str(self.source_type)[:80]
        self.finding = str(self.finding)[:300]
        self.evidence = str(self.evidence)[:2000]
        self.reference = str(self.reference or "")[:2048]

    def dedupe_key(self) -> tuple[str, str, str]:
        return (self.source.lower(), self.indicator.lower(), self.finding.lower())

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type.value,
            "source": self.source,
            "source_type": self.source_type,
            "finding": self.finding,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "reference": self.reference,
            "status": self.status.value,
            "origin": self.origin.value,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        return cls(
            indicator=data["indicator"],
            indicator_type=data["indicator_type"],
            source=data["source"],
            source_type=data.get("source_type", ""),
            finding=data["finding"],
            severity=data.get("severity", "info"),
            confidence=data.get("confidence", 0.0),
            evidence=data.get("evidence", ""),
            reference=data.get("reference", ""),
            status=data.get("status", "detected"),
            origin=data.get("origin", "LOCAL_ANALYSIS"),
            timestamp=data.get("timestamp") or utc_now(),
        )


@dataclass
class ScanRecord:
    """A completed scan as stored in history."""
    indicator: str
    indicator_type: IndicatorType
    risk_score: int
    confidence: float
    summary: str
    evidence: list[Evidence] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=new_scan_id)
    created_at: str = field(default_factory=utc_now)
    status: str = "completed"
    is_demo: bool = False
    module: Optional[str] = None

    @property
    def risk_level(self) -> str:
        return risk_level_for(self.risk_score)
