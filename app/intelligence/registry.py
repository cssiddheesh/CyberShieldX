"""Catalog of intelligence sources, their live status, and adapter registration.

Phase 1: every source below is listed with ``implemented=False``. A source flips
to implemented only when its adapter exists, was written against the provider's
current official documentation, and has passing tests. The ``default_reliability``
numbers are internal weights (PRD section 12), not claims about provider accuracy.
"""
from __future__ import annotations

from typing import Any, Optional, Type

from app.core.config import PROVIDER_ENV_VARS, Settings
from app.database.db import Database
from app.intelligence.base import SourceInfo, ThreatIntelProvider
from app.models.evidence import IndicatorType, ProviderState

T = IndicatorType
HASHES = (T.MD5, T.SHA1, T.SHA256)

SOURCES: list[SourceInfo] = [
    SourceInfo("urlhaus", "URLhaus", "phishing", "malware_url_intelligence", 0.90, (T.URL, T.DOMAIN),
               "Community database of URLs that distribute malware, run by abuse.ch.",
               "The URL or host you analyze is sent to abuse.ch.",
               "https://urlhaus.abuse.ch", env_var=PROVIDER_ENV_VARS["urlhaus"], implemented=True),
    SourceInfo("phishtank", "PhishTank", "phishing", "phishing_intelligence", 0.85, (T.URL,),
               "Community-verified list of phishing URLs.",
               "The URL you analyze is sent to PhishTank.",
               "https://phishtank.org", env_var=PROVIDER_ENV_VARS["phishtank"], implemented=True),
    SourceInfo("urlscan", "urlscan.io", "phishing", "url_scan_intelligence", 0.70, (T.URL, T.DOMAIN),
               "Public scans of websites, including how a page looked and behaved.",
               "The URL or domain you analyze is sent to urlscan.io.",
               "https://urlscan.io", env_var=PROVIDER_ENV_VARS["urlscan"], implemented=True),
    SourceInfo("safebrowsing", "Google Safe Browsing", "phishing", "browser_safety_intelligence", 0.90, (T.URL,),
               "Google's lists of unsafe websites.",
               "The URL you analyze is sent to Google.",
               "https://safebrowsing.google.com", env_var=PROVIDER_ENV_VARS["safebrowsing"], implemented=True),
    SourceInfo("hibp_passwords", "HIBP Pwned Passwords", "password", "password_exposure", 0.95, (T.PASSWORD,),
               "Checks whether a password appeared in known data breaches using k-anonymity.",
               "Only the first 5 characters of the password's SHA-1 hash leave this computer. "
               "The password itself is never sent.",
                "https://haveibeenpwned.com/API/v3#PwnedPasswords",
               env_var=None, implemented=True),
    SourceInfo("circl_hashlookup", "CIRCL Hashlookup", "file", "known_file_intelligence", 0.80, HASHES,
               "Identifies files that are known, such as common software, by their hash.",
               "The file hash (not the file) is sent to CIRCL.",
                "https://www.circl.lu/services/hashlookup/",
               env_var=None, implemented=True),
    SourceInfo("malwarebazaar", "MalwareBazaar", "malware", "malware_intelligence", 0.90, HASHES,
               "Database of malware samples shared by researchers, run by abuse.ch.",
               "The file hash (not the file) is sent to abuse.ch.",
                "https://bazaar.abuse.ch", env_var=PROVIDER_ENV_VARS["malwarebazaar"], implemented=True),
    SourceInfo("virustotal", "VirusTotal", "multi", "multi_engine_intelligence", 0.85,
               (T.URL, T.DOMAIN, T.IPV4, T.IPV6, *HASHES),
               "Results from many security engines combined.",
               "The URL, domain, IP address or file hash you analyze is sent to VirusTotal.",
               "https://www.virustotal.com", env_var=PROVIDER_ENV_VARS["virustotal"], implemented=True),
    SourceInfo("ipinfo", "IPinfo", "network", "ip_intelligence", 0.80, (T.IPV4, T.IPV6, T.DOMAIN),
               "Location, network owner and ASN for IP addresses.",
               "The IP address you analyze is sent to IPinfo.",
                "https://ipinfo.io", env_var=PROVIDER_ENV_VARS["ipinfo"], implemented=True),
    SourceInfo("circl_vuln", "CIRCL Vulnerability-Lookup", "vulnerability", "vulnerability_intelligence", 0.90,
               (T.CVE,),
               "Public vulnerability records (CVEs) with severity and references.",
               "The CVE identifier you look up is sent to CIRCL.",
                "https://vulnerability.circl.lu",
               env_var=None, implemented=True),
]

_BY_KEY = {s.key: s for s in SOURCES}


class ProviderRegistry:
    """Holds the catalog plus any registered adapter classes."""

    def __init__(self, settings: Settings, db: Database) -> None:
        self.settings = settings
        self.db = db
        self._adapters: dict[str, Type[ThreatIntelProvider]] = {}

    def register(self, adapter: Type[ThreatIntelProvider]) -> None:
        if adapter.info.key not in _BY_KEY:
            raise ValueError(f"Unknown source key: {adapter.info.key}")
        self._adapters[adapter.info.key] = adapter

    def adapter(self, key: str) -> Optional[Type[ThreatIntelProvider]]:
        return self._adapters.get(key)

    def disabled_keys(self) -> set[str]:
        return set(self.db.get_setting("disabled_sources", []) or [])

    def set_enabled(self, key: str, enabled: bool) -> None:
        if key not in _BY_KEY:
            raise KeyError(key)
        disabled = self.disabled_keys()
        disabled.discard(key) if enabled else disabled.add(key)
        self.db.set_setting("disabled_sources", sorted(disabled))

    def describe_all(self) -> list[dict[str, Any]]:
        health = self.db.get_source_health()
        disabled = self.disabled_keys()
        return [self._describe(info, health.get(info.key), info.key in disabled) for info in SOURCES]

    def _describe(self, info: SourceInfo, health: Optional[dict], user_disabled: bool) -> dict[str, Any]:
        implemented = info.implemented and info.key in self._adapters
        key_set = self.settings.has_key(info.key) if info.env_var else None
        checked_at = latency = None
        if user_disabled:
            state, reason, detail = ProviderState.DISABLED, "user_disabled", "Turned off in CyberShield X."
        elif info.env_var and not key_set:
            state, reason = ProviderState.NOT_CONFIGURED, "no_key"
            detail = f"Add {info.env_var} to your .env file to enable this source."
        elif not implemented:
            state, reason, detail = ProviderState.DISABLED, "not_built", "This source's adapter has not been built yet."
        elif health:
            state, reason = ProviderState(health["state"]), "health_check"
            detail, checked_at, latency = health["message"], health["checked_at"], health["latency_ms"]
        else:
            state, reason, detail = ProviderState.UNCHECKED, "unchecked", "Configured. Not checked yet."
        return {
            "key": info.key, "name": info.name, "category": info.category,
            "default_reliability": info.default_reliability,
            "indicator_types": [t.value for t in info.indicator_types],
            "description": info.description, "data_sent": info.data_sent, "homepage": info.homepage,
            "requires_key": info.env_var is not None, "key_set": key_set, "env_var": info.env_var,
            "implemented": implemented, "user_disabled": user_disabled,
            "state": state.value, "reason": reason, "detail": detail, "checked_at": checked_at, "latency_ms": latency,
        }
