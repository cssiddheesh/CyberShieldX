"""IPinfo adapter (Lite tier: country + ASN, unlimited free requests).

Docs: https://ipinfo.io/developers/lite-api
  GET https://api.ipinfo.io/lite/{ip}?token=$TOKEN
  -> {ip, asn, as_name, as_domain, country_code, country, continent_code, continent}
Token required (IPINFO_TOKEN). Domains are resolved to an IP locally first so
the only data sent out is the resulting address; resolution failures are
reported, never raised.
"""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.intelligence.base import (
    HealthResult, ProviderResult, SourceInfo, ThreatIntelProvider,
)
from app.models.evidence import Evidence, IndicatorType, ProviderState, ResultOrigin

INFO = SourceInfo(
    key="ipinfo", name="IPinfo", category="network",
    source_type="ip_intelligence", default_reliability=0.80,
    indicator_types=(IndicatorType.IPV4, IndicatorType.IPV6, IndicatorType.DOMAIN),
    description="Location, network owner and ASN for IP addresses.",
    data_sent="The IP address you analyze is sent to IPinfo.",
    homepage="https://ipinfo.io", env_var="IPINFO_TOKEN",
    implemented=True,
)

LITE_URL = "https://api.ipinfo.io/lite"


def resolve_domain(domain: str, timeout: float = 4.0) -> str | None:
    """Best-effort local DNS resolution with a hard timeout. Never raises."""
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(socket.getaddrinfo, domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            infos = future.result(timeout=timeout)
        for info in infos:
            address = info[4][0]
            try:
                if not ipaddress.ip_address(address).is_private:
                    return address
            except ValueError:
                continue
        return infos[0][4][0] if infos else None
    except Exception:
        return None


class IpInfoProvider(ThreatIntelProvider):
    info = INFO

    def check(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        token = self.settings.key("ipinfo")
        if not token:
            return ProviderResult(INFO.name, ProviderState.NOT_CONFIGURED,
                                  ResultOrigin.NOT_CONFIGURED, message="Add IPINFO_TOKEN to .env.")
        try:
            address = indicator
            if indicator_type == IndicatorType.DOMAIN:
                address = resolve_domain(indicator) or ""
                if not address:
                    evidence = [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                                         "Domain could not be resolved", "info", 0.7,
                                         "Local DNS resolution failed, so no IP context could be fetched. "
                                         "Check the spelling or try again later.",
                                         "https://ipinfo.io", "unavailable", ResultOrigin.PROVIDER_ERROR)]
                    return ProviderResult(INFO.name, ProviderState.UNAVAILABLE,
                                          ResultOrigin.PROVIDER_ERROR, evidence=evidence,
                                          message="Domain could not be resolved.")
            result = self.http.get(f"{LITE_URL}/{address}", params={"token": token})
            return self._interpret(indicator, indicator_type, result, resolved=address)
        except Exception:
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="IPinfo request failed.")

    def _interpret(self, indicator: str, indicator_type: IndicatorType, result,
                   resolved: str = "") -> ProviderResult:
        if result.error == "rate_limited":
            return ProviderResult(INFO.name, ProviderState.RATE_LIMITED,
                                  ResultOrigin.PROVIDER_ERROR, message="IPinfo rate limit reached.",
                                  latency_ms=result.latency_ms)
        if result.error in ("timeout", "network"):
            return ProviderResult(INFO.name, ProviderState.UNAVAILABLE,
                                  ResultOrigin.PROVIDER_ERROR, message="IPinfo could not be reached.",
                                  latency_ms=result.latency_ms)
        if not result.ok or not isinstance(result.data, dict):
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="IPinfo returned an unreadable response.",
                                  latency_ms=result.latency_ms)
        data = dict(result.data)
        if resolved and resolved != indicator:
            data["_resolved_ip"] = resolved
        evidence = self.normalize(indicator, indicator_type, data)
        return ProviderResult(INFO.name, ProviderState.AVAILABLE, ResultOrigin.LIVE,
                              evidence=evidence, message="IP context retrieved.",
                              latency_ms=result.latency_ms)

    def normalize(self, indicator: str, indicator_type: IndicatorType, response: Any) -> list[Evidence]:
        if not isinstance(response, dict):
            return []
        bits = []
        if response.get("_resolved_ip"):
            bits.append(f"resolves to {response['_resolved_ip']}")
        country = response.get("country") or response.get("country_code")
        if country:
            bits.append(f"country: {country}")
        asn = response.get("asn")
        owner = response.get("as_name") or response.get("org")
        if asn:
            bits.append(f"network: {asn}" + (f" ({owner})" if owner else ""))
        elif owner:
            bits.append(f"network: {owner}")
        detail = ("IP context: " + "; ".join(bits) + ".") if bits else "IPinfo returned a record with no context fields."
        detail += (" Context alone says nothing about malice; hosting networks and shared infrastructure "
                   "host both legitimate and abusive content.")
        return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                         "IP context retrieved", "info", 0.85,
                         detail, "https://ipinfo.io", "informational", ResultOrigin.LIVE)]

    def health_check(self) -> HealthResult:
        if not self.settings.key("ipinfo"):
            return HealthResult(ProviderState.NOT_CONFIGURED, "Add IPINFO_TOKEN to .env.")
        return HealthResult(ProviderState.UNCHECKED, "Configured. Not checked yet.")
