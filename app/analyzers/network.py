"""IP & Domain Intelligence: local classification (PRD section 7.4).

Pure functions - no network except best-effort local DNS (which the IPinfo
adapter also performs; this module only classifies what the indicator *is*).
"""
from __future__ import annotations

import ipaddress
from typing import Any

from app.models.evidence import Evidence, IndicatorType, ResultOrigin

SOURCE = "Network Analyzer"
SOURCE_TYPE = "local_network_analysis"


def classify_ip(value: str) -> dict[str, Any]:
    """Validate and classify an IP literal. Never raises."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return {"valid": False, "version": None, "flags": ["not an IP literal"]}
    flags: list[str] = []
    if ip.is_private:
        flags.append("private-use (LAN/VPN, not Internet-routable)")
    if ip.is_loopback:
        flags.append("loopback (this computer)")
    if ip.is_multicast:
        flags.append("multicast")
    if ip.is_reserved:
        flags.append("reserved")
    if ip.is_link_local:
        flags.append("link-local")
    if getattr(ip, "is_global", False):
        flags.append("globally routable")
    if ip.version == 4 and str(ip).startswith(("0.", "240.", "241.", "242.")):
        flags.append("special-use range")
    return {"valid": True, "version": ip.version, "compressed": ip.compressed,
            "flags": flags or ["ordinary address"]}


def analyze_network(indicator: str, indicator_type: IndicatorType) -> dict[str, Any]:
    """Local network-indicator analysis. Returns a JSON-serializable dict."""
    indicator = (indicator or "").strip()
    findings: list[dict[str, Any]] = []

    def add(id_: str, title: str, detail: str, severity: str, weight: int, confidence: float):
        findings.append({"id": id_, "title": title, "detail": detail,
                         "severity": severity, "weight": weight, "confidence": confidence})

    facts: dict[str, Any] = {"indicator": indicator, "type": indicator_type.value}
    if indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6):
        info = classify_ip(indicator)
        facts.update(info)
        if not info["valid"]:
            add("invalid_ip", "Invalid IP address",
                "The value does not parse as an IP address.", "info", 0, 0.9)
        elif "globally routable" not in info["flags"]:
            scope = ", ".join(info["flags"])
            add("non_routable", f"Non-routable address ({scope})",
                "Private, loopback or reserved addresses only exist inside local networks. "
                "They cannot host public phishing pages, but can appear in local attacks.",
                "info", 0, 0.9)
        else:
            add("routable", "Globally routable address",
                "A public address: remote servers, VPN exits, proxies or compromised hosts all share "
                "this shape. Reputation sources below add the security context.", "info", 0, 0.7)
    elif indicator_type == IndicatorType.DOMAIN:
        host = indicator.lower().rstrip(".")
        facts["hostname"] = host
        labels = host.split(".")
        facts["tld"] = labels[-1] if labels else ""
        facts["subdomain_count"] = max(0, len(labels) - 2)
        if facts["subdomain_count"] >= 4:
            add("many_subdomains", f"Deep subdomain chain ({facts['subdomain_count']} levels)",
                "Extra subdomains can bury the real domain.", "low", 6, 0.6)
        if "xn--" in host or any(ord(c) > 127 for c in host):
            add("idn_domain", "Internationalized domain name",
                "Non-Latin characters enable lookalike domains.", "medium", 12, 0.7)
    else:
        add("unsupported", "Unsupported indicator for this module",
            "Only IP addresses and domains are analyzed here.", "info", 0, 0.9)

    evidence = [Evidence(
        indicator, indicator_type, SOURCE, SOURCE_TYPE,
        item["title"], item["severity"], item["confidence"], item["detail"],  # type: ignore[arg-type]
        "", "detected" if item["weight"] else "informational", ResultOrigin.LOCAL)
        for item in findings]
    if not findings:
        evidence.append(Evidence(
            indicator, indicator_type, SOURCE, SOURCE_TYPE,
            "No suspicious local network indicators", "info", 0.6,
            "The address or domain parses cleanly. Local shape says nothing about reputation - "
            "intelligence sources below add context.",
            "", "informational", ResultOrigin.LOCAL))

    return {
        "facts": facts,
        "indicators": findings,
        "evidence": [e.to_dict() for e in evidence],
        "local_weights": [{"id": f["id"], "weight": f["weight"], "severity": f["severity"]}
                          for f in findings],
    }
