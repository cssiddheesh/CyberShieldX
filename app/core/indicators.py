"""Indicator identification for the Universal Analyzer (PRD section 8).

Pure functions - no network access. Analysis of the indicator happens elsewhere.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.models.evidence import IndicatorType

MAX_INDICATOR_LENGTH = 2048

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,19}$", re.IGNORECASE)
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

# Where each indicator type is analyzed (module key from app.core.modules).
MODULE_FOR_TYPE = {
    IndicatorType.URL: "phishing",
    IndicatorType.DOMAIN: "network",
    IndicatorType.IPV4: "network",
    IndicatorType.IPV6: "network",
    IndicatorType.MD5: "files",
    IndicatorType.SHA1: "files",
    IndicatorType.SHA256: "files",
    IndicatorType.CVE: "vulnerabilities",
}


@dataclass
class Identification:
    original: str
    normalized: str
    indicator_type: IndicatorType
    module: str | None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "normalized": self.normalized,
            "indicator_type": self.indicator_type.value,
            "module": self.module,
            "notes": self.notes,
        }


def refang(value: str) -> tuple[str, bool]:
    """Undo common 'defanging' (hxxp://, example[.]com) used when sharing indicators."""
    original = value
    value = re.sub(r"^hxxp", "http", value, flags=re.IGNORECASE)
    value = value.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    value = value.replace("[://]", "://").replace("[at]", "@")
    return value, value != original


def is_valid_hostname(host: str) -> bool:
    host = host.rstrip(".")
    if not host or len(host) > 253 or "." not in host:
        return False
    labels = host.split(".")
    if not all(_LABEL.match(label) for label in labels):
        return False
    # the final label (TLD) must not be purely numeric, otherwise it is an IPv4-like string
    return not labels[-1].isdigit()


def identify(raw: str) -> Identification:
    """Classify user input as URL, domain, IP, hash, CVE or unknown."""
    original = raw if isinstance(raw, str) else ""
    text = original.strip()
    notes: list[str] = []

    if not text:
        return Identification(original, "", IndicatorType.UNKNOWN, None, ["Input is empty."])
    if len(text) > MAX_INDICATOR_LENGTH:
        return Identification(original[:80], "", IndicatorType.UNKNOWN, None,
                              [f"Input is longer than {MAX_INDICATOR_LENGTH} characters."])
    if any(ch.isspace() for ch in text):
        return Identification(original, text, IndicatorType.UNKNOWN, None,
                              ["Input contains spaces. For longer writing use the Text Analyzer."])

    text, was_defanged = refang(text)
    if was_defanged:
        notes.append("Defanged indicator detected and restored for analysis.")

    # hashes
    if _HEX.match(text):
        kind = {32: IndicatorType.MD5, 40: IndicatorType.SHA1, 64: IndicatorType.SHA256}.get(len(text))
        if kind:
            return Identification(original, text.lower(), kind, MODULE_FOR_TYPE[kind], notes)

    # CVE
    if _CVE.match(text):
        return Identification(original, text.upper(), IndicatorType.CVE, "vulnerabilities", notes)

    # IP addresses (brackets allowed for IPv6)
    candidate = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    try:
        ip = ipaddress.ip_address(candidate)
        kind = IndicatorType.IPV4 if ip.version == 4 else IndicatorType.IPV6
        return Identification(original, str(ip), kind, MODULE_FOR_TYPE[kind], notes)
    except ValueError:
        pass

    # URLs (explicit scheme, or something that looks like host/path)
    if _SCHEME.match(text):
        scheme = text.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            return Identification(original, text, IndicatorType.UNKNOWN, None,
                                  [f"Only http and https links are analyzed (found '{scheme}')."])
        if not urlsplit(text).hostname:
            return Identification(original, text, IndicatorType.UNKNOWN, None, ["The link has no host name."])
        return Identification(original, text, IndicatorType.URL, "phishing", notes)

    if "/" in text or "?" in text or "#" in text:
        probe = urlsplit("http://" + text)
        host = probe.hostname or ""
        if host and (is_valid_hostname(host) or _is_ip(host)):
            notes.append("No scheme given; analyzed as an http(s) link.")
            return Identification(original, text, IndicatorType.URL, "phishing", notes)

    if is_valid_hostname(text):
        return Identification(original, text.lower().rstrip("."), IndicatorType.DOMAIN, "network", notes)

    return Identification(original, text, IndicatorType.UNKNOWN, None,
                          ["Not recognized as a URL, domain, IP address, file hash or CVE ID."])


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
