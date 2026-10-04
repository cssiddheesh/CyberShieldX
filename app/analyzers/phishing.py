"""PhishGuard local URL analysis engine (PRD section 7.1).

Pure functions - no network access, no Flask imports. Takes a URL string,
normalizes it (including defanged input), extracts structural features and
emits one Evidence object per finding plus an "all clear" informational
record when nothing suspicious is found.

Heuristics alone never declare a URL malicious (PRD 7.1); severities top out
at "high" and wording is probabilistic ("suggests", "may").
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from app.core.indicators import refang
from app.models.evidence import Evidence, IndicatorType, ResultOrigin

SOURCE = "PhishGuard Local"
SOURCE_TYPE = "local_url_analysis"

MAX_URL_LENGTH = 2048

# TLDs disproportionately abused for phishing/malware (internal heuristic list,
# not a blocklist verdict).
SUSPICIOUS_TLDS = frozenset({
    "zip", "mov", "top", "xyz", "click", "link", "country", "kim", "cricket",
    "science", "work", "party", "gq", "ml", "cf", "tk", "ga", "buzz", "fit",
    "rest", "review", "download", "stream",
})

# Well-known URL shorteners: the final destination is hidden, so flag as
# redirect-risk rather than as malicious.
SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bitly.com", "shorturl.at", "rb.gy", "cutt.ly", "rebrand.ly",
    "s.id", "lnkd.in",
})

# Keywords frequently abused in phishing paths/hosts. Weighted low individually.
SUSPICIOUS_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "security", "banking", "payment",
    "paypal", "apple-id", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "google", "wallet", "crypto", "invoice", "refund",
    "suspended", "locked", "confirm", "password", "credential", "free",
    "winner", "prize", "urgent",
)

# Brands commonly impersonated; flagged only together with a mismatched host
# (e.g. brand string in path while domain is unrelated).
KNOWN_BRANDS = (
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "binance", "coinbase", "hsbc", "chase", "wellsfargo",
    "dhl", "fedex", "ups",
)

SUSPICIOUS_QUERY_KEYS = frozenset({
    "redirect", "redirect_url", "redirecturl", "redir", "return", "returnurl",
    "return_url", "next", "dest", "destination", "continue", "url", "goto",
    "forward", "target", "rurl", "u",
})

UNUSUAL_PORTS = {22, 23, 25, 445, 3306, 3389, 5900, 8081, 8444}

# Cyrillic/Greek lookalikes for latin letters (homograph detection).
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ո": "n", "ԝ": "w", "ԛ": "q",
    "ɡ": "g", "ӏ": "l", "κ": "k", "ν": "v", "μ": "u", "τ": "t", "β": "b",
    "ρ": "p", "ο": "o", "ε": "e", "α": "a",
}


@dataclass
class UrlFeatures:
    original: str
    normalized_url: str
    was_defanged: bool
    scheme: str
    host: str
    domain: str
    port: int | None
    uses_ip_host: bool
    is_ipv6_host: bool
    uses_https: bool
    uses_punycode: bool
    has_non_ascii_host: bool
    url_length: int
    host_length: int
    path_depth: int
    subdomain_count: int
    tld: str
    entropy: float
    raw_host: str = ""
    had_at_sign: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class UrlIndicator:
    id: str
    title: str
    detail: str
    severity: str  # info | low | medium | high
    weight: int    # risk-engine contribution (0-40)
    confidence: float


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return round(-sum((n / length) * math.log2(n / length) for n in counts.values()), 3)


def normalize_url(raw: str) -> tuple[str, bool]:
    """Refang, trim, add a default scheme and strip credentials/fragments."""
    text = (raw or "").strip()
    text, was_defanged = refang(text)
    text = text.strip("<>\"' \t\r\n")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", text, re.IGNORECASE):
        text = "http://" + text
    try:
        parts = urlsplit(text)
    except ValueError:
        return text[:MAX_URL_LENGTH], was_defanged
    host = parts.hostname or ""
    # Rebuild without username/password/fragment; lowercase scheme+host.
    netloc = host.lower()
    if parts.port:
        netloc += f":{parts.port}"
    rebuilt = urlunsplit((parts.scheme.lower(), netloc, parts.path or "", parts.query or "", ""))
    return rebuilt[:MAX_URL_LENGTH], was_defanged


def extract_features(raw: str) -> UrlFeatures:
    original = raw if isinstance(raw, str) else ""
    normalized, was_defanged = normalize_url(original)
    notes: list[str] = []
    if was_defanged:
        notes.append("Defanged indicator was restored before analysis.")
    # '@' must be detected from the raw input: normalize_url() strips userinfo
    # (keeping only the real host), so by the time we parse `normalized` it is gone.
    raw_text, _ = refang((raw if isinstance(raw, str) else "").strip())
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw_text, re.IGNORECASE):
        raw_text = "http://" + raw_text
    try:
        had_at_sign = "@" in urlsplit(raw_text).netloc
    except ValueError:
        had_at_sign = "@" in raw_text
    if had_at_sign:
        notes.append("The link contains '@' in its authority section.")
    try:
        parts = urlsplit(normalized)
    except ValueError:
        return UrlFeatures(original, normalized, was_defanged, "", "", "", None,
                           False, False, False, False, False, len(normalized),
                           0, 0, 0, "", 0.0, "", had_at_sign, notes)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    # Raw authority (before IDNA decoding/userinfo stripping) for '@' and
    # confusable checks: urlsplit().hostname decodes punycode and drops userinfo.
    raw_netloc = parts.netloc.lower()
    raw_host = raw_netloc.rsplit("@", 1)[-1].split("]")[0].split(":")[0].strip("[]")
    uses_ip_host = False
    is_ipv6 = False
    if host:
        try:
            ip = ipaddress.ip_address(host)
            uses_ip_host = True
            is_ipv6 = ip.version == 6
        except ValueError:
            pass
    labels = host.split(".") if host and not uses_ip_host else []
    tld = labels[-1] if labels else ""
    path = parts.path or ""
    depth = len([seg for seg in path.split("/") if seg])
    subdomain_count = max(0, len(labels) - 2) if len(labels) >= 2 else 0
    uses_punycode = "xn--" in host or "xn--" in raw_host
    has_non_ascii = any(ord(ch) > 127 for ch in host + raw_host)
    entropy = shannon_entropy(normalized.lower())
    return UrlFeatures(
        original=original, normalized_url=normalized, was_defanged=was_defanged,
        scheme=scheme, host=host, domain=host, port=port,
        raw_host=raw_host, had_at_sign=had_at_sign,
        uses_ip_host=uses_ip_host, is_ipv6_host=is_ipv6,
        uses_https=scheme == "https", uses_punycode=uses_punycode,
        has_non_ascii_host=has_non_ascii, url_length=len(normalized),
        host_length=len(host), path_depth=depth,
        subdomain_count=subdomain_count, tld=tld, entropy=entropy, notes=notes,
    )


def _confusable_fold(host: str) -> tuple[str, list[str]]:
    folded, hits = [], []
    for ch in host:
        if ch in CONFUSABLES:
            folded.append(CONFUSABLES[ch])
            hits.append(ch)
        else:
            folded.append(ch)
    return "".join(folded), sorted(set(hits))


def detect_indicators(features: UrlFeatures) -> list[UrlIndicator]:
    found: list[UrlIndicator] = []
    f = features
    lowered_url = f.normalized_url.lower()

    if not f.host:
        found.append(UrlIndicator("no_host", "URL has no host name",
                                  "The link could not be parsed into a host name, so it cannot be checked.",
                                  "medium", 10, 0.9))
        return found

    if f.scheme and f.scheme not in ("http", "https"):
        found.append(UrlIndicator("unusual_scheme", f"Unusual URL scheme '{f.scheme}'",
                                  "Phishing and malware links sometimes use non-web schemes.",
                                  "low", 5, 0.6))

    if not f.uses_https:
        found.append(UrlIndicator(
            "no_https", "Page does not use HTTPS",
            "Data entered on a plain-http page can be read or modified in transit. "
            "Many legitimate sites use HTTPS, so its absence is a weak risk signal, not proof of harm.",
            "low", 5, 0.7))

    if f.uses_ip_host:
        found.append(UrlIndicator(
            "ip_host", "Link uses an IP address instead of a domain name",
            "Legitimate public websites rarely ask users to visit a bare IP address; "
            "phishing pages do this to avoid registering a recognizable domain.",
            "high", 25, 0.85))

    if f.uses_punycode or f.has_non_ascii_host:
        found.append(UrlIndicator(
            "idn_punycode", "Internationalized domain name (possible homograph)",
            "The domain uses punycode/non-Latin characters, which can be abused to build "
            "lookalike domains (e.g. swapping Latin 'a' for Cyrillic 'а').",
            "medium", 15, 0.7))
    folded, hits = _confusable_fold(f.raw_host or f.host)
    if hits:
        found.append(UrlIndicator(
            "homograph_chars", "Lookalike (confusable) characters in domain",
            f"The host contains non-Latin characters resembling Latin letters ({', '.join(hits)}); "
            f"visually it mimics '{folded}'. This is a known impersonation technique.",
            "high", 25, 0.8))

    if f.tld in SUSPICIOUS_TLDS:
        found.append(UrlIndicator(
            "suspicious_tld", f"Uncommon/high-abuse top-level domain '.{f.tld}'",
            "This ending is disproportionately used for phishing and malware delivery. "
            "Many legitimate sites use it too, so this is only a weak signal on its own.",
            "low", 8, 0.55))

    if f.url_length > 200:
        found.append(UrlIndicator(
            "long_url", f"Unusually long URL ({f.url_length} characters)",
            "Very long links can hide the real destination or carry injected payloads.",
            "medium" if f.url_length > 500 else "low",
            15 if f.url_length > 500 else 7, 0.6))
    if f.url_length > 1000:
        found[-1].detail += " Links over 1000 characters are rare outside of tracking or abuse."

    if f.entropy >= 4.5:
        found.append(UrlIndicator(
            "high_entropy", f"High-entropy URL ({f.entropy} bits/char)",
            "Random-looking strings (tokens, encoded blobs, DGAs) raise the randomness score. "
            "Legitimate tracking links can also look random.",
            "medium", 10, 0.55))

    if f.subdomain_count >= 3:
        found.append(UrlIndicator(
            "many_subdomains", f"Deep subdomain chain ({f.subdomain_count} levels)",
            "Extra subdomains can bury the real domain (e.g. bank.login.evil.example).",
            "medium", 12, 0.65))

    if f.host_length > 60:
        found.append(UrlIndicator(
            "long_host", f"Unusually long host name ({f.host_length} characters)",
            "Overlong host names are used to push the recognizable part out of view.",
            "low", 6, 0.55))

    if "%" in f.normalized_url or re.search(r"%[0-9a-fA-F]{2}", f.normalized_url):
        try:
            decoded = unquote(f.normalized_url)
            extra = " Decoding it reveals additional structure." if decoded != f.normalized_url else ""
        except Exception:
            extra = ""
        found.append(UrlIndicator(
            "encoded_chars", "URL contains percent-encoded characters",
            "Encoding can hide keywords or redirect targets from casual inspection." + extra,
            "low", 5, 0.6))

    if re.search(r"[^a-z0-9._~:/?#\[\]@!$&'()*+,;=%-]", lowered_url):
        # limit noise: only flag when combined with suspicious chars like ^ | ` { } \
        if re.search(r"[\^|`{}\\<>\"\s]", f.normalized_url):
            found.append(UrlIndicator(
                "suspicious_chars", "Suspicious characters in URL",
                "Characters rarely seen in legitimate links can indicate obfuscation.",
                "low", 5, 0.6))

    if f.had_at_sign:
        # userinfo or misleading authority part (detected pre-normalization:
        # normalization strips credentials, keeping only the real host)
        found.append(UrlIndicator(
            "at_sign", "URL contains '@' before the path",
            "Everything before '@' may be credentials while the real host follows it "
            "(e.g. http://trusted@evil.example).",
            "medium", 12, 0.75))

    host_no_dots = f.host.replace(".", "")
    if f.host.count(".") >= 1 and re.search(r"(.)\1{3,}", host_no_dots):
        found.append(UrlIndicator(
            "repeated_chars", "Repeated characters in host name",
            "Runs of the same character are uncommon in legitimate domains.",
            "low", 4, 0.5))

    if re.search(r"[0-9]{5,}", f.host):
        found.append(UrlIndicator(
            "digits_in_host", "Long digit runs in host name",
            "Auto-generated or lookalike domains often embed long numbers.",
            "low", 4, 0.5))

    if "-" in f.host and f.host.count("-") >= 3:
        found.append(UrlIndicator(
            "many_hyphens", "Many hyphens in host name",
            "Excessive hyphens are common in impersonating domains (e.g. secure-login-bank-example).",
            "low", 5, 0.55))

    if f.host in SHORTENERS or f.host.endswith(tuple("." + s for s in SHORTENERS)):
        found.append(UrlIndicator(
            "url_shortener", "Link uses a URL-shortening service",
            "Shorteners hide the final destination, so the link cannot be judged without resolving it. "
            "CyberShield X never follows redirects automatically.",
            "medium", 12, 0.8))

    query = (urlsplit(f.normalized_url).query or "").lower()
    if any(f"{k}=" in query for k in SUSPICIOUS_QUERY_KEYS) or "http" in query:
        found.append(UrlIndicator(
            "redirect_param", "Possible open-redirect parameter",
            "The link carries another URL inside its query string, a pattern used to bounce "
            "victims from a trusted-looking link to an attacker page.",
            "medium", 12, 0.6))

    if f.path_depth >= 5:
        found.append(UrlIndicator(
            "deep_path", f"Deep link path ({f.path_depth} levels)",
            "Unusually deep paths can bury malicious payloads or mimic real site structure.",
            "low", 4, 0.5))

    if f.port and (f.port in UNUSUAL_PORTS or f.port > 10000):
        found.append(UrlIndicator(
            "unusual_port", f"Unusual port :{f.port}",
            "Public websites normally use ports 80/443; odd ports are used by staging servers, "
            "proxies or malware panels.",
            "medium", 10, 0.65))

    path_query = (urlsplit(f.normalized_url).path + "?" + query).lower()
    hits = sorted({kw for kw in SUSPICIOUS_KEYWORDS if kw in path_query or kw in f.host})
    if hits:
        shown = ", ".join(hits[:6])
        found.append(UrlIndicator(
            "suspicious_keywords", f"Sensitive keywords in link ({shown})",
            "Words like login, verify or payment are used by both real login pages and phishing copies, "
            "so they raise attention without proving anything.",
            "low", min(10, 3 + 2 * len(hits)), 0.5))

    for brand in KNOWN_BRANDS:
        if brand in path_query and brand not in f.host:
            found.append(UrlIndicator(
                "brand_mismatch", f"Brand name '{brand}' appears outside the domain",
                f"The link mentions {brand} but is hosted on '{f.host}', which does not belong to that brand. "
                "This mismatch is a classic impersonation pattern.",
                "high", 25, 0.75))
            break

    return found


def _severity_for(indicator: UrlIndicator) -> str:
    return indicator.severity


def indicators_to_evidence(indicator_value: str, items: list[UrlIndicator]) -> list[Evidence]:
    evidence: list[Evidence] = []
    for item in items:
        evidence.append(Evidence(
            indicator=indicator_value[:2048],
            indicator_type=IndicatorType.URL,
            source=SOURCE,
            source_type=SOURCE_TYPE,
            finding=item.title,
            severity=item.severity,  # type: ignore[arg-type]
            confidence=item.confidence,
            evidence=item.detail,
            reference="",
            status="detected",
            origin=ResultOrigin.LOCAL,
        ))
    return evidence


def analyze_url(raw: str) -> dict[str, Any]:
    """Run the full local URL analysis. Returns a JSON-serializable dict."""
    features = extract_features(raw)
    indicators = detect_indicators(features)
    evidence = indicators_to_evidence(features.normalized_url or features.original, indicators)

    if not indicators:
        evidence.append(Evidence(
            indicator=features.normalized_url or features.original,
            indicator_type=IndicatorType.URL,
            source=SOURCE, source_type=SOURCE_TYPE,
            finding="No suspicious local indicators found",
            severity="info", confidence=0.6,
            evidence=("The link parses cleanly: standard ports, readable host, no encoded tricks, "
                      "no sensitive keywords and no impersonation patterns. This does not prove safety - "
                      "threat-intelligence databases may still hold a record."),
            reference="", status="informational", origin=ResultOrigin.LOCAL,
        ))

    return {
        "original": features.original[:2048],
        "normalized_url": features.normalized_url,
        "was_defanged": features.was_defanged,
        "scheme": features.scheme,
        "protocol": features.scheme,
        "host": features.host,
        "domain": features.domain,
        "port": features.port,
        "uses_https": features.uses_https,
        "uses_ip_host": features.uses_ip_host,
        "uses_punycode": features.uses_punycode,
        "url_length": features.url_length,
        "host_length": features.host_length,
        "path_depth": features.path_depth,
        "subdomain_count": features.subdomain_count,
        "tld": features.tld,
        "entropy": features.entropy,
        "notes": features.notes,
        "indicators": [
            {"id": i.id, "title": i.title, "detail": i.detail, "severity": _severity_for(i),
             "weight": i.weight, "confidence": i.confidence}
            for i in indicators
        ],
        "evidence": [e.to_dict() for e in evidence],
        "local_weights": [{"id": i.id, "weight": i.weight, "severity": i.severity} for i in indicators],
    }
