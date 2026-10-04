"""Phishing/URL provider adapters, one per documented public API.

Verified against official documentation (Oct 2026):
- URLhaus:  POST https://urlhaus-api.abuse.ch/v1/url/  form {url}, header Auth-Key.
            query_status "ok" = record, "no_results" = none. (abuse.ch / GitHub abusech/URLhaus)
- PhishTank: POST https://checkurl.phishtank.com/checkurl/  form {url, format: json,
             app_key?}, descriptive User-Agent required. results.in_database (+verified/valid).
             (phishtank.com/api_info.php)
- urlscan.io: GET https://urlscan.io/api/v1/search/?q=page.url:"..." header Api-Key.
             Read-only search; scan submission is intentionally not used. (docs.urlscan.io)
- Google Safe Browsing v4: POST .../v4/threatMatches:find?key=KEY with threatInfo body.
- VirusTotal v3: GET https://www.virustotal.com/api/v3/urls/{b64url_nopad} header x-apikey.

Every adapter must never raise: failures become a ProviderResult with the
appropriate state (NOT_CONFIGURED / RATE_LIMITED / UNAVAILABLE / ERROR).
"""
from app.intelligence.providers.circlvuln import CirclVulnProvider
from app.intelligence.providers.hashlookup import CirclHashlookupProvider
from app.intelligence.providers.hibp import HibpPasswordsProvider
from app.intelligence.providers.ipinfo import IpInfoProvider
from app.intelligence.providers.malwarebazaar import MalwareBazaarProvider
from app.intelligence.providers.phishtank import PhishTankProvider
from app.intelligence.providers.safebrowsing import SafeBrowsingProvider
from app.intelligence.providers.urlhaus import UrlHausProvider
from app.intelligence.providers.urlscan import UrlScanProvider
from app.intelligence.providers.virustotal import VirusTotalUrlProvider

PHISHING_ADAPTERS = (
    UrlHausProvider,
    PhishTankProvider,
    UrlScanProvider,
    SafeBrowsingProvider,
    VirusTotalUrlProvider,
)

INTEL_ADAPTERS = (
    HibpPasswordsProvider,
    CirclHashlookupProvider,
    MalwareBazaarProvider,
    CirclVulnProvider,
    IpInfoProvider,
)

ALL_ADAPTERS = PHISHING_ADAPTERS + INTEL_ADAPTERS

__all__ = ["PHISHING_ADAPTERS", "INTEL_ADAPTERS", "ALL_ADAPTERS", "UrlHausProvider", "PhishTankProvider",
           "UrlScanProvider", "SafeBrowsingProvider", "VirusTotalUrlProvider",
           "HibpPasswordsProvider", "CirclHashlookupProvider", "MalwareBazaarProvider",
           "CirclVulnProvider", "IpInfoProvider"]
