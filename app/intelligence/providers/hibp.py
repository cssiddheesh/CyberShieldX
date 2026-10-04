"""HIBP Pwned Passwords adapter (k-anonymity).

Docs: https://haveibeenpwned.com/API/v3#PwnedPasswords
  GET https://api.pwnedpasswords.com/range/{first 5 chars of SHA-1, uppercase}
  -> 200 text/plain lines "SUFFIX:count". Free, no key, but a User-Agent is
  required (403 otherwise). Only the 5-char prefix leaves this computer; the
  suffix match happens locally. Non-matching lines are discarded immediately.
"""
from __future__ import annotations

import hashlib
from typing import Any

from app.intelligence.base import (
    HealthResult, ProviderResult, SourceInfo, ThreatIntelProvider,
)
from app.models.evidence import Evidence, IndicatorType, ProviderState, ResultOrigin

INFO = SourceInfo(
    key="hibp_passwords", name="HIBP Pwned Passwords", category="password",
    source_type="password_exposure", default_reliability=0.95,
    indicator_types=(IndicatorType.PASSWORD,),
    description="Checks whether a password appeared in known data breaches using k-anonymity.",
    data_sent="Only the first 5 characters of the password's SHA-1 hash leave this computer. "
              "The password itself is never sent.",
    homepage="https://haveibeenpwned.com/API/v3#PwnedPasswords",
    env_var=None, implemented=True,
)

RANGE_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "CyberShieldX/0.1 (educational defensive scanner)"


def sha1_upper(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


class HibpPasswordsProvider(ThreatIntelProvider):
    info = INFO

    def check(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        try:
            digest = sha1_upper(indicator)
            result = self.http.get(RANGE_URL + digest[:5], expect_json=False,
                                   headers={"User-Agent": USER_AGENT, "Add-Padding": "true"})
            return self._interpret(indicator, digest, result)
        except Exception:
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="Exposure check failed.")

    def _interpret(self, indicator: str, digest: str, result) -> ProviderResult:
        if result.error == "rate_limited":
            return ProviderResult(INFO.name, ProviderState.RATE_LIMITED,
                                  ResultOrigin.PROVIDER_ERROR,
                                  message="Pwned Passwords rate limit reached.", latency_ms=result.latency_ms)
        if result.error in ("timeout", "network"):
            return ProviderResult(INFO.name, ProviderState.UNAVAILABLE,
                                  ResultOrigin.PROVIDER_ERROR,
                                  message="Pwned Passwords could not be reached.", latency_ms=result.latency_ms)
        if result.status == 403:
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="Pwned Passwords refused the request.", latency_ms=result.latency_ms)
        if not result.ok or not isinstance(result.data, str):
            return ProviderResult(INFO.name, ProviderState.ERROR, ResultOrigin.PROVIDER_ERROR,
                                  message="Pwned Passwords returned an unreadable response.",
                                  latency_ms=result.latency_ms)
        # The plaintext indicator must never be embedded in stored evidence.
        evidence = self.normalize("[password - not stored]", IndicatorType.PASSWORD,
                                  {"digest": digest, "body": result.data})
        exposed = any(e.status.value == "detected" for e in evidence)
        return ProviderResult(INFO.name, ProviderState.AVAILABLE, ResultOrigin.LIVE,
                              evidence=evidence,
                              message="This password appears in known breaches." if exposed
                              else "No breach record for this password.",
                              latency_ms=result.latency_ms)

    def normalize(self, indicator: str, indicator_type: IndicatorType, response: Any) -> list[Evidence]:
        if not isinstance(response, dict):
            return []
        digest = str(response.get("digest", ""))
        suffix = digest[5:]
        count = 0
        for line in str(response.get("body", "")).splitlines():
            head, _, tail = line.strip().partition(":")
            if head.upper() == suffix and tail.strip().isdigit():
                count = int(tail.strip())
                break
        # every non-matching suffix is discarded here and never stored
        if count > 0:
            sev = "critical" if count >= 1000 else "high"
            return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                             f"Password exposed in breaches ({count:,} sightings)", sev, 0.95,  # type: ignore[arg-type]
                             f"This password's hash appears {count:,} times in the Pwned Passwords corpus. "
                             "Attackers try breached passwords first; change it everywhere it is reused.",
                             "https://haveibeenpwned.com/Passwords", "detected", ResultOrigin.LIVE)]
        return [Evidence(indicator, indicator_type, INFO.name, INFO.source_type,
                         "Password not found in breach corpus", "info", 0.8,
                         "The password's hash is absent from Pwned Passwords. It may still be weak - "
                         "see the local strength analysis.",
                         "https://haveibeenpwned.com/Passwords", "not_found", ResultOrigin.LIVE)]

    def health_check(self) -> HealthResult:
        return HealthResult(ProviderState.UNCHECKED, "No key needed. Not checked yet.")
