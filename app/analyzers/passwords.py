"""Account Security: local password strength analysis (PRD section 7.2).

Pure functions - no network. The plaintext password is analyzed in memory and
never stored: callers must not persist it, log it, or embed it in Evidence.
Exposure checking lives in the HIBP adapter (k-anonymity).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from app.models.evidence import Evidence, IndicatorType, ResultOrigin

SOURCE = "Password Analyzer"
SOURCE_TYPE = "local_password_analysis"
PLACEHOLDER = "[password - not stored]"

COMMON_PASSWORDS = frozenset({
    "password", "123456", "123456789", "qwerty", "abc123", "password1", "12345678",
    "111111", "123123", "12345", "1234567", "qwerty123", "admin", "letmein",
    "welcome", "monkey", "dragon", "football", "iloveyou", "princess",
})

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")


def _has_sequence(text: str) -> bool:
    lowered = text.lower()
    for i in range(len(lowered) - 2):
        a, b, c = (ord(lowered[i + j]) for j in range(3))
        if (b == a + 1 and c == b + 1) or (b == a - 1 and c == b - 1):
            return True
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 2):
            if row[i:i + 3] in lowered or row[i:i + 3][::-1] in lowered:
                return True
    return False


def _estimate_bits(password: str) -> float:
    """Rough entropy estimate from the observed character pool."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    if pool <= 1:
        return 0.0
    raw = len(password) * math.log2(pool)
    # predictable structure discounts the theoretical value
    if _has_sequence(password):
        raw *= 0.6
    if re.search(r"(.)\1{2,}", password):
        raw *= 0.7
    return round(raw, 1)


def analyze_password(password: str) -> dict[str, Any]:
    """Analyze password strength locally. Returns a JSON-serializable dict."""
    password = password if isinstance(password, str) else ""
    length = len(password)
    classes = {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"[0-9]", password)),
        "symbols": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }
    diversity = sum(classes.values())
    repeated = bool(re.search(r"(.)\1{2,}", password))
    sequence = _has_sequence(password) if length >= 3 else False
    common = password.lower() in COMMON_PASSWORDS
    variety = len(set(password))
    bits = _estimate_bits(password)

    findings: list[dict[str, Any]] = []

    def add(id_: str, title: str, detail: str, severity: str, weight: int, confidence: float):
        findings.append({"id": id_, "title": title, "detail": detail,
                         "severity": severity, "weight": weight, "confidence": confidence})

    if length == 0:
        add("empty", "Password is empty", "An empty password offers no protection.", "critical", 40, 1.0)
    elif length < 8:
        add("too_short", f"Very short password ({length} characters)",
            "Short passwords fall quickly to guessing and brute force. Use at least 12-14 characters.",
            "high", 30, 0.9)
    elif length < 12:
        add("short", f"Short password ({length} characters)",
            "Below 12 characters leaves little margin. Longer passphrases resist guessing far better.",
            "medium", 15, 0.8)

    if length and diversity <= 1:
        add("single_class", "Only one character type used",
            "Mixing upper/lowercase, digits and symbols enlarges the search space.", "medium", 12, 0.8)
    elif length and diversity == 2:
        add("two_classes", "Only two character types used",
            "Adding a third character type strengthens the password.", "low", 5, 0.7)

    if common:
        add("common_password", "Extremely common password",
            "This exact password sits atop every attacker wordlist; it is guessed in seconds.",
            "critical", 40, 0.98)
    if repeated:
        add("repeated_chars", "Repeated characters",
            "Runs like 'aaa' shrink the effective search space.", "low", 5, 0.7)
    if sequence:
        add("sequence", "Predictable sequence detected",
            "Sequences like 'abc', '123' or 'qwe' are tried early by guessing tools.", "medium", 12, 0.75)
    if length and variety <= max(2, length // 3):
        add("low_variety", "Low character variety",
            "Reusing a small set of characters makes the password more guessable.", "low", 6, 0.6)

    # strength score 0-100 from bits + structure, then category
    score = max(0, min(100, int(bits * 1.4)))
    if common:
        score = min(score, 10)  # most-guessed passwords are effectively worthless
    elif length < 8:
        score = min(score, 20)
    if length >= 16 and diversity >= 3 and not sequence and not common:
        score = max(score, 80)
    category = ("Very weak" if score < 20 else "Weak" if score < 40 else
                "Fair" if score < 60 else "Strong" if score < 80 else "Very strong")

    evidence = [Evidence(
        PLACEHOLDER, IndicatorType.PASSWORD, SOURCE, SOURCE_TYPE,
        item["title"], item["severity"], item["confidence"], item["detail"],  # type: ignore[arg-type]
        "", "detected", ResultOrigin.LOCAL) for item in findings]
    if not findings:
        evidence.append(Evidence(
            PLACEHOLDER, IndicatorType.PASSWORD, SOURCE, SOURCE_TYPE,
            "Good local strength characteristics", "info", 0.7,
            "Length, character mix and unpredictability look solid. Strength alone says nothing "
            "about breach exposure - check that separately.",
            "", "informational", ResultOrigin.LOCAL))

    return {
        "length": length,
        "diversity": diversity,
        "classes": classes,
        "unique_chars": variety,
        "estimated_bits": bits,
        "strength_score": score,
        "strength_category": category,
        "is_common": common,
        "has_sequence": sequence,
        "has_repeats": repeated,
        "indicators": findings,
        "evidence": [e.to_dict() for e in evidence],
        "local_weights": [{"id": f["id"], "weight": f["weight"], "severity": f["severity"]}
                          for f in findings],
    }


def assess_password_risk(local: dict[str, Any], exposed_count: int | None,
                         exposure_available: bool) -> dict[str, Any]:
    """Risk for passwords: weak strength and breach exposure compound.

    exposed_count None = exposure source unavailable (confidence drops).
    """
    contributions: list[dict[str, Any]] = []
    score = 0
    if local["strength_category"] in ("Very weak",):
        score += 45
        contributions.append({"source": SOURCE, "points": 45,
                              "detail": "Password strength is Very weak (+45)."})
    elif local["strength_category"] == "Weak":
        score += 30
        contributions.append({"source": SOURCE, "points": 30,
                              "detail": "Password strength is Weak (+30)."})
    elif local["strength_category"] == "Fair":
        score += 12
        contributions.append({"source": SOURCE, "points": 12,
                              "detail": "Password strength is only Fair (+12)."})
    else:
        contributions.append({"source": SOURCE, "points": 0,
                              "detail": "Local strength is Strong or better (+0)."})

    if exposed_count and exposed_count > 0:
        extra = 40 if exposed_count >= 1000 else 30
        score += extra
        contributions.append({"source": "HIBP Pwned Passwords", "points": extra,
                              "detail": f"Seen {exposed_count:,} times in breaches (+{extra}). "
                                        "Attackers automate breached-password reuse."})
    elif exposure_available:
        contributions.append({"source": "HIBP Pwned Passwords", "points": 0,
                              "detail": "Not present in the breach corpus (+0)."})
    else:
        contributions.append({"source": "Risk Engine", "points": 0,
                              "detail": "Exposure could not be checked; strength alone sets the score."})

    score = max(0, min(100, score))
    if score >= 80:
        verdict, summary = "critical", ("This password is unsafe: it is weak and/or publicly breached. "
                                        "Change it everywhere it is used.")
    elif score >= 50:
        verdict, summary = "at_risk", ("This password has a real problem - breach exposure or weak structure. "
                                       "Replace it with a long unique passphrase.")
    elif score >= 25:
        verdict, summary = "uncertain", ("Usable but improvable. A longer, unique passphrase plus a password "
                                        "manager removes the remaining risk.")
    else:
        verdict, summary = "strong", ("Strong and unbreached as far as can be checked. Keep it unique per site.")

    confidence = 0.9 if exposure_available else 0.6
    return {"score": score, "verdict": verdict, "summary": summary,
            "confidence": confidence,
            "confidence_label": ("High" if confidence >= 0.7 else "Moderate"),
            "level": ("Critical" if score >= 80 else "High" if score >= 60 else
                      "Moderate" if score >= 40 else "Low" if score >= 20 else "Minimal"),
            "contributions": contributions,
            "exposed_count": exposed_count,
            "exposure_available": exposure_available}
