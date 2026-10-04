"""File Forensics: static hashing + metadata (PRD section 7.3).

Pure functions - no network, never executes anything. Operates on raw bytes
already validated and size-limited by the API layer. Only hashes and metadata
are returned; file contents never leave this module except as digests.
"""
from __future__ import annotations

import hashlib
import math
import mimetypes
from collections import Counter
from pathlib import PurePath
from typing import Any

from app.models.evidence import Evidence, IndicatorType, ResultOrigin

SOURCE = "File Forensics"
SOURCE_TYPE = "local_file_analysis"

# Extension -> expected MIME family, for mismatch hints (not verdicts).
EXECUTABLE_EXTS = frozenset({".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                              ".jar", ".apk", ".com", ".scr", ".pif", ".gadget", ".msc"})
ARCHIVE_EXTS = frozenset({".zip", ".rar", ".7z", ".tar", ".gz", ".cab"})
DOUBLE_EXT_RISK = frozenset({".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
                              ".com", ".pif", ".msi", ".dll"})

HASH_TYPES = {
    32: IndicatorType.MD5,
    40: IndicatorType.SHA1,
    64: IndicatorType.SHA256,
}


def hash_bytes(data: bytes) -> dict[str, str]:
    return {"md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:1_048_576]  # cap work on huge files
    counts = Counter(sample)
    length = len(sample)
    return round(-sum((n / length) * math.log2(n / length) for n in counts.values()), 3)


def analyze_file(data: bytes, filename: str) -> dict[str, Any]:
    """Static file analysis. Returns a JSON-serializable dict (no file bytes)."""
    data = data if isinstance(data, bytes) else b""
    name = (filename or "upload").strip()[:255] or "upload"
    suffix = PurePath(name).suffix.lower()
    digests = hash_bytes(data)
    size = len(data)
    entropy = shannon_entropy_bytes(data)
    mime, _ = mimetypes.guess_type(name)

    indicators: list[dict[str, Any]] = []

    def add(id_: str, title: str, detail: str, severity: str, weight: int, confidence: float):
        indicators.append({"id": id_, "title": title, "detail": detail,
                           "severity": severity, "weight": weight, "confidence": confidence})

    parts = PurePath(name).name.split(".")
    if len(parts) > 2 and f".{parts[-1].lower()}" in DOUBLE_EXT_RISK:
        add("double_extension", f"Suspicious double extension (.{parts[-2]}.{parts[-1]})",
            "Files like 'invoice.pdf.exe' use a harmless-looking middle extension to hide executables.",
            "high", 25, 0.8)
    if suffix in EXECUTABLE_EXTS:
        add("executable_type", f"Executable file type ({suffix or 'none'})",
            "Executables can perform any action once run. Handle with care and verify the source.",
            "medium", 12, 0.8)
    if size == 0:
        add("empty_file", "File is empty",
            "An empty file carries no content to analyze; hashes are of zero bytes.", "info", 0, 0.9)
    elif size < 200 and suffix in EXECUTABLE_EXTS:
        add("tiny_executable", f"Unusually small executable ({size} bytes)",
            "Real executables are rarely this small; tiny droppers and stubs abuse this shape.",
            "medium", 12, 0.6)
    if entropy >= 7.5 and size > 1024:
        add("high_entropy", f"High entropy ({entropy} bits/byte)",
            "Packed, encrypted or compressed content looks random. Malware often hides this way, "
            "but so do legitimate archives and installers.", "medium", 10, 0.55)
    if entropy <= 1.0 and size > 1024:
        add("low_entropy", f"Very low entropy ({entropy} bits/byte)",
            "Highly repetitive content (padding, blank images). Occasionally used to pad malware, "
            "usually benign.", "low", 3, 0.4)

    evidence = [Evidence(
        digests["sha256"], IndicatorType.SHA256, SOURCE, SOURCE_TYPE,
        item["title"], item["severity"], item["confidence"], item["detail"],  # type: ignore[arg-type]
        "", "detected", ResultOrigin.LOCAL) for item in indicators if item["weight"] > 0 or True]
    if not indicators:
        evidence.append(Evidence(
            digests["sha256"], IndicatorType.SHA256, SOURCE, SOURCE_TYPE,
            "No suspicious static indicators", "info", 0.6,
            "Size, type, naming and randomness look ordinary. Static analysis cannot detect novel "
            "or well-hidden malware - intelligence lookups add the next layer.",
            "", "informational", ResultOrigin.LOCAL))

    return {
        "filename": name,
        "extension": suffix,
        "size_bytes": size,
        "mime_guess": mime or "unknown",
        "hashes": digests,
        "entropy": entropy,
        "indicators": indicators,
        "evidence": [e.to_dict() for e in evidence],
        "local_weights": [{"id": i["id"], "weight": i["weight"], "severity": i["severity"]}
                          for i in indicators],
    }


def identify_hash_type(value: str) -> IndicatorType | None:
    text = (value or "").strip().lower()
    if all(c in "0123456789abcdef" for c in text):
        return HASH_TYPES.get(len(text))
    return None
