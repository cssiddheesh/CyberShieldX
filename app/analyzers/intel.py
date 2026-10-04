"""Phase-3 scan pipelines: password, file/hash, network, CVE.

Each runner follows Detect -> Correlate -> Explain -> Report, persists a
ScanRecord and returns the report dict. Framework-agnostic (no Flask).

Password privacy: the plaintext password lives only in this call's memory.
It is hashed (SHA-1, for k-anonymity) inside the HIBP adapter, only the
5-char prefix leaves the machine, and stored records carry the placeholder.
"""
from __future__ import annotations

from typing import Any

from app.analyzers.files import analyze_file, identify_hash_type
from app.analyzers.network import analyze_network
from app.analyzers.passwords import analyze_password, assess_password_risk
from app.analyzers.pipeline import ensure_adapters_registered, reliability_map
from app.analyzers.vulnerabilities import (
    LOCAL_REFERENCE, analyze_cve, parse_cve, risk_for_cvss,
)
from app.ai.analyst import build_assessment
from app.analyzers.textstats import REQUIRED_LIMITATION, analyze_text
from app.analyzers.media import analyze_image, identify_image
from app.models.evidence import (
    Evidence, IndicatorType, ResultOrigin, ScanRecord, confidence_label, risk_level_for, utc_now,
)
from app.core.config import Settings
from app.database.db import Database
from app.correlation.engine import correlate, note_provider_gaps
from app.intelligence.service import IntelService
from app.correlation.risk import assess_risk
from app.intelligence.registry import ProviderRegistry
from app.reports.builder import build_generic_report

EICAR_SHA256 = "275a021bbfb6489e5a62c763859df87b4c8e1534458e96e041e9e209f98d882"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


# ------------------------------------------------------------------ password

def run_password_scan(password: str, settings: Settings, db: Database,
                       registry: ProviderRegistry, demo: bool = False) -> dict[str, Any]:
    if not isinstance(password, str) or not password:
        raise ValueError("Password is empty.")
    if len(password) > 512:
        raise ValueError("Password is longer than 512 characters.")
    ensure_adapters_registered(registry)

    local = analyze_password(password)
    evidence: list[Evidence] = [Evidence.from_dict(e) for e in local["evidence"]]
    provider_rows: list[dict[str, Any]] = []
    exposed: int | None = None
    exposure_available = False

    if demo:
        evidence.append(Evidence(
            "[password - not stored]", IndicatorType.PASSWORD, "HIBP Pwned Passwords",
            "password_exposure", "Password exposed in breaches (3 sightings)", "high", 0.9,
            "DEMONSTRATION DATA: pretend breach exposure used to show the full workflow.",
            "https://haveibeenpwned.com/Passwords", "detected", ResultOrigin.DEMO))
        provider_rows = [{"key": "hibp_passwords", "name": "HIBP Pwned Passwords",
                          "state": "AVAILABLE", "origin": "DEMO_DATA",
                          "message": "Demonstration data.", "latency_ms": 0, "evidence_count": 1}]
        exposed, exposure_available = 3, True
    else:
        outcome = IntelService(settings, registry).query(password, IndicatorType.PASSWORD)
        evidence.extend(outcome["evidence"])
        provider_rows = outcome["providers"]
        for item in outcome["evidence"]:
            if item.status.value == "detected" and item.source == "HIBP Pwned Passwords":
                import re
                match = re.search(r"\(([\d,]+) sightings\)", item.finding)
                exposed = int(match.group(1).replace(",", "")) if match else 1
        exposure_available = any(r["state"] == "AVAILABLE" for r in provider_rows)

    correlation = note_provider_gaps(correlate(evidence, reliability_map(registry)), provider_rows)
    risk = assess_password_risk(local, exposed, exposure_available)
    scan_time = utc_now()
    report = build_generic_report(
        module="account", module_label="Account Security", target="[password - not stored]",
        original_input="[password - not stored]", indicator_type="password",
        facts={"strength": local["strength_category"], "score": f"{local['strength_score']}/100",
               "length": f"{local['length']} characters",
               "character_types": f"{local['diversity']} of 4",
               "estimated_strength": f"~{local['estimated_bits']} bits",
               "breach_exposure": ("unknown (source unavailable)" if not exposure_available
                                   else (f"exposed ({exposed:,} sightings)" if exposed else "not found in breaches"))},
        indicators=local["indicators"], notes=[], correlation=correlation, risk=risk,
        providers=provider_rows, is_demo=demo, scan_time=scan_time)
    report["ai_analysis"] = build_assessment(
        module_label="Account Security", target="this password", risk=risk,
        correlation=correlation, recommendations=report["recommendations"],
        limitations=report["limitations"], providers=provider_rows, is_demo=demo)
    record = ScanRecord(indicator="[password]", indicator_type=IndicatorType.PASSWORD,
                        risk_score=risk["score"], confidence=risk["confidence"],
                        summary=risk["summary"], evidence=evidence, report=report,
                        module="account", is_demo=demo)
    record.report["scan_id"] = record.id
    db.save_scan(record)  # DB layer replaces the indicator with the placeholder
    report["scan_id"] = record.id
    return report


# ---------------------------------------------------------------------- file

def _file_status(evidence: list[Evidence]) -> tuple[str, str]:
    """PRD 7.3 interpretation ladder: malicious > suspicious > known > unknown."""
    severities = [e.severity.value for e in evidence if e.status.value == "detected"]
    sources = {e.source for e in evidence if e.status.value == "detected"}
    intel_hit = bool(sources - {"File Forensics"})
    if "critical" in severities and intel_hit:
        return "malicious", "At least one intelligence source identifies this hash as malware."
    if "high" in severities or "medium" in severities and intel_hit:
        return "suspicious", "Suspicious signals need verification before trusting this file."
    if any(e.status.value == "informational" and e.source == "CIRCL Hashlookup" for e in evidence):
        return "known", "The hash is catalogued as a known file (context only, not a safety verdict)."
    if intel_hit:
        return "suspicious", "An intelligence source holds a record worth reviewing."
    return "unknown", "No intelligence source holds this hash; unknown is not safe."


def run_file_scan(file_hash: str, settings: Settings, db: Database,
                  registry: ProviderRegistry, demo: bool = False,
                  uploaded: dict[str, Any] | None = None) -> dict[str, Any]:
    file_hash = (file_hash or "").strip().lower()
    kind = identify_hash_type(file_hash)
    if kind is None:
        raise ValueError("Not a valid MD5, SHA-1 or SHA-256 hash.")
    ensure_adapters_registered(registry)

    if uploaded is not None:
        local = analyze_file(uploaded["data"], uploaded.get("filename", "upload"))
        target = local["hashes"]["sha256"]
        kind = IndicatorType.SHA256
        facts = {"filename": local["filename"], "size": f"{local['size_bytes']:,} bytes",
                 "type": f"{local['extension'] or '(none)'} ({local['mime_guess']})",
                 "entropy": f"{local['entropy']} bits/byte",
                 "md5": local["hashes"]["md5"], "sha1": local["hashes"]["sha1"],
                 "sha256": local["hashes"]["sha256"]}
    else:
        local = {"indicators": [], "evidence": [], "local_weights": []}
        facts = {"hash": file_hash, "hash_type": kind.value,
                 "note": "Hash only: no file was uploaded, so static metadata is unavailable."}
        target = file_hash

    evidence: list[Evidence] = [Evidence.from_dict(e) for e in local["evidence"]]
    provider_rows: list[dict[str, Any]] = []

    if demo:
        if target == EICAR_SHA256 or file_hash in (EICAR_SHA256, EICAR_MD5):
            evidence.append(Evidence(
                target, kind, "MalwareBazaar", "malware_intelligence",
                "MalwareBazaar record: EICAR-Test-File (not a virus)", "high", 0.9,
                "DEMONSTRATION DATA: the EICAR test file is the industry-standard harmless test "
                "sample that every engine flags on purpose.",
                "https://bazaar.abuse.ch", "detected", ResultOrigin.DEMO))
        else:
            evidence.append(Evidence(
                target, kind, "MalwareBazaar", "malware_intelligence",
                "No MalwareBazaar record for this hash", "info", 0.6,
                "DEMONSTRATION DATA: no record held.",
                "https://bazaar.abuse.ch", "not_found", ResultOrigin.DEMO))
        provider_rows = [{"key": "malwarebazaar", "name": "MalwareBazaar", "state": "AVAILABLE",
                          "origin": "DEMO_DATA", "message": "Demonstration data.",
                          "latency_ms": 0, "evidence_count": 1}]
    else:
        query_hash = file_hash
        outcome = IntelService(settings, registry).query(query_hash, kind)
        evidence.extend(outcome["evidence"])
        provider_rows = outcome["providers"]

    status, status_detail = _file_status(evidence)
    correlation = note_provider_gaps(correlate(evidence, reliability_map(registry)), provider_rows)
    provider_hits = sum(1 for e in evidence
                        if e.status.value == "detected" and e.source != "File Forensics")
    risk = assess_risk(local["local_weights"], correlation, provider_hits, subject="file")
    facts["file_status"] = f"{status} - {status_detail}"
    scan_time = utc_now()
    report = build_generic_report(
        module="files", module_label="File Forensics", target=target,
        original_input=file_hash if uploaded is None else local.get("filename", file_hash),
        indicator_type=kind.value, facts=facts, indicators=local["indicators"],
        notes=None, correlation=correlation, risk=risk, providers=provider_rows,
        is_demo=demo, scan_time=scan_time)
    # File verdict wording comes from the interpretation ladder, not the URL ladder.
    report["file_status"] = status
    report["ai_analysis"] = build_assessment(
        module_label="File Forensics", target=report["target"], risk=risk,
        correlation=correlation, recommendations=report["recommendations"],
        limitations=report["limitations"], providers=provider_rows, is_demo=demo)
    record = ScanRecord(indicator=target, indicator_type=kind,
                        risk_score=risk["score"], confidence=risk["confidence"],
                        summary=f"{report['executive_summary']} File status: {status}.",
                        evidence=evidence, report=report, module="files", is_demo=demo)
    record.report["scan_id"] = record.id
    db.save_scan(record)
    report["scan_id"] = record.id
    return report


# ------------------------------------------------------------------- network

def run_network_scan(raw_input: str, settings: Settings, db: Database,
                     registry: ProviderRegistry, demo: bool = False) -> dict[str, Any]:
    from app.core.indicators import identify
    identification = identify(raw_input)
    if identification.indicator_type not in (IndicatorType.IPV4, IndicatorType.IPV6, IndicatorType.DOMAIN):
        raise ValueError("Only IP addresses and domains are analyzed here.")
    ensure_adapters_registered(registry)
    target = identification.normalized
    kind = identification.indicator_type

    local = analyze_network(target, kind)
    evidence: list[Evidence] = [Evidence.from_dict(e) for e in local["evidence"]]
    provider_rows: list[dict[str, Any]] = []

    if demo:
        evidence.append(Evidence(
            target, kind, "IPinfo", "ip_intelligence", "IP context retrieved", "info", 0.8,
            "DEMONSTRATION DATA: country: Exampleland; network: AS64496 (Example Hosting). "
            "Context alone says nothing about malice.",
            "https://ipinfo.io", "informational", ResultOrigin.DEMO))
        provider_rows = [{"key": "ipinfo", "name": "IPinfo", "state": "AVAILABLE",
                          "origin": "DEMO_DATA", "message": "Demonstration data.",
                          "latency_ms": 0, "evidence_count": 1}]
    else:
        outcome = IntelService(settings, registry).query(target, kind)
        evidence.extend(outcome["evidence"])
        provider_rows = outcome["providers"]

    correlation = note_provider_gaps(correlate(evidence, reliability_map(registry)), provider_rows)
    provider_hits = sum(1 for e in evidence
                        if e.status.value == "detected" and e.source != "Network Analyzer")
    subject = "address" if kind in (IndicatorType.IPV4, IndicatorType.IPV6) else "domain"
    risk = assess_risk(local["local_weights"], correlation, provider_hits, subject=subject)
    facts = dict(local["facts"])
    facts["indicator"] = target
    scan_time = utc_now()
    report = build_generic_report(
        module="network", module_label="IP and Domain", target=target,
        original_input=identification.original, indicator_type=kind.value,
        facts=facts, indicators=local["indicators"], notes=identification.notes,
        correlation=correlation, risk=risk, providers=provider_rows,
        is_demo=demo, scan_time=scan_time)
    report["ai_analysis"] = build_assessment(
        module_label="IP and Domain", target=target, risk=risk,
        correlation=correlation, recommendations=report["recommendations"],
        limitations=report["limitations"], providers=provider_rows, is_demo=demo)
    record = ScanRecord(indicator=target, indicator_type=kind,
                        risk_score=risk["score"], confidence=risk["confidence"],
                        summary=risk["summary"], evidence=evidence, report=report,
                        module="network", is_demo=demo)
    record.report["scan_id"] = record.id
    db.save_scan(record)
    report["scan_id"] = record.id
    return report


# ----------------------------------------------------------------------- CVE

def run_cve_scan(raw_input: str, settings: Settings, db: Database,
                 registry: ProviderRegistry, demo: bool = False) -> dict[str, Any]:
    parsed = parse_cve(raw_input)
    if not parsed["valid"]:
        raise ValueError("Not a valid CVE identifier (expected like CVE-2021-44228).")
    ensure_adapters_registered(registry)
    target = parsed["normalized"]

    local = analyze_cve(target)
    evidence: list[Evidence] = [Evidence.from_dict(e) for e in local["evidence"]]
    provider_rows: list[dict[str, Any]] = []
    live_record: dict[str, Any] | None = None

    if not demo:
        outcome = IntelService(settings, registry).query(target, IndicatorType.CVE)
        evidence.extend(outcome["evidence"])
        provider_rows = outcome["providers"]

    correlation = note_provider_gaps(correlate(evidence, reliability_map(registry)), provider_rows)

    # Risk follows the CVSS score: live record first, else local reference, else unknown.
    cvss: float | None = None
    for item in evidence:
        if item.source == "CIRCL Vulnerability-Lookup" and item.status.value == "detected":
            live_record = {"finding": item.finding}
            import re
            match = re.search(r"CVSS ([\d.]+)", item.finding)
            cvss = float(match.group(1)) if match else None
            break
    if cvss is None and local["reference"]:
        cvss = float(local["reference"]["cvss"])
    points, level = risk_for_cvss(cvss)
    live = live_record is not None
    has_rating = cvss is not None
    confidence = 0.9 if live and has_rating else (0.75 if local["reference"] else 0.5)
    contributions = [{"source": "CIRCL Vulnerability-Lookup" if live else "CyberShield X CVE reference",
                      "points": points,
                      "detail": f"CVSS base score {cvss if cvss is not None else 'unrated'} maps to {points}/100."}]
    if cvss is None:
        contributions = [{"source": "Risk Engine", "points": 30,
                          "detail": "No severity published; assessed as Low until a score appears."}]
    severity_word = level.lower()
    if level == "Minimal":
        severity_word = "low"
    plain = {"critical": "Fix urgently: attackers can likely take over affected systems.",
             "high": "Fix soon: serious real-world impact.",
             "moderate": "Plan a fix in your next maintenance window.",
             "low": "Fix in routine maintenance."}.get(severity_word, "No severity published yet.")
    summary = (f"{target}: CVSS {cvss if cvss is not None else 'unrated'} ({level}). {plain} "
               "Severity assessment only; it contains no instructions for misuse.")
    verdict = ("unknown" if not has_rating else
               "critical" if level == "Critical" else
               "high" if level == "High" else
               "moderate" if level == "Moderate" else
               "low" if level == "Low" else "unknown")
    risk = {"score": points, "level": level, "confidence": confidence,
            "confidence_label": confidence_label(confidence),
            "verdict": verdict,
            "summary": summary, "contributions": contributions}

    facts = {"cve": target, "year": str(parsed["year"]),
             "cvss": str(cvss) if cvss is not None else "unrated",
             "severity": level,
             "record_source": ("CIRCL live record" if live else
                               "local reference" if local["reference"] else "none yet")}
    if local["reference"]:
        facts["title"] = local["reference"]["title"]
        facts["affected"] = local["reference"]["affected"]
        facts["fix"] = local["reference"]["remediation"]
    scan_time = utc_now()
    report = build_generic_report(
        module="vulnerabilities", module_label="Vulnerabilities", target=target,
        original_input=target, indicator_type="cve", facts=facts,
        indicators=local["indicators"], notes=None, correlation=correlation, risk=risk,
        providers=provider_rows, is_demo=demo, scan_time=scan_time,
        extra={"plain_language": local["plain_language"]})
    report["ai_analysis"] = build_assessment(
        module_label="Vulnerabilities", target=target, risk=risk,
        correlation=correlation, recommendations=report["recommendations"],
        limitations=report["limitations"], providers=provider_rows, is_demo=demo)
    record = ScanRecord(indicator=target, indicator_type=IndicatorType.CVE,
                        risk_score=risk["score"], confidence=risk["confidence"],
                        summary=risk["summary"], evidence=evidence, report=report,
                        module="vulnerabilities", is_demo=demo)
    record.report["scan_id"] = record.id
    db.save_scan(record)
    report["scan_id"] = record.id
    return report


# ---------------------------------------------------------------------- text

def run_text_scan(text: str, settings: Settings, db: Database,
                  registry: ProviderRegistry, demo: bool = False) -> dict[str, Any]:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Text is empty.")
    if len(text) > 20000:
        raise ValueError("Text is longer than 20000 characters.")
    ensure_adapters_registered(registry)

    local = analyze_text(text)
    evidence: list[Evidence] = [Evidence.from_dict(e) for e in local["evidence"]]
    correlation = correlate(evidence, reliability_map(registry))  # local-only: no providers

    likeness = local["likeness"]
    if likeness == "inconclusive":
        score, level = 5, "Minimal"
        summary = ("Too little text for statistical analysis. " + REQUIRED_LIMITATION)
    else:
        score = int(local["stats"]["ai_score"])
        level = risk_level_for(score)
        noun = {"high": "Strong AI-like characteristics were measured",
                "moderate": "Some AI-like characteristics were measured",
                "low": "The text reads human-like on measured characteristics"}[likeness]
        summary = (f"{noun} (score {score}/100). {REQUIRED_LIMITATION}")
    risk = {"score": score, "level": level, "confidence": local["confidence"],
            "confidence_label": confidence_label(local["confidence"]),
            "verdict": likeness, "summary": summary,
            "contributions": [{"source": "Text Analyzer", "points": score,
                               "detail": f"Combined statistical signals score {score}/100."}]}
    facts = {"words": str(local["stats"]["words"]), "sentences": str(local["stats"]["sentences"]),
             "paragraphs": str(local["stats"].get("paragraphs", "?")),
             "mean_sentence_length": f"{local['stats'].get('mean_sentence_words', '?')} words",
             "vocabulary_diversity": str(local["stats"].get("vocab_diversity", "?")),
             "ai_likeness": likeness}
    scan_time = utc_now()
    stored_target = text[:1000]
    report = build_generic_report(
        module="text", module_label="Text Analyzer", target=stored_target,
        original_input=stored_target, indicator_type="text", facts=facts,
        indicators=local["indicators"], notes=None, correlation=correlation, risk=risk,
        providers=[], is_demo=demo, scan_time=scan_time)
    report["ai_analysis"] = build_assessment(
        module_label="Text Analyzer", target="this text", risk=risk,
        correlation=correlation, recommendations=report["recommendations"],
        limitations=report["limitations"] + [REQUIRED_LIMITATION], providers=[],
        is_demo=demo)
    record = ScanRecord(indicator=stored_target, indicator_type=IndicatorType.TEXT,
                        risk_score=risk["score"], confidence=risk["confidence"],
                        summary=risk["summary"], evidence=evidence, report=report,
                        module="text", is_demo=demo)
    record.report["scan_id"] = record.id
    db.save_scan(record)
    report["scan_id"] = record.id
    return report


# ---------------------------------------------------------------------- media

def run_media_scan(data: bytes, filename: str, settings: Settings, db: Database,
                   registry: ProviderRegistry, demo: bool = False) -> dict[str, Any]:
    if not data:
        raise ValueError("The image is empty.")
    if identify_image(data) is None:
        raise ValueError("Not a recognised image (PNG, JPEG, GIF, BMP or WebP).")
    ensure_adapters_registered(registry)

    import hashlib
    sha256 = hashlib.sha256(data).hexdigest()
    local = analyze_image(data, filename)
    evidence: list[Evidence] = [Evidence.from_dict(e) for e in local["evidence"]]
    provider_rows: list[dict[str, Any]] = []

    if demo:
        provider_rows = [{"key": "virustotal", "name": "VirusTotal", "state": "AVAILABLE",
                          "origin": "DEMO_DATA", "message": "Demonstration data.",
                          "latency_ms": 0, "evidence_count": 0}]
    else:
        outcome = IntelService(settings, registry).query(sha256, IndicatorType.SHA256)
        evidence.extend(outcome["evidence"])
        provider_rows = outcome["providers"]

    correlation = note_provider_gaps(correlate(evidence, reliability_map(registry)), provider_rows)
    provider_hits = sum(1 for e in evidence
                        if e.status.value == "detected" and e.source != "Media Forensics")
    risk = assess_risk(local["local_weights"], correlation, provider_hits, subject="image")
    facts = {k: str(v) for k, v in local["facts"].items()
             if k not in ("text_chunks", "segments", "comments", "software_tags")}
    facts["sha256"] = sha256
    extra_chunks = local["facts"].get("text_chunks") or local["facts"].get("segments") or []
    if extra_chunks:
        facts["metadata_markers"] = ", ".join(str(c)[:40] for c in extra_chunks[:6])
    target = f"{local['facts']['filename']} ({sha256[:16]}...)"
    scan_time = utc_now()
    report = build_generic_report(
        module="media", module_label="Media Forensics", target=target,
        original_input=target, indicator_type="image", facts=facts,
        indicators=local["indicators"], notes=None, correlation=correlation, risk=risk,
        providers=provider_rows, is_demo=demo, scan_time=scan_time)
    report["ai_analysis"] = build_assessment(
        module_label="Media Forensics", target=target, risk=risk,
        correlation=correlation, recommendations=report["recommendations"],
        limitations=report["limitations"], providers=provider_rows, is_demo=demo)
    record = ScanRecord(indicator=target, indicator_type=IndicatorType.IMAGE,
                        risk_score=risk["score"], confidence=risk["confidence"],
                        summary=risk["summary"], evidence=evidence, report=report,
                        module="media", is_demo=demo)
    record.report["scan_id"] = record.id
    db.save_scan(record)
    report["scan_id"] = record.id
    return report
