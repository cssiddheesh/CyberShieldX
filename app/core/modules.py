"""Catalog of product modules - the single source of truth for what is built.

The frontend renders navigation and the 360-degree coverage ring from this list,
so a module is only shown as available once its analysis really works.
Change ``status`` to "available" only when the module works end to end.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

AVAILABLE = "available"
PLANNED = "planned"


@dataclass(frozen=True)
class Module:
    key: str
    label: str
    path: str
    group: str
    dimension: Optional[str]
    status: str
    phase: int
    blurb: str


# The eight 360-degree dimensions from PRD section 4.
DIMENSIONS = [
    ("web", "Web"),
    ("identity", "Identity"),
    ("files", "Files"),
    ("infrastructure", "Infrastructure"),
    ("vulnerabilities", "Vulnerabilities"),
    ("content", "Content"),
    ("intelligence", "Intelligence"),
    ("reporting", "Reporting"),
]

MODULES: list[Module] = [
    Module("dashboard", "Dashboard", "/", "Overview", None, AVAILABLE, 1,
           "Security status, recent scans and source health."),
    Module("analyze", "Universal Analyzer", "/analyze", "Overview", "intelligence", AVAILABLE, 2,
           "Paste any indicator and CyberShield X routes it to the right analyzer."),
    Module("phishing", "PhishGuard", "/phishing", "Analyzers", "web", AVAILABLE, 2,
           "Checks links for phishing signals using local rules and threat intelligence."),
    Module("account", "Account Security", "/account", "Analyzers", "identity", AVAILABLE, 4,
           "Rates password strength and checks exposure without sending the password."),
    Module("files", "File Forensics", "/files", "Analyzers", "files", AVAILABLE, 4,
           "Hashes and inspects files without ever running them."),
    Module("network", "IP and Domain", "/network", "Analyzers", "infrastructure", AVAILABLE, 4,
           "Context and reputation for IP addresses and domains."),
    Module("vulnerabilities", "Vulnerabilities", "/vulnerabilities", "Analyzers", "vulnerabilities", AVAILABLE, 4,
           "Explains CVEs in plain language."),
    Module("text", "Text Analyzer", "/text", "Analyzers", "content", AVAILABLE, 7,
           "Estimates how AI-like a piece of writing is. Probabilistic only."),
    Module("media", "Media Forensics", "/media", "Analyzers", "content", AVAILABLE, 7,
           "Looks at image metadata and basic forensic indicators."),
    Module("lab", "Threat Lab", "/lab", "Learn", None, AVAILABLE, 7,
           "Safe, educational simulations of common attacks."),
    Module("history", "Scan History", "/history", "Records", "reporting", AVAILABLE, 1,
           "Every saved scan, with filters."),
    Module("reports", "Reports", "/reports", "Records", "reporting", AVAILABLE, 6,
           "Export scan reports as PDF or JSON."),
    Module("sources", "Intelligence Sources", "/sources", "System", "intelligence", AVAILABLE, 1,
           "Status of every external intelligence provider."),
    Module("settings", "Settings", "/settings", "System", None, AVAILABLE, 1,
           "Demo Mode and application limits."),
]


def module_by_key(key: str) -> Optional[Module]:
    return next((m for m in MODULES if m.key == key), None)


def modules_payload() -> dict:
    modules = [
        {"key": m.key, "label": m.label, "path": m.path, "group": m.group, "dimension": m.dimension,
         "status": m.status, "phase": m.phase, "blurb": m.blurb}
        for m in MODULES
    ]
    dimensions = []
    for key, label in DIMENSIONS:
        members = [m for m in MODULES if m.dimension == key]
        ready = [m for m in members if m.status == AVAILABLE]
        if members and len(ready) == len(members):
            status = "ready"
        elif ready:
            status = "partial"
        else:
            status = "planned"
        dimensions.append({
            "key": key,
            "label": label,
            "status": status,
            "path": members[0].path if members else "/",
            "modules": [m.label for m in members],
        })
    return {"modules": modules, "dimensions": dimensions}
