"""SQLite persistence (PRD section 25).

Tables: scans, findings, reports, sources, settings.
Passwords are never stored: any scan of type ``password`` has its indicator
replaced by a fixed placeholder before it touches the database.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from app.models.evidence import RISK_LEVEL_NAMES, Evidence, IndicatorType, ScanRecord, risk_level_for, utc_now

SCHEMA_VERSION = 1
PASSWORD_PLACEHOLDER = "[password - not stored]"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    indicator       TEXT NOT NULL,
    indicator_type  TEXT NOT NULL,
    module          TEXT,
    risk_score      INTEGER NOT NULL,
    risk_level      TEXT NOT NULL,
    confidence      REAL NOT NULL,
    summary         TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'completed',
    is_demo         INTEGER NOT NULL DEFAULT 0,
    report_json     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_level ON scans(risk_level);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    indicator       TEXT NOT NULL,
    indicator_type  TEXT NOT NULL,
    source          TEXT NOT NULL,
    source_type     TEXT NOT NULL DEFAULT '',
    finding         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL,
    evidence        TEXT NOT NULL DEFAULT '',
    reference       TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL,
    origin          TEXT NOT NULL,
    timestamp       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    format      TEXT NOT NULL,
    content     BLOB
);

CREATE TABLE IF NOT EXISTS sources (
    key         TEXT PRIMARY KEY,
    state       TEXT NOT NULL,
    checked_at  TEXT NOT NULL,
    latency_ms  INTEGER,
    message     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(SCHEMA)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def ping(self) -> bool:
        try:
            with self.connect() as conn:
                conn.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    # ------------------------------------------------------------------ settings
    def get_setting(self, key: str, default: Any = None) -> Any:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return default

    def set_setting(self, key: str, value: Any) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value)),
            )

    # --------------------------------------------------------------------- scans
    def save_scan(self, record: ScanRecord) -> str:
        indicator = record.indicator
        report = record.report
        if record.indicator_type == IndicatorType.PASSWORD:
            indicator = PASSWORD_PLACEHOLDER
            report = {k: v for k, v in report.items() if k not in {"password", "indicator", "target"}}
        evidence = [self._redact(e, record.indicator_type) for e in record.evidence]
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO scans(id, created_at, indicator, indicator_type, module, risk_score, risk_level, "
                "confidence, summary, status, is_demo, report_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (record.id, record.created_at, indicator, record.indicator_type.value, record.module,
                 int(record.risk_score), record.risk_level, float(record.confidence), record.summary,
                 record.status, 1 if record.is_demo else 0, json.dumps(report)),
            )
            conn.executemany(
                "INSERT INTO findings(scan_id, indicator, indicator_type, source, source_type, finding, severity, "
                "confidence, evidence, reference, status, origin, timestamp) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(record.id, e.indicator, e.indicator_type.value, e.source, e.source_type, e.finding,
                  e.severity.value, e.confidence, e.evidence, e.reference, e.status.value, e.origin.value,
                  e.timestamp) for e in evidence],
            )
        return record.id

    @staticmethod
    def _redact(e: Evidence, scan_type: IndicatorType) -> Evidence:
        if scan_type != IndicatorType.PASSWORD and e.indicator_type != IndicatorType.PASSWORD:
            return e
        data = e.to_dict()
        data["indicator"] = PASSWORD_PLACEHOLDER
        return Evidence.from_dict(data)

    def list_scans(self, limit: int = 25, offset: int = 0, risk_level: Optional[str] = None,
                   indicator_type: Optional[str] = None) -> dict[str, Any]:
        limit = max(1, min(100, int(limit)))
        offset = max(0, int(offset))
        where, params = [], []
        if risk_level in RISK_LEVEL_NAMES:
            where.append("risk_level = ?")
            params.append(risk_level)
        if indicator_type:
            where.append("indicator_type = ?")
            params.append(indicator_type)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        with self.connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM scans {clause}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT id, created_at, indicator, indicator_type, module, risk_score, risk_level, confidence, "
                f"summary, status, is_demo FROM scans {clause} ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return {"total": total, "limit": limit, "offset": offset, "items": [self._scan_row(r) for r in rows]}

    def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            findings = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        scan = self._scan_row(row)
        try:
            scan["report"] = json.loads(row["report_json"])
        except json.JSONDecodeError:
            scan["report"] = {}
        scan["evidence"] = [
            {k: f[k] for k in ("indicator", "indicator_type", "source", "source_type", "finding", "severity",
                               "confidence", "evidence", "reference", "status", "origin", "timestamp")}
            for f in findings
        ]
        return scan

    @staticmethod
    def _scan_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "created_at": row["created_at"], "indicator": row["indicator"],
            "indicator_type": row["indicator_type"], "module": row["module"],
            "risk_score": row["risk_score"], "risk_level": risk_level_for(row["risk_score"]),
            "confidence": row["confidence"], "summary": row["summary"], "status": row["status"],
            "is_demo": bool(row["is_demo"]),
        }

    def dashboard_stats(self) -> dict[str, Any]:
        with self.connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            demo_total = conn.execute("SELECT COUNT(*) FROM scans WHERE is_demo = 1").fetchone()[0]
            by_level = {r["risk_level"]: r["n"] for r in conn.execute(
                "SELECT risk_level, COUNT(*) AS n FROM scans GROUP BY risk_level")}
            by_type = {r["indicator_type"]: r["n"] for r in conn.execute(
                "SELECT indicator_type, COUNT(*) AS n FROM scans GROUP BY indicator_type")}
            recent_rows = conn.execute(
                "SELECT id, created_at, indicator, indicator_type, module, risk_score, risk_level, confidence, "
                "summary, status, is_demo FROM scans ORDER BY created_at DESC, rowid DESC LIMIT 8").fetchall()
            latest = conn.execute(
                "SELECT risk_level FROM scans ORDER BY created_at DESC, rowid DESC LIMIT 20").fetchall()
        distribution = {name: by_level.get(name, 0) for name in RISK_LEVEL_NAMES}
        recent_levels = {r["risk_level"] for r in latest}
        if not total:
            posture = {"level": "none", "label": "No scans yet"}
        elif "Critical" in recent_levels:
            posture = {"level": "critical", "label": "Critical findings to review"}
        elif "High" in recent_levels:
            posture = {"level": "high", "label": "High-risk findings to review"}
        elif "Moderate" in recent_levels:
            posture = {"level": "moderate", "label": "Some findings to review"}
        else:
            posture = {"level": "stable", "label": "No elevated findings"}
        return {
            "total_scans": total,
            "demo_scans": demo_total,
            "high_critical": distribution["High"] + distribution["Critical"],
            "distribution": distribution,
            "by_type": by_type,
            "posture": posture,
            "recent": [self._scan_row(r) for r in recent_rows],
        }

    # ------------------------------------------------- AI enhancements
    def save_ai_enhancement(self, scan_id: str, payload: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM reports WHERE scan_id = ? AND format = 'ai'", (scan_id,))
            conn.execute(
                "INSERT INTO reports(scan_id, created_at, format, content) VALUES(?,?,?,?)",
                (scan_id, utc_now(), "ai", json.dumps(payload)),
            )

    def get_ai_enhancement(self, scan_id: str) -> Optional[dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT content FROM reports WHERE scan_id = ? AND format = 'ai' "
                "ORDER BY id DESC LIMIT 1", (scan_id,)).fetchone()
        if row is None:
            return None
        try:
            data = json.loads(row["content"])
        except (json.JSONDecodeError, TypeError):
            return None
        return data if isinstance(data, dict) else None

    # ------------------------------------------------------------------- sources
    def save_source_health(self, key: str, state: str, message: str = "", latency_ms: Optional[int] = None) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO sources(key, state, checked_at, latency_ms, message) VALUES(?,?,?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET state=excluded.state, checked_at=excluded.checked_at, "
                "latency_ms=excluded.latency_ms, message=excluded.message",
                (key, state, utc_now(), latency_ms, message[:300]),
            )

    def get_source_health(self) -> dict[str, dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT key, state, checked_at, latency_ms, message FROM sources").fetchall()
        return {r["key"]: dict(r) for r in rows}
