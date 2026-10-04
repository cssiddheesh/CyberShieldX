import tempfile
import unittest
from pathlib import Path

from app.database.db import PASSWORD_PLACEHOLDER, Database
from app.models.evidence import Evidence, IndicatorType, ScanRecord


def ev(**kw):
    base = dict(indicator="x.example", indicator_type="domain", source="S", source_type="t",
                finding="F", severity="low", confidence=0.5, evidence="e")
    base.update(kw)
    return Evidence(**base)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(Path(tempfile.mkdtemp()) / "t.db")
        self.db.init()

    def scan(self, score, indicator="a.example", kind=IndicatorType.DOMAIN, **kw):
        return ScanRecord(indicator=indicator, indicator_type=kind, risk_score=score, confidence=0.6,
                          summary="s", evidence=[ev(indicator=indicator)], report={"k": 1}, **kw)

    def test_init_is_idempotent_and_ping_works(self):
        self.db.init()
        self.assertTrue(self.db.ping())

    def test_settings_roundtrip(self):
        self.assertEqual(self.db.get_setting("missing", "dflt"), "dflt")
        self.db.set_setting("demo_mode", True)
        self.db.set_setting("demo_mode", False)
        self.assertIs(self.db.get_setting("demo_mode"), False)

    def test_save_and_reopen_scan(self):
        rec = self.scan(65)
        self.db.save_scan(rec)
        got = self.db.get_scan(rec.id)
        self.assertEqual((got["risk_level"], got["risk_score"]), ("High", 65))
        self.assertEqual(got["report"], {"k": 1})
        self.assertEqual(len(got["evidence"]), 1)
        self.assertIsNone(self.db.get_scan("CSX-NOPE"))

    def test_passwords_are_never_stored(self):
        secret = "Hunter2-super-secret"
        rec = ScanRecord(indicator=secret, indicator_type=IndicatorType.PASSWORD, risk_score=50,
                         confidence=0.8, summary="strength only",
                         evidence=[ev(indicator=secret, indicator_type="password")],
                         report={"password": secret, "target": secret, "strength": "Fair"})
        self.db.save_scan(rec)
        got = self.db.get_scan(rec.id)
        self.assertEqual(got["indicator"], PASSWORD_PLACEHOLDER)
        self.assertEqual(got["evidence"][0]["indicator"], PASSWORD_PLACEHOLDER)
        self.assertEqual(got["report"], {"strength": "Fair"})
        raw = Path(self.db.path).read_bytes()
        wal = Path(str(self.db.path) + "-wal")
        if wal.exists():
            raw += wal.read_bytes()
        self.assertNotIn(secret.encode(), raw)

    def test_list_filters_and_pagination(self):
        for score in (5, 25, 45, 65, 85):
            self.db.save_scan(self.scan(score))
        self.db.save_scan(self.scan(90, indicator="1.2.3.4", kind=IndicatorType.IPV4))
        self.assertEqual(self.db.list_scans()["total"], 6)
        self.assertEqual(self.db.list_scans(risk_level="Critical")["total"], 2)
        self.assertEqual(self.db.list_scans(indicator_type="ipv4")["total"], 1)
        page = self.db.list_scans(limit=2, offset=4)
        self.assertEqual(len(page["items"]), 2)
        self.assertEqual(self.db.list_scans(risk_level="'; DROP TABLE scans;--")["total"], 6)  # ignored safely
        self.assertEqual(self.db.list_scans(limit=-5)["limit"], 1)

    def test_dashboard_stats(self):
        empty = self.db.dashboard_stats()
        self.assertEqual((empty["total_scans"], empty["posture"]["level"]), (0, "none"))
        self.db.save_scan(self.scan(10))
        self.db.save_scan(self.scan(70))
        self.db.save_scan(self.scan(95, is_demo=True))
        s = self.db.dashboard_stats()
        self.assertEqual((s["total_scans"], s["high_critical"], s["demo_scans"]), (3, 2, 1))
        self.assertEqual(s["posture"]["level"], "critical")
        self.assertEqual(sum(s["distribution"].values()), 3)

    def test_source_health_upsert(self):
        self.db.save_source_health("urlhaus", "AVAILABLE", "ok", 120)
        self.db.save_source_health("urlhaus", "ERROR", "boom", None)
        self.assertEqual(self.db.get_source_health()["urlhaus"]["state"], "ERROR")


if __name__ == "__main__":
    unittest.main()
