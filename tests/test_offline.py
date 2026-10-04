import io
import unittest
from unittest import mock

from tests.helpers import make_app


def _all_adapters():
    from app.intelligence import providers as p
    return [getattr(p, name) for name in p.__all__
            if name.endswith("Provider")]


class OfflineFallbackTests(unittest.TestCase):
    """Total provider failure must still yield a local-only assessment (PRD 22)."""

    def setUp(self):
        self.app, self.settings = make_app({})
        self.c = self.app.test_client()

    def _break_everything(self):
        return [mock.patch.object(cls, "check", side_effect=RuntimeError("link down"))
                for cls in _all_adapters()]

    def test_url_scan_survives_total_outage(self):
        patches = self._break_everything()
        for patcher in patches:
            patcher.start()
        try:
            r = self.c.post("/api/scans", json={"input": "http://192.0.2.10/paypal/login"})
        finally:
            for patcher in patches:
                patcher.stop()
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True)[:300])
        report = r.get_json()
        self.assertTrue(report["evidence"])  # local evidence remains
        origins = {e["origin"] for e in report["evidence"]}
        self.assertTrue(origins <= {"LOCAL_ANALYSIS", "PROVIDER_ERROR"}, origins)
        states = {p["state"] for p in report["sources_consulted"]}
        self.assertTrue(states <= {"ERROR", "NOT_CONFIGURED", "DISABLED"}, states)
        self.assertIn("only available evidence", report["correlation_explanation"])

    def test_password_scan_survives_hibp_outage(self):
        with mock.patch("app.intelligence.providers.hibp.HibpPasswordsProvider.check",
                        side_effect=RuntimeError("down")):
            r = self.c.post("/api/scans/password", json={"password": "Some-Decent-Passphrase-9!"})
        self.assertEqual(r.status_code, 201)
        report = r.get_json()
        self.assertFalse(report["ai_analysis"]["grounding"]["intel_hits"])
        self.assertIn("could not be checked", str(report["score_contributions"]))

    def test_file_upload_survives_outage(self):
        patches = self._break_everything()
        for patcher in patches:
            patcher.start()
        try:
            data = {"file": (io.BytesIO(b"some bytes here"), "doc.txt")}
            r = self.c.post("/api/scans/file", data=data, content_type="multipart/form-data")
        finally:
            for patcher in patches:
                patcher.stop()
        self.assertEqual(r.status_code, 201)
        self.assertTrue(r.get_json()["evidence"])


if __name__ == "__main__":
    unittest.main()
