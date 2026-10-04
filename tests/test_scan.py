import unittest

from tests.helpers import make_app


class ScanApiTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app({})
        self.c = self.app.test_client()

    def test_full_scan_workflow_offline(self):
        # no keys configured: local analysis only, must still work
        r = self.c.post("/api/scans", json={"input": "http://192.0.2.10/paypal/login?redirect=http://x.evil"})
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        report = r.get_json()
        for field in ("target", "indicator_type", "risk_score", "overall_risk", "confidence",
                      "executive_summary", "findings", "evidence", "correlation_explanation",
                      "recommendations", "limitations", "sources_consulted", "scan_id"):
            self.assertIn(field, report, field)
        self.assertEqual(report["indicator_type"], "url")
        self.assertFalse(report["is_demo"])
        self.assertTrue(report["evidence"])  # local evidence at minimum
        self.assertTrue(report["score_contributions"])  # every point explained
        self.assertNotIn("definitely", report["executive_summary"].lower())

        scan_id = report["scan_id"]
        scan = self.c.get(f"/api/scans/{scan_id}").get_json()
        self.assertEqual(scan["module"], "phishing")
        fetched = self.c.get(f"/api/reports/{scan_id}").get_json()
        self.assertEqual(fetched["scan_id"], scan_id)

        # dashboard reflects the scan
        dash = self.c.get("/api/dashboard").get_json()
        self.assertEqual(dash["total_scans"], 1)

    def test_non_url_types_route_to_their_modules(self):
        # Phase 3: hashes, IPs and CVEs scan end-to-end through /api/scans.
        for text in ("8.8.8.8", "CVE-2021-44228",
                     "d41d8cd98f00b204e9800998ecf8427e", "example.com"):
            r = self.c.post("/api/scans", json={"input": text})
            self.assertEqual(r.status_code, 201, text)
        r = self.c.post("/api/scans", json={"input": "hello world"})
        self.assertEqual(r.status_code, 422)
        r = self.c.post("/api/scans", json={"input": ""})
        self.assertEqual(r.status_code, 400)
        r = self.c.post("/api/scans", json={"input": 5})
        self.assertEqual(r.status_code, 400)

    def test_demo_mode_labels_data(self):
        self.c.put("/api/settings", json={"demo_mode": True})
        report = self.c.post("/api/scans", json={"input": "https://example.com/login"}).get_json()
        self.assertTrue(report["is_demo"])
        self.assertEqual(report["data_label"], "DEMONSTRATION DATA")
        origins = {e["origin"] for e in report["evidence"]}
        self.assertTrue(origins <= {"DEMO_DATA", "LOCAL_ANALYSIS"} or "DEMO_DATA" in origins)

    def test_defanged_input_scans(self):
        r = self.c.post("/api/scans", json={"input": "hxxps://evil[.]example[.]com/login"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["local_analysis"]["domain"], "evil.example.com")

    def test_no_keys_leak_in_reports(self):
        app, _ = make_app({"VIRUSTOTAL_API_KEY": "TOPSECRET-KEY-999"})
        c = app.test_client()
        report = c.post("/api/scans", json={"input": "https://example.com/"}).get_json()
        self.assertNotIn("TOPSECRET-KEY-999", str(report))

    def test_phishing_module_now_available(self):
        status = {m["key"]: m["status"] for m in self.c.get("/api/modules").get_json()["modules"]}
        self.assertEqual(status["phishing"], "available")
        self.assertEqual(status["analyze"], "available")


if __name__ == "__main__":
    unittest.main()
