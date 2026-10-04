import io
import unittest

from tests.helpers import make_app


class Phase3ApiTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app({})
        self.c = self.app.test_client()

    def test_password_scan_never_stores_secret(self):
        secret = "Sup3r-Secret-XYZ-9!"
        r = self.c.post("/api/scans/password", json={"password": secret})
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        report = r.get_json()
        self.assertEqual(report["module"], "account")
        self.assertNotIn(secret, r.get_data(as_text=True))
        scan = self.c.get(f"/api/scans/{report['scan_id']}").get_json()
        self.assertNotIn(secret, str(scan))
        self.assertEqual(scan["indicator"], "[password - not stored]")
        self.assertEqual(self.c.post("/api/scans/password", json={}).status_code, 400)
        self.assertEqual(self.c.post("/api/scans/password", json={"password": ""}).status_code, 400)

    def test_password_demo_mode(self):
        self.c.put("/api/settings", json={"demo_mode": True})
        report = self.c.post("/api/scans/password", json={"password": "demo-pass-1"}).get_json()
        self.assertTrue(report["is_demo"])
        self.assertEqual(report["data_label"], "DEMONSTRATION DATA")

    def test_hash_scan_offline(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"  # empty string hash: unknown everywhere
        r = self.c.post("/api/scans", json={"input": md5})
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        report = r.get_json()
        self.assertEqual(report["module"], "files")
        self.assertIn("file_status", report)
        self.assertTrue(report["evidence"])

    def test_file_upload_scans_bytes_not_filename(self):
        data = {"file": (io.BytesIO(b"hello world, this is a test file"), "notes.txt")}
        r = self.c.post("/api/scans/file", data=data, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        report = r.get_json()
        import hashlib
        self.assertEqual(report["target"], hashlib.sha256(b"hello world, this is a test file").hexdigest())
        r = self.c.post("/api/scans/file", data={}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_network_scan_offline(self):
        r = self.c.post("/api/scans", json={"input": "8.8.8.8"})
        self.assertEqual(r.status_code, 201)
        report = r.get_json()
        self.assertEqual(report["module"], "network")
        self.assertIn("globally routable", str(report["local_analysis"]))
        r = self.c.post("/api/scans", json={"input": "192.168.1.1"})
        self.assertIn("Non-routable", r.get_data(as_text=True))

    def test_cve_scan_offline_reference(self):
        r = self.c.post("/api/scans", json={"input": "CVE-2021-44228"})
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        report = r.get_json()
        self.assertEqual(report["module"], "vulnerabilities")
        self.assertEqual(report["risk_score"], 100)
        self.assertEqual(report["verdict"], "critical")
        for text in [report["executive_summary"], *report["recommendations"]]:
            self.assertNotIn("exploit", text.lower())

    def test_cve_scan_unknown_offline(self):
        r = self.c.post("/api/scans", json={"input": "CVE-2099-0001"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["verdict"], "unknown")

    def test_all_modules_now_available(self):
        status = {m["key"]: m["status"] for m in self.c.get("/api/modules").get_json()["modules"]}
        for key in ("phishing", "analyze", "account", "files", "network", "vulnerabilities"):
            self.assertEqual(status[key], "available", key)

    def test_dashboard_counts_new_types(self):
        self.c.post("/api/scans", json={"input": "8.8.8.8"})
        self.c.post("/api/scans", json={"input": "CVE-2021-44228"})
        dash = self.c.get("/api/dashboard").get_json()
        self.assertEqual(dash["total_scans"], 2)
        self.assertIn("ipv4", dash["by_type"])
        self.assertIn("cve", dash["by_type"])


if __name__ == "__main__":
    unittest.main()
