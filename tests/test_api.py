import unittest

from app.intelligence.registry import SOURCES
from tests.helpers import make_app


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app({"VIRUSTOTAL_API_KEY": "TOPSECRET-KEY-999"})
        self.c = self.app.test_client()

    def test_no_endpoint_leaks_api_keys(self):
        for url in ["/api/health", "/api/config", "/api/sources", "/api/dashboard", "/api/modules", "/api/scans"]:
            self.assertNotIn("TOPSECRET-KEY-999", self.c.get(url).get_data(as_text=True), url)

    def test_missing_key_is_not_configured_never_clean(self):
        items = {i["key"]: i for i in self.c.get("/api/sources").get_json()["items"]}
        self.assertEqual((items["urlhaus"]["state"], items["urlhaus"]["reason"]), ("NOT_CONFIGURED", "no_key"))
        # keyless providers are implemented and waiting, not "not built"
        self.assertEqual(items["hibp_passwords"]["state"], "UNCHECKED")
        self.assertTrue(items["hibp_passwords"]["implemented"])
        self.assertFalse(items["urlhaus"]["key_set"])
        self.assertTrue(items["virustotal"]["key_set"])
        self.assertNotEqual(items["virustotal"]["state"], "NOT_CONFIGURED")
        # a source with no adapter must never report itself as available
        for item in items.values():
            if not item["implemented"]:
                self.assertNotEqual(item["state"], "AVAILABLE", item["key"])
        self.assertEqual(len(items), len(SOURCES))

    def test_disable_and_enable_source(self):
        r = self.c.put("/api/sources/urlhaus", json={"enabled": False})
        self.assertEqual((r.get_json()["state"], r.get_json()["reason"]), ("DISABLED", "user_disabled"))
        self.assertTrue(r.get_json()["user_disabled"])
        r = self.c.put("/api/sources/urlhaus", json={"enabled": True})
        self.assertEqual(r.get_json()["state"], "NOT_CONFIGURED")
        self.assertEqual(self.c.put("/api/sources/nope", json={"enabled": True}).status_code, 404)
        self.assertEqual(self.c.put("/api/sources/urlhaus", json={"enabled": "yes"}).status_code, 400)

    def test_demo_mode_toggle_persists(self):
        self.assertFalse(self.c.get("/api/config").get_json()["demo_mode"])
        self.assertEqual(self.c.put("/api/settings", json={"demo_mode": True}).status_code, 200)
        self.assertTrue(self.c.get("/api/config").get_json()["demo_mode"])
        self.assertEqual(self.c.put("/api/settings", json={"demo_mode": 1}).status_code, 400)
        self.assertEqual(self.c.put("/api/settings", data="not json", content_type="text/plain").status_code, 400)

    def test_identify_endpoint(self):
        r = self.c.post("/api/identify", json={"input": "8.8.8.8"}).get_json()
        self.assertEqual((r["indicator_type"], r["module"], r["module_available"]), ("ipv4", "network", True))
        self.assertEqual(self.c.post("/api/identify", json={"input": 5}).status_code, 400)
        self.assertEqual(self.c.post("/api/identify", json=[1]).status_code, 400)
        self.assertEqual(self.c.post("/api/identify", json={"input": ""}).get_json()["indicator_type"], "unknown")

    def test_dashboard_empty_state(self):
        d = self.c.get("/api/dashboard").get_json()
        self.assertEqual((d["total_scans"], d["high_critical"], d["recent"]), (0, 0, []))
        self.assertEqual(d["posture"]["level"], "none")
        self.assertEqual(d["sources"]["total"], len(SOURCES))

    def test_modules_are_honest_about_status(self):
        data = self.c.get("/api/modules").get_json()
        status = {m["key"]: m["status"] for m in data["modules"]}
        self.assertEqual(status["phishing"], "available")  # Phase 2 works end to end
        self.assertEqual(status["analyze"], "available")
        self.assertEqual(status["dashboard"], "available")
        self.assertEqual(len(data["dimensions"]), 8)

    def test_scan_endpoints_validate_input(self):
        self.assertEqual(self.c.get("/api/scans?limit=abc").status_code, 400)
        self.assertEqual(self.c.get("/api/scans?risk=Bogus").status_code, 400)
        self.assertEqual(self.c.get("/api/scans?type=bogus").status_code, 400)
        self.assertEqual(self.c.get("/api/scans/" + "A" * 100).status_code, 404)
        self.assertEqual(self.c.get("/api/scans/CSX-NOPE").status_code, 404)

    def test_errors_are_json_and_methods_enforced(self):
        r = self.c.get("/api/unknown")
        self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (404, "not_found"))
        self.assertEqual(self.c.delete("/api/health").status_code, 405)

    def test_security_headers_present(self):
        r = self.c.get("/api/health")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_rate_limit_returns_429(self):
        app, _ = make_app({"CYBERSHIELD_RATE_LIMIT": "10"})
        c = app.test_client()
        codes = [c.get("/api/health").status_code for _ in range(12)]
        self.assertEqual(codes[:10], [200] * 10)
        self.assertEqual(codes[10], 429)
        self.assertIn("Retry-After", c.get("/api/health").headers)

    def test_unexpected_errors_do_not_leak_details(self):
        @self.app.get("/api/boom")
        def boom():
            raise RuntimeError("secret internal detail /etc/passwd")
        self.app.config["PROPAGATE_EXCEPTIONS"] = False
        r = self.c.get("/api/boom")
        self.assertEqual(r.status_code, 500)
        self.assertNotIn("secret internal detail", r.get_data(as_text=True))
        with self.assertLogs("cybershieldx", level="ERROR") as logs:
            self.c.get("/api/boom")
        text = "\n".join(logs.output)
        self.assertIn("RuntimeError", text)
        self.assertNotIn("secret internal detail", text)  # exception messages are never logged

    def test_path_traversal_is_refused(self):
        for path in ["/..%2f..%2f.env", "/../.env", "/assets/..%2f..%2f..%2fapp/main.py"]:
            r = self.c.get(path)
            self.assertNotIn(b"load_settings", r.data, path)
            self.assertIn(r.status_code, (404, 503, 308, 200))


if __name__ == "__main__":
    unittest.main()
