import json
import unittest
from unittest import mock

from app.ai.llm import (
    build_prompt, generate_enhancement, resolve_config, validate_enhancement,
)
from app.core.config import load_settings
from app.intelligence.http import HttpResult
from tests.helpers import make_app

GOOD_JSON = json.dumps({
    "plain_summary": "This link looks risky because it uses an IP host.",
    "what_matters": ["PhishTank: phishing record with high confidence."],
    "next_steps": ["Do not visit the link."],
    "blind_spots": ["URLhaus could not be reached."],
})


def fake_ok(content=GOOD_JSON):
    class FakeHttp:
        def __init__(self, *a, **k):
            self.calls = []

        def post(self, url, **kwargs):
            self.calls.append((url, kwargs))
            return HttpResult(True, 200, {"choices": [{"message": {"content": content}}]})
    return FakeHttp()


class LlmUnitTests(unittest.TestCase):
    def test_validator_accepts_good_shape(self):
        out = validate_enhancement(json.loads(GOOD_JSON))
        self.assertTrue(out["plain_summary"].startswith("This link"))

    def test_validator_rejects_invention_shapes(self):
        self.assertIsNone(validate_enhancement({"plain_summary": "x"}))
        self.assertIsNone(validate_enhancement({"plain_summary": "x", "what_matters": [],
                                                "next_steps": ["y"], "blind_spots": []}))
        self.assertIsNone(validate_enhancement("not json"))
        self.assertIsNone(validate_enhancement({"plain_summary": "", "what_matters": ["a"],
                                                "next_steps": ["b"], "blind_spots": []}))

    def test_prompt_contains_only_evidence(self):
        report = {"module_label": "PhishGuard", "target": "http://evil.example/",
                  "overall_risk": "High", "risk_score": 72,
                  "ai_analysis": {"executive_summary": "s"},
                  "evidence": [{"source": "S", "finding": "F", "severity": "high",
                                "confidence": 0.9, "evidence": "d" * 2000,
                                "status": "detected", "origin": "LIVE_RESULT"}]}
        messages = build_prompt(report)
        blob = json.dumps(messages)
        self.assertIn("http://evil.example/", blob)
        self.assertLess(len(blob), 20000)  # truncated, bounded

    def test_not_configured_without_key(self):
        from app.ai.llm import AiConfig
        out, err = generate_enhancement({}, AiConfig(api_key=""))
        self.assertEqual((out, err), (None, "not_configured"))

    def test_bad_model_json_is_rejected(self):
        from app.ai.llm import AiConfig
        out, err = generate_enhancement(
            {"evidence": []}, AiConfig(api_key="k"), http=fake_ok("hello world"))
        self.assertEqual((out, err), (None, "bad_response"))


class AiApiTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app({})
        self.c = self.app.test_client()

    def test_key_lifecycle_never_returns_key(self):
        self.assertFalse(self.c.get("/api/config").get_json()["ai"]["configured"])
        r = self.c.put("/api/settings/ai", json={"api_key": "sk-test-12345678", "model": "gpt-4o-mini"})
        self.assertTrue(r.get_json()["configured"])
        self.assertNotIn("sk-test-12345678", r.get_data(as_text=True))
        for url in ["/api/config", "/api/sources", "/api/dashboard", "/api/settings"]:
            body = self.c.get(url).get_data(as_text=True) if url != "/api/settings" else ""
            self.assertNotIn("sk-test-12345678", body, url)
        self.assertEqual(self.c.put("/api/settings/ai", json={"api_key": "x"}).status_code, 400)
        self.assertEqual(self.c.put("/api/settings/ai", json={"base_url": "ftp://x"}).status_code, 400)
        self.c.put("/api/settings/ai", json={"api_key": ""})
        self.assertFalse(self.c.get("/api/config").get_json()["ai"]["configured"])

    def test_enhance_needs_key(self):
        scan = self.c.post("/api/scans", json={"input": "https://example.com/"}).get_json()
        r = self.c.post(f"/api/scans/{scan['scan_id']}/ai", json={})
        self.assertEqual(r.status_code, 400)

    def test_enhance_flow_caches_and_attaches(self):
        self.c.put("/api/settings/ai", json={"api_key": "sk-test-12345678"})
        scan = self.c.post("/api/scans", json={"input": "https://example.com/"}).get_json()
        calls = []

        def factory(*a, **k):
            fake = fake_ok()
            calls.append(fake)
            return fake

        with mock.patch("app.ai.llm.HttpClient", side_effect=factory):
            first = self.c.post(f"/api/scans/{scan['scan_id']}/ai", json={})
            second = self.c.post(f"/api/scans/{scan['scan_id']}/ai", json={})
        self.assertEqual(first.status_code, 200)
        self.assertIn("looks risky", first.get_json()["plain_summary"])
        self.assertEqual(second.get_json(), first.get_json())
        self.assertEqual(len(calls), 1)  # second call served from cache, no spend
        attached = self.c.get(f"/api/scans/{scan['scan_id']}").get_json()
        self.assertEqual(attached["ai_enhanced"]["plain_summary"],
                         first.get_json()["plain_summary"])
        self.assertEqual(self.c.post("/api/scans/CSX-NOPE/ai", json={}).status_code, 404)

    def test_password_secret_never_reaches_model(self):
        secret = "Ultra-Secret-PW-42!"
        self.c.put("/api/settings/ai", json={"api_key": "sk-test-12345678"})
        scan = self.c.post("/api/scans/password", json={"password": secret}).get_json()
        seen = {}

        class SpyHttp:
            def __init__(self, *a, **k):
                pass

            def post(self, url, **kwargs):
                seen["body"] = json.dumps(kwargs.get("json_body", {}))
                return HttpResult(True, 200, {"choices": [{"message": {"content": GOOD_JSON}}]})

        with mock.patch("app.ai.llm.HttpClient", side_effect=lambda *a, **k: SpyHttp()):
            r = self.c.post(f"/api/scans/{scan['scan_id']}/ai", json={})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(secret, seen.get("body", ""))
        self.assertNotIn(secret, r.get_data(as_text=True))

    def test_model_failure_is_safe_502(self):
        self.c.put("/api/settings/ai", json={"api_key": "sk-test-12345678"})
        scan = self.c.post("/api/scans", json={"input": "https://example.com/"}).get_json()

        class FailHttp:
            def __init__(self, *a, **k):
                pass

            def post(self, url, **kwargs):
                return HttpResult(False, 401, error="http_error")

        with mock.patch("app.ai.llm.HttpClient", side_effect=lambda *a, **k: FailHttp()):
            r = self.c.post(f"/api/scans/{scan['scan_id']}/ai", json={})
        self.assertEqual(r.status_code, 502)
        self.assertIn("key", r.get_json()["error"]["message"].lower())


if __name__ == "__main__":
    unittest.main()
