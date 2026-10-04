import unittest

from app.core.config import load_settings
from app.intelligence.http import HttpResult
from app.intelligence.providers.phishtank import PhishTankProvider
from app.intelligence.providers.safebrowsing import SafeBrowsingProvider
from app.intelligence.providers.urlhaus import UrlHausProvider
from app.intelligence.providers.urlscan import UrlScanProvider
from app.intelligence.providers.virustotal import VirusTotalUrlProvider, url_id
from app.models.evidence import IndicatorType


class FakeHttp:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.result

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.result


def settings_with(**keys):
    return load_settings(keys, read_dotenv=False)


class ProviderContractTests(unittest.TestCase):
    def test_missing_key_is_not_configured(self):
        s = settings_with()
        r = UrlHausProvider(s).check("http://evil.example/", IndicatorType.URL)
        self.assertEqual(r.state.value, "NOT_CONFIGURED")
        self.assertFalse(r.evidence)
        r = SafeBrowsingProvider(s).check("http://evil.example/", IndicatorType.URL)
        self.assertEqual(r.state.value, "NOT_CONFIGURED")

    def test_phishtank_works_without_key_but_sends_user_agent(self):
        fake = FakeHttp(HttpResult(True, 200, {"results": {"in_database": False}}, latency_ms=5))
        p = PhishTankProvider(settings_with(), http=fake)
        r = p.check("http://evil.example/", IndicatorType.URL)
        self.assertEqual(r.state.value, "AVAILABLE")
        self.assertEqual(r.evidence[0].status.value, "not_found")
        self.assertIn("User-Agent", fake.calls[0][2]["headers"])

    def test_urlhaus_hit(self):
        body = {"query_status": "ok", "threat": "malware_download", "malware": "Emotet"}
        p = UrlHausProvider(settings_with(URLHAUS_API_KEY="k"), http=FakeHttp(HttpResult(True, 200, body)))
        r = p.check("http://evil.example/x.exe", IndicatorType.URL)
        self.assertEqual(r.evidence[0].severity.value, "critical")
        self.assertEqual(r.evidence[0].status.value, "detected")

    def test_urlhaus_no_results_is_not_clean(self):
        p = UrlHausProvider(settings_with(URLHAUS_API_KEY="k"),
                            http=FakeHttp(HttpResult(True, 200, {"query_status": "no_results"})))
        r = p.check("http://evil.example/", IndicatorType.URL)
        self.assertEqual(r.evidence[0].status.value, "not_found")

    def test_rate_limit_and_timeout_states(self):
        p = UrlHausProvider(settings_with(URLHAUS_API_KEY="k"),
                            http=FakeHttp(HttpResult(False, 429, error="rate_limited")))
        self.assertEqual(p.check("http://e.example/", IndicatorType.URL).state.value, "RATE_LIMITED")
        p = PhishTankProvider(settings_with(), http=FakeHttp(HttpResult(False, None, error="timeout")))
        self.assertEqual(p.check("http://e.example/", IndicatorType.URL).state.value, "UNAVAILABLE")

    def test_malformed_response_is_error_not_crash(self):
        p = UrlHausProvider(settings_with(URLHAUS_API_KEY="k"),
                            http=FakeHttp(HttpResult(False, 200, error="bad_json")))
        r = p.check("http://e.example/", IndicatorType.URL)
        self.assertEqual(r.state.value, "ERROR")

    def test_urlscan_search_counts_malicious_verdicts(self):
        body = {"total": 2, "results": [
            {"verdicts": {"overall": {"malicious": True}}, "result": "https://urlscan.io/r/1"},
            {"verdicts": {"overall": {"malicious": False}}},
        ]}
        fake = FakeHttp(HttpResult(True, 200, body))
        p = UrlScanProvider(settings_with(URLSCAN_API_KEY="k"), http=fake)
        r = p.check("http://evil.example/", IndicatorType.URL)
        self.assertEqual(r.evidence[0].status.value, "detected")
        self.assertIn("API-Key", fake.calls[0][2]["headers"])

    def test_safebrowsing_match(self):
        body = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
        p = SafeBrowsingProvider(settings_with(GOOGLE_SAFE_BROWSING_API_KEY="k"),
                                 http=FakeHttp(HttpResult(True, 200, body)))
        r = p.check("http://evil.example/", IndicatorType.URL)
        self.assertEqual(r.evidence[0].severity.value, "critical")

    def test_virustotal_stats(self):
        attrs = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10}}}}
        p = VirusTotalUrlProvider(settings_with(VIRUSTOTAL_API_KEY="k"),
                                  http=FakeHttp(HttpResult(True, 200, attrs)))
        r = p.check("http://evil.example/", IndicatorType.URL)
        self.assertEqual(r.evidence[0].status.value, "detected")
        # 404 means unknown, not safe
        p404 = VirusTotalUrlProvider(settings_with(VIRUSTOTAL_API_KEY="k"),
                                    http=FakeHttp(HttpResult(False, 404, error="http_error")))
        self.assertEqual(p404.check("http://new.example/", IndicatorType.URL).evidence[0].status.value,
                         "not_found")

    def test_url_id_has_no_padding(self):
        self.assertNotIn("=", url_id("http://example.com/"))

    def test_adapters_never_raise(self):
        class Boom:
            def get(self, *a, **k):
                raise RuntimeError("boom")

            def post(self, *a, **k):
                raise RuntimeError("boom")

        for cls, env in [(UrlHausProvider, {"URLHAUS_API_KEY": "k"}),
                         (PhishTankProvider, {}),
                         (UrlScanProvider, {"URLSCAN_API_KEY": "k"}),
                         (SafeBrowsingProvider, {"GOOGLE_SAFE_BROWSING_API_KEY": "k"}),
                         (VirusTotalUrlProvider, {"VIRUSTOTAL_API_KEY": "k"})]:
            r = cls(settings_with(**env), http=Boom()).check("http://e.example/", IndicatorType.URL)
            self.assertEqual(r.origin.value, "PROVIDER_ERROR")


if __name__ == "__main__":
    unittest.main()
