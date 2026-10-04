import unittest

from app.core.config import load_settings
from app.intelligence.http import HttpResult
from app.intelligence.providers.circlvuln import CirclVulnProvider, cvss_from_record, severity_for_score
from app.intelligence.providers.hashlookup import CirclHashlookupProvider
from app.intelligence.providers.hibp import HibpPasswordsProvider, sha1_upper
from app.intelligence.providers.ipinfo import IpInfoProvider
from app.intelligence.providers.malwarebazaar import MalwareBazaarProvider
from app.intelligence.providers.virustotal import VirusTotalUrlProvider
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


class Phase3ProviderTests(unittest.TestCase):
    def test_hibp_sends_only_prefix_and_matches_locally(self):
        secret = "S3cret-Test-Value!9"
        digest = sha1_upper(secret)
        body = f"{digest[5:]}:999\nAAAAA11111111111111111111111111111:2\n"
        fake = FakeHttp(HttpResult(True, 200, body, latency_ms=5))
        r = HibpPasswordsProvider(settings_with(), http=fake).check(secret, IndicatorType.PASSWORD)
        self.assertEqual(r.evidence[0].status.value, "detected")
        self.assertIn("999", r.evidence[0].finding)
        sent_url = fake.calls[0][1]
        sent_path = sent_url.split("api.pwnedpasswords.com/range/")[-1]
        self.assertEqual(sent_path, digest[:5])  # only the 5-char prefix leaves the machine
        # the plaintext secret value appears nowhere in evidence
        self.assertNotIn(secret, str(r.evidence[0].to_dict()))

    def test_hibp_no_match(self):
        fake = FakeHttp(HttpResult(True, 200, "AAAAA11111111111111111111111111111:2\n"))
        r = HibpPasswordsProvider(settings_with(), http=fake).check("unique-thing", IndicatorType.PASSWORD)
        self.assertEqual(r.evidence[0].status.value, "not_found")

    def test_hibp_requires_no_key(self):
        self.assertTrue(HibpPasswordsProvider(settings_with()).settings is not None)
        r = HibpPasswordsProvider(settings_with(), http=FakeHttp(HttpResult(False, None, error="timeout")))
        self.assertEqual(r.check("x", IndicatorType.PASSWORD).state.value, "UNAVAILABLE")

    def test_sha1_upper(self):
        self.assertEqual(sha1_upper("password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")

    def test_hashlookup_known_is_informational_not_malicious(self):
        body = {"FileName": "notepad.exe", "FileSize": "193024", "source": "NSRL"}
        fake = FakeHttp(HttpResult(True, 200, body))
        r = CirclHashlookupProvider(settings_with(), http=fake).check(
            "8ED4B4ED952526D89899E723F3488DE4", IndicatorType.MD5)
        ev = r.evidence[0]
        self.assertEqual((ev.status.value, ev.severity.value), ("informational", "info"))

    def test_hashlookup_404_is_unknown_not_clean(self):
        fake = FakeHttp(HttpResult(False, 404, error="http_error"))
        r = CirclHashlookupProvider(settings_with(), http=fake).check(
            "8ED4B4ED952526D89899E723F3488DE4", IndicatorType.MD5)
        self.assertEqual(r.evidence[0].status.value, "not_found")

    def test_malwarebazaar_hit_and_miss(self):
        hit = {"query_status": "ok", "data": [{"signature": "Emotet", "file_type_mime": "application/x-dosexec",
                                               "first_seen": "2021-01-01", "tags": ["exe"]}]}
        p = MalwareBazaarProvider(settings_with(MALWAREBAZAAR_API_KEY="k"),
                                  http=FakeHttp(HttpResult(True, 200, hit)))
        r = p.check("e" * 64, IndicatorType.SHA256)
        self.assertEqual((r.evidence[0].status.value, r.evidence[0].severity.value),
                         ("detected", "critical"))
        miss = MalwareBazaarProvider(settings_with(MALWAREBAZAAR_API_KEY="k"),
                                     http=FakeHttp(HttpResult(True, 200, {"query_status": "hash_not_found"})))
        self.assertEqual(miss.check("e" * 64, IndicatorType.SHA256).evidence[0].status.value, "not_found")

    def test_malwarebazaar_missing_key(self):
        r = MalwareBazaarProvider(settings_with()).check("e" * 64, IndicatorType.SHA256)
        self.assertEqual(r.state.value, "NOT_CONFIGURED")

    def test_circlvuln_parses_cvss(self):
        record = {"cveMetadata": {"cveId": "CVE-2021-44228"},
                  "containers": {"cna": {
                      "descriptions": [{"lang": "en", "value": "Log4j flaw."}],
                      "affected": [{"vendor": "Apache", "product": "Log4j"}],
                      "metrics": [{"cvssV3_1": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}],
                      "references": [{"url": "https://example.com/advisory"}]}}}
        self.assertEqual(cvss_from_record(record), (10.0, "critical"))
        self.assertEqual(severity_for_score(10.0), "critical")
        self.assertEqual(severity_for_score(None), "medium")
        p = CirclVulnProvider(settings_with(), http=FakeHttp(HttpResult(True, 200, record)))
        r = p.check("CVE-2021-44228", IndicatorType.CVE)
        self.assertEqual(r.evidence[0].severity.value, "critical")
        self.assertIn("Log4j", r.evidence[0].evidence)

    def test_circlvuln_404(self):
        p = CirclVulnProvider(settings_with(), http=FakeHttp(HttpResult(False, 404, error="http_error")))
        self.assertEqual(p.check("CVE-2099-0001", IndicatorType.CVE).evidence[0].status.value, "not_found")

    def test_ipinfo_lite_shape_and_missing_key(self):
        body = {"ip": "8.8.8.8", "asn": "AS15169", "as_name": "Google LLC",
                "country": "United States", "continent": "North America"}
        fake = FakeHttp(HttpResult(True, 200, body))
        r = IpInfoProvider(settings_with(IPINFO_TOKEN="t"), http=fake).check("8.8.8.8", IndicatorType.IPV4)
        self.assertEqual(r.evidence[0].status.value, "informational")
        self.assertIn("AS15169", r.evidence[0].evidence)
        called_url = fake.calls[0][1]
        self.assertIn("/lite/8.8.8.8", called_url)
        nokey = IpInfoProvider(settings_with()).check("8.8.8.8", IndicatorType.IPV4)
        self.assertEqual(nokey.state.value, "NOT_CONFIGURED")

    def test_virustotal_file_and_ip_endpoints(self):
        stats = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 3, "suspicious": 0, "harmless": 60, "undetected": 5}}}}
        fake = FakeHttp(HttpResult(True, 200, stats))
        p = VirusTotalUrlProvider(settings_with(VIRUSTOTAL_API_KEY="k"), http=fake)
        r = p.check("e" * 64, IndicatorType.SHA256)
        self.assertEqual(r.evidence[0].status.value, "detected")
        self.assertIn("/files/", fake.calls[0][1])
        r2 = p.check("8.8.8.8", IndicatorType.IPV4)
        self.assertIn("/ip_addresses/", fake.calls[1][1])
        self.assertEqual(r2.evidence[0].status.value, "detected")


if __name__ == "__main__":
    unittest.main()
