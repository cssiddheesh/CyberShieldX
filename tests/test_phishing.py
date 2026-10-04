import unittest

from app.analyzers.phishing import analyze_url, extract_features, normalize_url
from app.models.evidence import IndicatorType


class NormalizeTests(unittest.TestCase):
    def test_defanged_url_restored(self):
        url, was = normalize_url("hxxps://evil[.]example[.]com/login")
        self.assertTrue(was)
        self.assertEqual(url, "https://evil.example.com/login")

    def test_scheme_added_and_credentials_stripped(self):
        url, was = normalize_url("example.com/a?b=1#frag")
        self.assertFalse(was)
        self.assertTrue(url.startswith("http://example.com"))
        self.assertNotIn("#frag", url)

    def test_userinfo_stripped(self):
        url, _ = normalize_url("http://user:pass@example.com/")
        self.assertNotIn("user", url)
        self.assertIn("example.com", url)


class FeatureTests(unittest.TestCase):
    def test_ip_host_detected(self):
        f = extract_features("http://192.168.1.5/login")
        self.assertTrue(f.uses_ip_host)
        self.assertFalse(f.uses_https)

    def test_subdomain_and_tld(self):
        f = extract_features("https://a.b.c.example.com/x/y")
        self.assertEqual((f.subdomain_count, f.tld), (3, "com"))

    def test_entropy_positive(self):
        f = extract_features("https://example.com")
        self.assertGreater(f.entropy, 0)


class IndicatorTests(unittest.TestCase):
    def ids(self, raw):
        return {i["id"] for i in analyze_url(raw)["indicators"]}

    def test_clean_url_has_no_indicators(self):
        result = analyze_url("https://example.com/about")
        self.assertEqual(result["indicators"], [])
        self.assertEqual(len(result["evidence"]), 1)  # informational all-clear

    def test_ip_host_and_no_https(self):
        self.assertTrue({"ip_host", "no_https"} <= self.ids("http://192.0.2.10/login"))

    def test_brand_mismatch(self):
        self.assertIn("brand_mismatch", self.ids("http://evil.example/account/paypal/verify-login"))

    def test_shortener_and_redirect_param(self):
        ids = self.ids("https://bit.ly/abc?redirect=https://evil.example")
        self.assertTrue({"url_shortener", "redirect_param"} <= ids)

    def test_suspicious_tld_and_keywords(self):
        ids = self.ids("http://prize-claim-verify.top/login/free-prize")
        self.assertTrue({"suspicious_tld", "suspicious_keywords"} <= ids)

    def test_at_sign_and_punycode(self):
        self.assertIn("at_sign", self.ids("http://trusted@evil.example/"))
        self.assertIn("idn_punycode", self.ids("http://xn--pple-43d.example/"))

    def test_homograph_cyrillic(self):
        self.assertIn("homograph_chars", self.ids("http://exаmple.com/"))

    def test_long_url_and_deep_path(self):
        self.assertIn("long_url", self.ids("https://example.com/" + "a" * 300))
        self.assertIn("deep_path", self.ids("https://example.com/a/b/c/d/e/f"))

    def test_evidence_never_claims_certainty(self):
        result = analyze_url("http://192.0.2.10/paypal/login")
        for item in result["evidence"]:
            self.assertEqual(item["indicator_type"], IndicatorType.URL.value)
            self.assertEqual(item["origin"], "LOCAL_ANALYSIS")
        severities = {e["severity"] for e in result["evidence"]}
        self.assertNotIn("critical", severities)  # heuristics alone: no critical verdicts


if __name__ == "__main__":
    unittest.main()
