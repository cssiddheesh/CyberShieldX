import unittest

from app.core.config import load_settings
from app.core.indicators import identify, is_valid_hostname
from app.core.security import RateLimiter, clean_text
from app.models.evidence import (Evidence, IndicatorType, ResultOrigin, Severity, confidence_label,
                                 risk_level_for)


class ConfigTests(unittest.TestCase):
    def test_missing_keys_are_simply_absent(self):
        s = load_settings({}, read_dotenv=False)
        self.assertFalse(s.has_key("virustotal"))
        self.assertEqual(s.key("virustotal"), "")

    def test_keys_are_trimmed_and_never_public(self):
        s = load_settings({"VIRUSTOTAL_API_KEY": ' "abc123" '}, read_dotenv=False)
        self.assertEqual(s.key("virustotal"), "abc123")
        self.assertNotIn("abc123", str(s.public_dict()))
        self.assertNotIn("abc123", repr(s))

    def test_numeric_settings_are_clamped_and_validated(self):
        s = load_settings({"CYBERSHIELD_MAX_UPLOAD_MB": "9999", "CYBERSHIELD_HTTP_TIMEOUT": "abc",
                           "CYBERSHIELD_HTTP_RETRIES": "-3", "CYBERSHIELD_PORT": "70000"}, read_dotenv=False)
        self.assertEqual(s.max_upload_bytes, 100 * 1024 * 1024)
        self.assertEqual(s.http_timeout, 8.0)
        self.assertEqual(s.http_retries, 0)
        self.assertEqual(s.port, 65535)

    def test_demo_default_flag(self):
        self.assertTrue(load_settings({"CYBERSHIELD_DEMO_MODE": "True"}, read_dotenv=False).demo_mode_default)
        self.assertFalse(load_settings({"CYBERSHIELD_DEMO_MODE": ""}, read_dotenv=False).demo_mode_default)


class IdentifyTests(unittest.TestCase):
    def kind(self, text):
        return identify(text).indicator_type

    def test_types(self):
        cases = {
            "https://example.com/login?x=1": IndicatorType.URL,
            "http://192.168.1.5:8080/a": IndicatorType.URL,
            "example.com": IndicatorType.DOMAIN,
            "sub.example.co.uk": IndicatorType.DOMAIN,
            "8.8.8.8": IndicatorType.IPV4,
            "2001:db8::1": IndicatorType.IPV6,
            "[2001:db8::1]": IndicatorType.IPV6,
            "d41d8cd98f00b204e9800998ecf8427e": IndicatorType.MD5,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709": IndicatorType.SHA1,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": IndicatorType.SHA256,
            "CVE-2021-44228": IndicatorType.CVE,
            "cve-2024-3094": IndicatorType.CVE,
            "www.example.com/path": IndicatorType.URL,
        }
        for text, expected in cases.items():
            self.assertEqual(self.kind(text), expected, text)

    def test_invalid_inputs_are_unknown_not_guessed(self):
        for text in ["", "   ", "999.1.1.1", "ftp://x.com", "javascript:alert(1)", "hello world",
                     "abc", "cve-21-1", "a" * 5000, "http://", "-bad-.com", "12345"]:
            self.assertEqual(self.kind(text), IndicatorType.UNKNOWN, text[:30])

    def test_defanged_links_are_restored(self):
        r = identify("hxxps://evil[.]example[.]com/login")
        self.assertEqual(r.indicator_type, IndicatorType.URL)
        self.assertEqual(r.normalized, "https://evil.example.com/login")
        self.assertTrue(r.notes)

    def test_hash_is_lowercased_and_routed(self):
        r = identify("D41D8CD98F00B204E9800998ECF8427E")
        self.assertEqual((r.normalized, r.module), ("d41d8cd98f00b204e9800998ecf8427e", "files"))

    def test_hostname_validation(self):
        self.assertTrue(is_valid_hostname("example.com"))
        self.assertFalse(is_valid_hostname("localhost"))
        self.assertFalse(is_valid_hostname("exa mple.com"))
        self.assertFalse(is_valid_hostname("1.2.3.999"))


class SecurityTests(unittest.TestCase):
    def test_rate_limiter_blocks_then_recovers(self):
        now = [0.0]
        rl = RateLimiter(3, 60, clock=lambda: now[0])
        self.assertTrue(all(rl.allow("a")[0] for _ in range(3)))
        allowed, retry = rl.allow("a")
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)
        self.assertTrue(rl.allow("b")[0])  # other clients unaffected
        now[0] = 61
        self.assertTrue(rl.allow("a")[0])

    def test_clean_text(self):
        self.assertEqual(clean_text("a\x00b\x07c"), "abc")
        self.assertEqual(len(clean_text("x" * 10000, 100)), 100)


class EvidenceTests(unittest.TestCase):
    def make(self, **kw):
        base = dict(indicator="example.com", indicator_type="domain", source="Test", source_type="t",
                    finding="Something", severity="high", confidence=0.9, evidence="e")
        base.update(kw)
        return Evidence(**base)

    def test_coercion_and_clamping(self):
        e = self.make(confidence=7, severity="HIGH" if False else "high")
        self.assertEqual(e.confidence, 1.0)
        self.assertIs(e.severity, Severity.HIGH)
        self.assertIs(e.indicator_type, IndicatorType.DOMAIN)

    def test_required_fields(self):
        with self.assertRaises(ValueError):
            self.make(source=" ")
        with self.assertRaises(ValueError):
            self.make(finding="")
        with self.assertRaises(ValueError):
            self.make(confidence="lots")

    def test_roundtrip_and_dedupe_key(self):
        e = self.make(origin=ResultOrigin.DEMO)
        again = Evidence.from_dict(e.to_dict())
        self.assertEqual(again.to_dict(), e.to_dict())
        self.assertEqual(e.dedupe_key(), self.make(indicator="EXAMPLE.com").dedupe_key())

    def test_oversized_fields_are_bounded(self):
        e = self.make(evidence="x" * 50000, finding="f" * 5000)
        self.assertLessEqual(len(e.evidence), 2000)
        self.assertLessEqual(len(e.finding), 300)

    def test_risk_levels_match_prd_table(self):
        pairs = {0: "Minimal", 19: "Minimal", 20: "Low", 39: "Low", 40: "Moderate", 59: "Moderate",
                 60: "High", 79: "High", 80: "Critical", 100: "Critical", -5: "Minimal", 400: "Critical"}
        for score, level in pairs.items():
            self.assertEqual(risk_level_for(score), level, score)

    def test_confidence_labels_are_separate_from_risk(self):
        self.assertEqual([confidence_label(x) for x in (0.1, 0.5, 0.9)], ["Low", "Moderate", "High"])


if __name__ == "__main__":
    unittest.main()
