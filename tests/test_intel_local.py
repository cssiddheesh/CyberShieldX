import io
import unittest

from app.analyzers.files import analyze_file, hash_bytes, identify_hash_type
from app.analyzers.network import analyze_network, classify_ip
from app.analyzers.passwords import analyze_password, assess_password_risk
from app.analyzers.vulnerabilities import analyze_cve, parse_cve, risk_for_cvss
from app.models.evidence import IndicatorType


class PasswordLocalTests(unittest.TestCase):
    def test_common_password_is_critical(self):
        local = analyze_password("password")
        self.assertEqual(local["strength_category"], "Very weak")
        self.assertTrue(local["is_common"])
        self.assertIn("common_password", {i["id"] for i in local["indicators"]})

    def test_strong_passphrase_scores_high(self):
        local = analyze_password("Correct-Horse 9 Battery!Staple")
        self.assertIn(local["strength_category"], ("Strong", "Very strong"))
        self.assertGreaterEqual(local["diversity"], 3)

    def test_sequences_and_repeats_flagged(self):
        ids = {i["id"] for i in analyze_password("abc123aaa")["indicators"]}
        self.assertTrue({"sequence", "repeated_chars"} <= ids)

    def test_risk_compounds_strength_and_exposure(self):
        weak = analyze_password("qwerty123")
        risk = assess_password_risk(weak, 50000, True)
        self.assertEqual(risk["verdict"], "critical")
        strong = analyze_password("X7#kq!Vm2zQw9$pL4")
        safe = assess_password_risk(strong, 0, True)
        self.assertEqual(safe["verdict"], "strong")
        unknown = assess_password_risk(strong, None, False)
        self.assertEqual(unknown["confidence"], 0.6)

    def test_no_plaintext_in_evidence(self):
        secret = "Sup3r-Secret-XYZ-123!"
        local = analyze_password(secret)
        self.assertNotIn(secret, str(local["evidence"]))


class FileLocalTests(unittest.TestCase):
    def test_hashes_are_correct(self):
        digests = hash_bytes(b"abc")
        self.assertEqual(digests["md5"], "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(digests["sha256"],
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_double_extension_flagged(self):
        result = analyze_file(b"X" * 5000, "invoice.pdf.exe")
        self.assertIn("double_extension", {i["id"] for i in result["indicators"]})

    def test_hash_type_identification(self):
        self.assertEqual(identify_hash_type("d41d8cd98f00b204e9800998ecf8427e"), IndicatorType.MD5)
        self.assertEqual(identify_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"), IndicatorType.SHA1)
        self.assertEqual(identify_hash_type("e" * 64), IndicatorType.SHA256)
        self.assertIsNone(identify_hash_type("not-a-hash"))
        self.assertIsNone(identify_hash_type("abc123"))


class NetworkLocalTests(unittest.TestCase):
    def test_private_and_loopback_classified(self):
        self.assertIn("private-use (LAN/VPN, not Internet-routable)",
                      classify_ip("192.168.1.1")["flags"])
        self.assertIn("loopback (this computer)", classify_ip("127.0.0.1")["flags"])
        self.assertIn("globally routable", classify_ip("8.8.8.8")["flags"])

    def test_invalid_ip(self):
        self.assertFalse(classify_ip("999.1.1.1")["valid"])

    def test_domain_facts(self):
        result = analyze_network("a.b.c.d.example.com", IndicatorType.DOMAIN)
        self.assertEqual(result["facts"]["subdomain_count"], 4)
        self.assertIn("many_subdomains", {i["id"] for i in result["indicators"]})


class CveLocalTests(unittest.TestCase):
    def test_parse(self):
        parsed = parse_cve("cve-2021-44228")
        self.assertEqual((parsed["valid"], parsed["normalized"], parsed["year"]),
                         (True, "CVE-2021-44228", 2021))
        self.assertFalse(parse_cve("cve-21-1")["valid"])

    def test_reference_lookup(self):
        result = analyze_cve("CVE-2021-44228")
        self.assertIsNotNone(result["reference"])
        self.assertEqual(result["reference"]["cvss"], 10.0)
        self.assertIn("Log4j", result["reference"]["title"])

    def test_unknown_cve_has_no_reference(self):
        result = analyze_cve("CVE-2099-0001")
        self.assertIsNone(result["reference"])

    def test_cvss_mapping(self):
        self.assertEqual(risk_for_cvss(10.0), (100, "Critical"))
        self.assertEqual(risk_for_cvss(7.5), (75, "High"))
        self.assertEqual(risk_for_cvss(None), (30, "Low"))


if __name__ == "__main__":
    unittest.main()
