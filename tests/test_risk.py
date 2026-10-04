import unittest

from app.correlation.engine import correlate
from app.correlation.risk import assess_risk
from app.models.evidence import Evidence, IndicatorType, risk_level_for


def ev(source, severity="medium", confidence=0.7, status="detected", finding="Finding"):
    return Evidence("http://evil.example/", IndicatorType.URL, source, "t",
                    finding, severity, confidence, "detail", "", status, "LOCAL_ANALYSIS")


class CorrelationTests(unittest.TestCase):
    def test_deduplication(self):
        out = correlate([ev("A"), ev("A"), ev("B")])
        self.assertEqual((out["total"], out["duplicates_removed"]), (2, 1))

    def test_corroboration_bonus_needs_independent_sources(self):
        two = correlate([ev("A", "high"), ev("B", "high")])
        self.assertEqual(two["corroboration_bonus"], 8)
        one = correlate([ev("A", "high"), ev("A2", "low")])
        self.assertEqual(one["corroboration_bonus"], 0)

    def test_not_found_is_not_a_clean_verdict(self):
        out = correlate([ev("A", "info", status="not_found", finding="No record")])
        self.assertIn("does not prove safety", out["explanation"])

    def test_evidence_sorted_by_contribution(self):
        out = correlate([ev("Weak", "low", 0.5), ev("Strong", "high", 0.9)])
        self.assertEqual(out["evidence"][0]["source"], "Strong")


class RiskTests(unittest.TestCase):
    def test_clean_scan_scores_minimal(self):
        corr = correlate([ev("PhishGuard Local", "info", 0.6, "informational", "All clear")])
        risk = assess_risk([], corr)
        self.assertEqual(risk_level_for(risk["score"]), "Minimal")
        self.assertEqual(risk["verdict"], "likely_safe")

    def test_local_signals_raise_score_with_explanations(self):
        corr = correlate([ev("PhishGuard Local", "high", 0.8)])
        risk = assess_risk([{"id": "ip_host", "weight": 25, "severity": "high"},
                            {"id": "brand_mismatch", "weight": 25, "severity": "high"}], corr)
        self.assertGreaterEqual(risk["score"], 40)
        self.assertTrue(risk["contributions"])
        self.assertIn(risk["verdict"], ("uncertain", "suspicious"))

    def test_heuristics_alone_never_claim_certainty(self):
        corr = correlate([ev("PhishGuard Local", "high", 0.9)])
        risk = assess_risk([{"id": f"s{i}", "weight": 40, "severity": "high"} for i in range(10)], corr)
        self.assertNotEqual(risk["verdict"], "likely_malicious")
        self.assertLessEqual(risk["score"], 100)

    def test_intel_hit_can_confirm(self):
        corr = correlate([ev("PhishTank", "critical", 0.9)])
        risk = assess_risk([{"id": "ip_host", "weight": 25, "severity": "high"}], corr, provider_hits=1)
        self.assertIn(risk["verdict"], ("suspicious", "likely_malicious"))

    def test_confidence_separate_from_risk(self):
        corr = correlate([ev("PhishGuard Local", "high", 0.9)])
        risk = assess_risk([{"id": "ip_host", "weight": 25, "severity": "high"}], corr)
        self.assertIn(risk["confidence_label"], ("Low", "Moderate", "High"))
        self.assertNotEqual(risk["score"], risk["confidence"])


if __name__ == "__main__":
    unittest.main()
