import unittest

from app.ai.analyst import build_assessment
from tests.helpers import make_app

FORBIDDEN = ("definitely", "certainly", "proven", "guaranteed", "100% safe", "no doubt")


def sample_inputs(**over):
    correlation = {
        "evidence": [
            {"indicator": "http://evil.example/", "indicator_type": "url", "source": "PhishGuard Local",
             "source_type": "t", "finding": "Link uses an IP address", "severity": "high",
             "confidence": 0.85, "evidence": "detail", "reference": "",
             "status": "detected", "origin": "LOCAL_ANALYSIS", "timestamp": "t",
             "source_weight": 0.7, "contribution": 20.0},
            {"indicator": "http://evil.example/", "indicator_type": "url", "source": "PhishTank",
             "source_type": "t", "finding": "PhishTank phishing record", "severity": "critical",
             "confidence": 0.9, "evidence": "detail", "reference": "",
             "status": "detected", "origin": "LIVE_RESULT", "timestamp": "t",
             "source_weight": 0.85, "contribution": 30.0},
            {"indicator": "http://evil.example/", "indicator_type": "url", "source": "URLhaus",
             "source_type": "t", "finding": "No record", "severity": "info",
             "confidence": 0.7, "evidence": "detail", "reference": "",
             "status": "not_found", "origin": "LIVE_RESULT", "timestamp": "t",
             "source_weight": 0.9, "contribution": 0.0},
        ],
        "explanation": "3 items combined.",
        "origins": ["LOCAL_ANALYSIS", "LIVE_RESULT"],
    }
    base = dict(module_label="PhishGuard", target="http://evil.example/",
                risk={"level": "High", "score": 72, "confidence": 0.62,
                      "confidence_label": "Moderate", "verdict": "suspicious",
                      "summary": "s", "contributions": []},
                correlation=correlation, recommendations=["Do X."],
                limitations=["Limitation."], providers=[], is_demo=False)
    base.update(over)
    return base


class AnalystTests(unittest.TestCase):
    def test_sections_present_and_labelled(self):
        ai = build_assessment(**sample_inputs())
        for key in ("executive_summary", "observed", "assessment", "key_findings",
                    "recommendations", "limitations", "uncertainty", "grounding"):
            self.assertIn(key, ai, key)
        self.assertTrue(all(f["type"] == "observed" for f in ai["key_findings"]))
        self.assertTrue(all(u["type"] == "uncertain" for u in ai["uncertainty"]))
        self.assertTrue(all(r["type"] == "recommendation" for r in ai["recommendations"]))

    def test_every_finding_cites_real_evidence(self):
        ai = build_assessment(**sample_inputs())
        evidence = sample_inputs()["correlation"]["evidence"]
        sources = {e["source"] for e in evidence}
        for finding in ai["key_findings"]:
            ref = finding["evidence_ref"]
            self.assertLess(ref, len(evidence))
            self.assertIn(evidence[ref]["source"], finding["statement"])
        self.assertTrue(set(ai["grounding"]["sources"]) <= (sources | {"unknown"}))
        self.assertEqual(ai["grounding"]["evidence_count"], len(evidence))

    def test_never_claims_certainty(self):
        ai = build_assessment(**sample_inputs())
        blob = " ".join([ai["executive_summary"], ai["assessment"], *ai["observed"]]).lower()
        for word in FORBIDDEN:
            self.assertNotIn(word, blob)

    def test_uncertainty_lists_gaps(self):
        ai = build_assessment(**sample_inputs())
        blob = " ".join(u["text"] for u in ai["uncertainty"]).lower()
        self.assertIn("does not prove safety", blob)  # the not_found row is disclosed

    def test_demo_is_labelled(self):
        ai = build_assessment(**sample_inputs(is_demo=True))
        self.assertTrue(ai["executive_summary"].startswith("DEMONSTRATION DATA"))

    def test_empty_evidence_still_honest(self):
        kwargs = sample_inputs()
        kwargs["correlation"] = {"evidence": [], "explanation": "none", "origins": []}
        ai = build_assessment(**kwargs)
        self.assertIn("no", ai["assessment"].lower())

    def test_all_pipelines_attach_ai_analysis(self):
        app, _ = make_app({})
        c = app.test_client()
        scans = [
            c.post("/api/scans", json={"input": "http://192.0.2.10/login"}),
            c.post("/api/scans", json={"input": "d41d8cd98f00b204e9800998ecf8427e"}),
            c.post("/api/scans", json={"input": "8.8.8.8"}),
            c.post("/api/scans", json={"input": "CVE-2021-44228"}),
            c.post("/api/scans/password", json={"password": "password"}),
        ]
        for r in scans:
            self.assertEqual(r.status_code, 201, r.get_data(as_text=True)[:200])
            ai = r.get_json()["ai_analysis"]
            self.assertIn("executive_summary", ai)
            self.assertTrue(ai["key_findings"] or ai["observed"])


if __name__ == "__main__":
    unittest.main()
