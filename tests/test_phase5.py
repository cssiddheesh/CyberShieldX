import io
import struct
import unittest
import zlib

from app.analyzers.media import analyze_image, identify_image
from app.analyzers.textstats import REQUIRED_LIMITATION, analyze_text
from app.lab.quizzes import LAB_MODULES, QUIZZES, grade, public_quiz


def make_png(width=100, height=80, text_chunks=()):
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    out = [b"\x89PNG\r\n\x1a\n"]

    def chunk(ctype, payload):
        out.append(struct.pack(">I", len(payload)) + ctype + payload +
                   struct.pack(">I", zlib.crc32(ctype + payload) & 0xFFFFFFFF))

    chunk(b"IHDR", ihdr)
    for keyword, body in text_chunks:
        chunk(b"tEXt", keyword + b"\x00" + body)
    raw = b"\x00" + b"\x00" * (width * 3) * height
    chunk(b"IDAT", zlib.compress(raw))
    chunk(b"IEND", b"")
    return b"".join(out)


def make_jpeg() -> bytes:
    out = bytearray(b"\xff\xd8")
    out += b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    out += b"\xff\xfe" + struct.pack(">H", 2 + 11) + b"Hello World"
    out += b"\xff\xdb" + struct.pack(">H", 67) + b"\x00" + bytes(range(1, 65))
    out += b"\xff\xc0" + struct.pack(">H", 11) + b"\x08\x00\x40\x00\x50\x01\x01\x11\x00"
    out += b"\xff\xda" + struct.pack(">H", 6) + b"\x00\x00\x00\x00"
    return bytes(out)


HUMAN_TEXT = (
    "I woke up late again. The bus? Gone, obviously. Ran the whole way, coffee sloshing everywhere, "
    "and my boss just laughed. Honestly, mornings hate me. But then - miracle! - Priya had saved me "
    "a seat AND a donut. Best coworker ever. We spent lunch arguing about whether pineapple belongs "
    "on pizza (it does, fight me). By five I was wiped. You know those days? Yeah. Anyway, small wins. "
    "I'll set two alarms tonight. Maybe three. Who am I kidding, I'll still snooze them all. "
    "Life's messy like that, and I kind of love it."
)

AI_TEXT = (
    "Moreover, the landscape of modern cybersecurity is multifaceted and constantly evolving. "
    "Furthermore, organizations must leverage comprehensive strategies to showcase resilience. "
    "Additionally, it is crucial to delve into intricate threat models. In conclusion, the tapestry "
    "of digital defense requires a pivotal and vibrant approach. Moreover, stakeholders should utilize "
    "robust frameworks. Furthermore, continuous monitoring is essential. Additionally, proactive defense "
    "is crucial for success. In summary, the realm of security demands comprehensive vigilance. "
    "Moreover, teams must leverage automation. Furthermore, threat intelligence is pivotal. "
    "Typically, mature programs also emphasize governance. Often, success tends to follow those who "
    "embark on comprehensive transformation journeys. Ultimately, resilience is a testament to diligence. "
    "Moreover, excellence demands showcasing best practices across the organization. Furthermore, leaders "
    "must leverage vibrant partnerships to navigate the intricate threat landscape. Additionally, robust "
    "governance showcases maturity. In conclusion, diligence remains pivotal."
)


class TextAnalyzerTests(unittest.TestCase):
    def test_human_text_scores_low(self):
        result = analyze_text(HUMAN_TEXT)
        self.assertEqual(result["likeness"], "low")
        self.assertLess(result["stats"]["ai_score"], 30)

    def test_ai_style_text_scores_high(self):
        result = analyze_text(AI_TEXT)
        self.assertEqual(result["likeness"], "high")
        self.assertIn("ai_tells", {i["id"] for i in result["indicators"]})

    def test_short_text_inconclusive(self):
        result = analyze_text("Hello world, this is short.")
        self.assertEqual(result["likeness"], "inconclusive")

    def test_limitation_always_present(self):
        for text in (HUMAN_TEXT, AI_TEXT):
            blob = str(analyze_text(text))
            self.assertIn("cannot establish authorship", blob)
        self.assertTrue(REQUIRED_LIMITATION.startswith("AI-text detection is probabilistic"))

    def test_stats_sane(self):
        stats = analyze_text(HUMAN_TEXT)["stats"]
        self.assertGreater(stats["words"], 80)
        self.assertGreater(stats["sentences"], 5)
        self.assertGreaterEqual(stats["vocab_diversity"], 0.3)


class MediaTests(unittest.TestCase):
    def test_png_dimensions_and_software_tag(self):
        result = analyze_image(make_png(100, 80, [(b"Software", b"Adobe Photoshop")]), "shot.png")
        self.assertEqual((result["facts"]["width"], result["facts"]["height"]), (100, 80))
        self.assertIn("editor_tag", {i["id"] for i in result["indicators"]})

    def test_png_without_metadata_flagged_weakly(self):
        result = analyze_image(make_png(), "plain.png")
        ids = {i["id"] for i in result["indicators"]}
        self.assertIn("stripped_metadata", ids)
        for item in result["indicators"]:
            self.assertNotEqual(item["severity"], "critical")  # never decisive

    def test_jpeg_parses_and_estimates_quality(self):
        result = analyze_image(make_jpeg(), "photo.jpg")
        self.assertEqual(result["facts"]["format"], "JPEG")
        self.assertEqual((result["facts"]["width"], result["facts"]["height"]), (80, 64))
        self.assertIn("jpeg_quality_estimate", result["facts"])

    def test_non_image_rejected(self):
        self.assertIsNone(identify_image(b"MZ\x90\x00evil"))
        with self.assertRaises(ValueError):
            analyze_image(b"not an image at all", "x.bin")

    def test_probabilistic_wording(self):
        blob = str(analyze_image(make_png(), "p.png"))
        self.assertIn("never proof", blob)


class LabTests(unittest.TestCase):
    def test_modules_and_blind_quiz(self):
        self.assertEqual(len(LAB_MODULES), 6)
        quiz = public_quiz("phishing")
        self.assertEqual(len(quiz), 5)
        self.assertNotIn("answer", str(quiz))  # answers stay server-side
        self.assertIsNone(public_quiz("nope"))

    def test_grading(self):
        key = "passwords"
        correct = [item["answer"] for item in QUIZZES[key]]
        result = grade(key, correct)
        self.assertEqual((result["score"], result["percent"]), (5, 100))
        wrong = grade(key, [0, 0, 0, 0, 0])
        self.assertLess(wrong["score"], 5)
        self.assertTrue(all("explanation" in r for r in result["results"]))
        self.assertIsNone(grade("nope", []))
        self.assertIsNone(grade(key, "garbage"))  # malformed input -> None, never raises
        self.assertIsNotNone(grade(key, []))


class Phase5ApiTests(unittest.TestCase):
    def setUp(self):
        from tests.helpers import make_app
        self.app, _ = make_app({})
        self.c = self.app.test_client()

    def test_text_scan(self):
        r = self.c.post("/api/scans/text", json={"text": HUMAN_TEXT})
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True)[:200])
        report = r.get_json()
        self.assertEqual(report["module"], "text")
        self.assertIn("ai_analysis", report)
        self.assertEqual(self.c.post("/api/scans/text", json={"text": "  "}).status_code, 400)
        self.assertEqual(self.c.post("/api/scans/text", json={}).status_code, 400)

    def test_media_scan(self):
        data = {"file": (io.BytesIO(make_png()), "shot.png")}
        r = self.c.post("/api/scans/media", data=data, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True)[:200])
        self.assertEqual(r.get_json()["module"], "media")
        bad = {"file": (io.BytesIO(b"MZ executable"), "evil.exe")}
        self.assertEqual(self.c.post(
            "/api/scans/media", data=bad, content_type="multipart/form-data").status_code, 415)

    def test_lab_endpoints(self):
        modules = self.c.get("/api/lab/modules").get_json()["modules"]
        self.assertEqual(len(modules), 6)
        quiz = self.c.get("/api/lab/quiz/phishing").get_json()
        self.assertEqual(quiz["total"], 5)
        self.assertEqual(self.c.get("/api/lab/quiz/nope").status_code, 404)
        answers = [item["answer"] for item in QUIZZES["phishing"]]
        graded = self.c.post("/api/lab/submit", json={"module": "phishing", "answers": answers}).get_json()
        self.assertEqual(graded["percent"], 100)
        self.assertEqual(self.c.post("/api/lab/submit", json={"module": "nope", "answers": []}).status_code, 404)

    def test_pdf_export(self):
        scan = self.c.post("/api/scans", json={"input": "https://example.com/"}).get_json()
        r = self.c.get(f"/api/reports/{scan['scan_id']}.pdf")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["Content-Type"], "application/pdf")
        self.assertTrue(r.data.startswith(b"%PDF"))
        self.assertEqual(self.c.get("/api/reports/CSX-NOPE.pdf").status_code, 404)

    def test_all_modules_available(self):
        status = {m["key"]: m["status"] for m in self.c.get("/api/modules").get_json()["modules"]}
        for key in ("text", "media", "lab", "reports"):
            self.assertEqual(status[key], "available", key)


if __name__ == "__main__":
    unittest.main()
