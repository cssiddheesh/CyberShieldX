import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from app.intelligence.http import HttpClient


class Handler(BaseHTTPRequestHandler):
    hits = {}

    def log_message(self, *a):  # keep test output quiet
        pass

    def _send(self, status, body=b"{}", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # client gave up (timeout test)

    def do_GET(self):
        Handler.hits[self.path] = Handler.hits.get(self.path, 0) + 1
        n = Handler.hits[self.path]
        if self.path == "/ok":
            self._send(200, json.dumps({"hello": "world"}).encode())
        elif self.path == "/bad-json":
            self._send(200, b"<html>not json</html>")
        elif self.path == "/rate":
            self._send(429, b"{}", {"Retry-After": "30"})
        elif self.path == "/flaky":
            self._send(503) if n < 3 else self._send(200, b'{"ok": true}')
        elif self.path == "/always-500":
            self._send(500)
        elif self.path == "/notfound":
            self._send(404)
        elif self.path == "/slow":
            time.sleep(2)
            self._send(200)
        elif self.path == "/huge":
            self._send(200, b"x" * (3 * 1024 * 1024))
        elif self.path == "/redirect":
            self._send(302, b"", {"Location": "http://example.invalid/"})


class HttpClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Handler.hits.clear()
        self.sleeps = []
        self.client = HttpClient(timeout=0.5, retries=2, backoff=0.5, sleep=self.sleeps.append)

    def test_success_parses_json(self):
        r = self.client.get(self.base + "/ok")
        self.assertTrue(r.ok)
        self.assertEqual(r.data, {"hello": "world"})

    def test_malformed_json_is_reported_not_raised(self):
        r = self.client.get(self.base + "/bad-json")
        self.assertFalse(r.ok)
        self.assertEqual(r.error, "bad_json")

    def test_rate_limit_is_not_retried(self):
        r = self.client.get(self.base + "/rate")
        self.assertEqual((r.ok, r.error, r.retry_after), (False, "rate_limited", 30.0))
        self.assertEqual(Handler.hits["/rate"], 1)

    def test_server_errors_retry_with_exponential_backoff(self):
        r = self.client.get(self.base + "/flaky")
        self.assertTrue(r.ok)
        self.assertEqual(Handler.hits["/flaky"], 3)
        self.assertEqual(self.sleeps, [0.5, 1.0])

    def test_retry_limit_is_respected(self):
        r = self.client.get(self.base + "/always-500")
        self.assertEqual((r.ok, r.error), (False, "http_error"))
        self.assertEqual(Handler.hits["/always-500"], 3)

    def test_client_errors_are_not_retried(self):
        r = self.client.get(self.base + "/notfound")
        self.assertEqual((r.ok, r.status), (False, 404))
        self.assertEqual(Handler.hits["/notfound"], 1)

    def test_timeout(self):
        c = HttpClient(timeout=0.3, retries=0, sleep=self.sleeps.append)
        r = c.get(self.base + "/slow")
        self.assertEqual((r.ok, r.error), (False, "timeout"))

    def test_connection_failure(self):
        c = HttpClient(timeout=0.5, retries=0, sleep=self.sleeps.append)
        r = c.get("http://127.0.0.1:1/")
        self.assertEqual((r.ok, r.error), (False, "network"))

    def test_oversized_response_is_rejected(self):
        r = self.client.get(self.base + "/huge")
        self.assertEqual((r.ok, r.error), (False, "too_large"))

    def test_redirects_are_not_followed(self):
        r = self.client.get(self.base + "/redirect", expect_json=False)
        self.assertEqual(r.status, 302)  # surfaced, never silently followed to another host

    def test_min_interval_throttles(self):
        c = HttpClient(timeout=1, retries=0, min_interval=1.0, sleep=self.sleeps.append)
        c.get(self.base + "/ok")
        c.get(self.base + "/ok")
        self.assertTrue(self.sleeps and self.sleeps[0] > 0)


if __name__ == "__main__":
    unittest.main()
