"""HTTP client for provider adapters.

Adds what PRD section 24 requires: hard timeouts, a retry limit with exponential
backoff, and a per-provider minimum interval between requests. A 429 response is
reported as ``rate_limited`` and is never retried. Errors are returned as data,
never raised, and never include request headers (which may hold API keys).
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

import requests

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


@dataclass
class HttpResult:
    ok: bool
    status: Optional[int] = None
    data: Any = None            # parsed JSON when expect_json=True, else decoded text
    error: Optional[str] = None  # timeout | rate_limited | http_error | bad_json | too_large | network
    retry_after: Optional[float] = None
    latency_ms: Optional[int] = None


class HttpClient:
    def __init__(self, timeout: float = 8.0, retries: int = 2, backoff: float = 0.5,
                 min_interval: float = 0.0, sleep: Callable[[float], None] = time.sleep,
                 session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.retries = max(0, retries)
        self.backoff = backoff
        self.min_interval = min_interval
        self._sleep = sleep
        self._session = session or requests.Session()
        self._last_request = 0.0
        self._lock = threading.Lock()

    def _throttle(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            wait = self.min_interval - (time.monotonic() - self._last_request)
            if wait > 0:
                self._sleep(wait)
            self._last_request = time.monotonic()

    def request(self, method: str, url: str, *, headers: Optional[Mapping[str, str]] = None,
                params: Optional[Mapping[str, Any]] = None, data: Any = None, json_body: Any = None,
                expect_json: bool = True) -> HttpResult:
        error: Optional[str] = None
        status: Optional[int] = None
        started = time.monotonic()
        for attempt in range(self.retries + 1):
            if attempt:
                self._sleep(self.backoff * (2 ** (attempt - 1)))
            self._throttle()
            try:
                response = self._session.request(
                    method, url, headers=dict(headers or {}), params=params, data=data, json=json_body,
                    timeout=self.timeout, stream=True, allow_redirects=False,
                )
            except requests.ConnectTimeout:
                # The peer could not be reached at all (refused/unroutable/filtered).
                error, status = "network", None
                continue
            except requests.Timeout:
                error, status = "timeout", None
                continue
            except requests.RequestException:
                error, status = "network", None
                continue

            try:
                status = response.status_code
                latency = int((time.monotonic() - started) * 1000)
                if status == 429:
                    return HttpResult(False, status, error="rate_limited",
                                      retry_after=_retry_after(response), latency_ms=latency)
                if status >= 500:
                    error = "http_error"
                    continue
                if status >= 400:
                    return HttpResult(False, status, error="http_error", latency_ms=latency)
                body = _read_limited(response)
                if body is None:
                    return HttpResult(False, status, error="too_large", latency_ms=latency)
                if not expect_json:
                    return HttpResult(True, status, data=body.decode("utf-8", errors="replace"), latency_ms=latency)
                try:
                    return HttpResult(True, status, data=json.loads(body.decode("utf-8")), latency_ms=latency)
                except (ValueError, UnicodeDecodeError):
                    return HttpResult(False, status, error="bad_json", latency_ms=latency)
            finally:
                response.close()
        return HttpResult(False, status, error=error or "network",
                          latency_ms=int((time.monotonic() - started) * 1000))

    def get(self, url: str, **kwargs: Any) -> HttpResult:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> HttpResult:
        return self.request("POST", url, **kwargs)


def _read_limited(response: requests.Response) -> Optional[bytes]:
    chunks, size = [], 0
    for chunk in response.iter_content(chunk_size=16384):
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _retry_after(response: requests.Response) -> Optional[float]:
    value = response.headers.get("Retry-After")
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None
