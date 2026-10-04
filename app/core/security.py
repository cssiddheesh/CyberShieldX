"""Small security helpers: rate limiting, text sanitising, response headers."""
from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque
from typing import Callable

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; connect-src 'self'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
}


def clean_text(value: object, max_len: int = 2048) -> str:
    """Return a string with control characters removed and length capped."""
    text = "" if value is None else str(value)
    text = _CONTROL_CHARS.sub("", text)
    return text[:max_len]


class RateLimiter:
    """In-memory sliding-window limiter (per key, e.g. client address)."""

    MAX_KEYS = 5000

    def __init__(self, limit: int, window_seconds: float = 60.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.limit = limit
        self.window = window_seconds
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        """Record a hit. Returns (allowed, retry_after_seconds)."""
        now = self._clock()
        with self._lock:
            if len(self._hits) > self.MAX_KEYS:
                self._hits.clear()
            hits = self._hits[key]
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False, max(0.0, self.window - (now - hits[0]))
            hits.append(now)
            return True, 0.0
