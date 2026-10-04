"""Application configuration.

Secrets (API keys) are read from the environment / .env file and are held only
inside ``Settings``. They are never part of ``public_dict()``, ``repr()`` or any
API response. Adapters obtain a key through ``Settings.key()``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional

APP_NAME = "CyberShield X"
APP_VERSION = "0.1.0"
BASE_DIR = Path(__file__).resolve().parents[2]

# provider key -> environment variable that holds its credential
PROVIDER_ENV_VARS: dict[str, str] = {
    "phishtank": "PHISHTANK_API_KEY",
    "urlhaus": "URLHAUS_API_KEY",
    "malwarebazaar": "MALWAREBAZAAR_API_KEY",
    "urlscan": "URLSCAN_API_KEY",
    "ipinfo": "IPINFO_TOKEN",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "safebrowsing": "GOOGLE_SAFE_BROWSING_API_KEY",
}


def _read_env_file(path: Path) -> dict[str, str]:
    """Minimal .env parser used only if python-dotenv is not installed."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        values[name.strip()] = value.strip()
    return values


def _load_dotenv_into(environ: dict[str, str]) -> None:
    env_path = BASE_DIR / ".env"
    try:
        from dotenv import dotenv_values  # type: ignore

        values = {k: v for k, v in dotenv_values(env_path).items() if v is not None}
    except ImportError:
        values = _read_env_file(env_path)
    for name, value in values.items():
        environ.setdefault(name, value)  # real environment variables win


def _clean(value: Optional[str]) -> str:
    if value is None:
        return ""
    return value.strip().strip('"').strip("'").strip()


def _as_bool(value: Optional[str], default: bool) -> bool:
    text = _clean(value).lower()
    if not text:
        return default
    return text in {"1", "true", "yes", "on"}


def _as_int(value: Optional[str], default: int, low: int, high: int) -> int:
    try:
        number = int(_clean(value))
    except ValueError:
        return default
    return max(low, min(high, number))


@dataclass(frozen=True)
class Settings:
    db_path: Path
    frontend_dist: Path
    demo_mode_default: bool = False
    host: str = "127.0.0.1"
    port: int = 8000
    max_upload_bytes: int = 25 * 1024 * 1024
    http_timeout: float = 8.0
    http_retries: int = 2
    rate_limit_per_minute: int = 120
    ai_model: str = "gpt-4o-mini"
    ai_base_url: str = "https://api.openai.com/v1"
    _keys: Mapping[str, str] = field(default_factory=dict, repr=False)

    def key(self, provider: str) -> str:
        """Return the credential for a provider ('' when not configured)."""
        return self._keys.get(provider, "")

    def has_key(self, provider: str) -> bool:
        return bool(self._keys.get(provider))

    def public_dict(self) -> dict:
        """Safe-to-expose configuration. Contains no secrets."""
        return {
            "app_name": APP_NAME,
            "version": APP_VERSION,
            "limits": {
                "max_upload_mb": self.max_upload_bytes // (1024 * 1024),
                "http_timeout_seconds": self.http_timeout,
                "http_retries": self.http_retries,
                "rate_limit_per_minute": self.rate_limit_per_minute,
            },
        }


def load_settings(env: Optional[Mapping[str, str]] = None, read_dotenv: bool = True) -> Settings:
    """Build Settings from ``env`` (defaults to os.environ plus the .env file)."""
    if env is None:
        environ: dict[str, str] = dict(os.environ)
        if read_dotenv:
            _load_dotenv_into(environ)
    else:
        environ = dict(env)

    keys = {
        provider: _clean(environ.get(var))
        for provider, var in PROVIDER_ENV_VARS.items()
        if _clean(environ.get(var))
    }
    if _clean(environ.get("AI_API_KEY")):
        keys["ai"] = _clean(environ.get("AI_API_KEY"))
    db_override = _clean(environ.get("CYBERSHIELD_DB_PATH"))
    return Settings(
        db_path=Path(db_override) if db_override else BASE_DIR / "data" / "cybershield.db",
        frontend_dist=BASE_DIR / "frontend" / "dist",
        demo_mode_default=_as_bool(environ.get("CYBERSHIELD_DEMO_MODE"), False),
        host=_clean(environ.get("CYBERSHIELD_HOST")) or "127.0.0.1",
        port=_as_int(environ.get("CYBERSHIELD_PORT"), 8000, 1, 65535),
        max_upload_bytes=_as_int(environ.get("CYBERSHIELD_MAX_UPLOAD_MB"), 25, 1, 100) * 1024 * 1024,
        http_timeout=float(_as_int(environ.get("CYBERSHIELD_HTTP_TIMEOUT"), 8, 1, 30)),
        http_retries=_as_int(environ.get("CYBERSHIELD_HTTP_RETRIES"), 2, 0, 4),
        rate_limit_per_minute=_as_int(environ.get("CYBERSHIELD_RATE_LIMIT"), 120, 10, 6000),
        ai_model=_clean(environ.get("AI_MODEL")) or "gpt-4o-mini",
        ai_base_url=_clean(environ.get("AI_BASE_URL")) or "https://api.openai.com/v1",
        _keys=keys,
    )
