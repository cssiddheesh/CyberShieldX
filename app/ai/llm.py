"""Optional LLM enhancement (user-supplied key, OpenAI-compatible API).

Takes a completed scan report and asks an external chat model to restate it
in clearer prose. The model receives ONLY the report's structured evidence -
never passwords (stored reports carry placeholders), never API keys. Its
output is validated against a fixed schema and labelled AI-generated.

No key configured -> the feature is simply unavailable; everything else works.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.intelligence.http import HttpClient

DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_BASE_URL = "https://api.openai.com/v1"
TIMEOUT = 60.0

SYSTEM_PROMPT = (
    "You are an assistant inside CyberShield X, a defensive security tool. "
    "You receive structured scan evidence as JSON. Rules you must obey:\n"
    "1. Only restate and explain the evidence given. Never invent findings, sources, "
    "CVEs, hashes, URLs, counts or verdicts.\n"
    "2. Use probabilistic language (suggests, consistent with, may). Never claim certainty.\n"
    "3. Keep every section short. Reply with JSON ONLY, no markdown fences, "
    "using exactly these keys: plain_summary (string, 2-4 sentences), "
    "what_matters (array of up to 3 strings, each naming the source it comes from), "
    "next_steps (array of up to 3 strings, practical user actions), "
    "blind_spots (array of up to 2 strings: what the evidence cannot establish).\n"
    "4. If evidence is thin, say so instead of padding."
)

REQUIRED_KEYS = ("plain_summary", "what_matters", "next_steps", "blind_spots")


@dataclass
class AiConfig:
    api_key: str
    model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL

    @property
    def configured(self) -> bool:
        return bool(self.api_key)


def resolve_config(settings, db=None) -> AiConfig:
    """DB-stored key (set from the UI) wins; .env values are the fallback."""
    key = model = base_url = ""
    if db is not None:
        try:
            key = str(db.get_setting("ai_api_key", "") or "")
            model = str(db.get_setting("ai_model", "") or "")
            base_url = str(db.get_setting("ai_base_url", "") or "")
        except Exception:
            pass
    if not key:
        key = settings.key("ai")
    return AiConfig(
        api_key=key,
        model=model or getattr(settings, "ai_model", "") or DEFAULT_MODEL,
        base_url=(base_url or getattr(settings, "ai_base_url", "") or DEFAULT_BASE_URL).rstrip("/"),
    )


def build_prompt(report: dict[str, Any]) -> list[dict[str, str]]:
    """Compress a report to the evidence-only payload the model may see."""
    evidence = []
    for row in (report.get("evidence") or [])[:12]:
        evidence.append({
            "source": row.get("source"),
            "finding": row.get("finding"),
            "severity": row.get("severity"),
            "confidence": row.get("confidence"),
            "detail": str(row.get("evidence") or "")[:400],
            "status": row.get("status"),
            "origin": row.get("origin"),
        })
    payload = {
        "module": report.get("module_label"),
        "target": str(report.get("target") or "")[:300],
        "risk": f"{report.get('overall_risk')} ({report.get('risk_score')}/100)",
        "analyst_summary": str((report.get("ai_analysis") or {}).get("executive_summary") or "")[:600],
        "evidence": evidence,
    }
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Explain this scan result:\n" + json.dumps(payload)},
    ]


def validate_enhancement(data: Any) -> dict[str, Any] | None:
    """Enforce the fixed schema; reject invented shapes. Never raises."""
    if not isinstance(data, dict):
        return None
    if any(k not in data for k in REQUIRED_KEYS):
        return None
    if not isinstance(data["plain_summary"], str) or not data["plain_summary"].strip():
        return None
    out: dict[str, Any] = {"plain_summary": data["plain_summary"].strip()[:1500]}
    for key in ("what_matters", "next_steps", "blind_spots"):
        items = data[key]
        if not isinstance(items, list):
            return None
        out[key] = [str(i).strip()[:400] for i in items if str(i).strip()][:3]
    if not out["what_matters"] or not out["next_steps"]:
        return None
    return out


def _extract_json(text: str) -> Any:
    text = (text or "").strip()
    try:
        return json.loads(text)
    except ValueError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            return json.loads(text[start:end + 1])
        except ValueError:
            return None
    return None


def generate_enhancement(report: dict[str, Any], config: AiConfig,
                         http: HttpClient | None = None) -> tuple[dict[str, Any] | None, str]:
    """Call the model. Returns (enhancement, error_code); error_code "" on success."""
    if not config.configured:
        return None, "not_configured"
    client = http or HttpClient(timeout=TIMEOUT, retries=1)
    result = client.post(
        f"{config.base_url}/chat/completions",
        headers={"Authorization": f"Bearer {config.api_key}"},
        json_body={"model": config.model, "messages": build_prompt(report),
                   "temperature": 0.2, "max_tokens": 800, "response_format": {"type": "json_object"}},
    )
    if result.error == "rate_limited":
        return None, "rate_limited"
    if result.error in ("timeout", "network"):
        return None, "unreachable"
    if result.status == 401 or result.status == 403:
        return None, "bad_key"
    if not result.ok or not isinstance(result.data, dict):
        return None, "bad_response"
    try:
        content = result.data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None, "bad_response"
    enhancement = validate_enhancement(_extract_json(content))
    if enhancement is None:
        return None, "bad_response"
    enhancement["model"] = config.model
    return enhancement, ""
