"""HTTP API. Thin layer: validation and serialisation only, no analysis logic."""
from __future__ import annotations

from typing import Any

from flask import Blueprint, current_app, jsonify, request

from app.analyzers.intel import (
    run_cve_scan, run_file_scan, run_media_scan, run_network_scan,
    run_password_scan, run_text_scan,
)
from app.ai.llm import generate_enhancement, resolve_config
from app.analyzers.pipeline import run_phishing_scan
from app.core.config import APP_NAME, APP_VERSION
from app.core.indicators import MAX_INDICATOR_LENGTH, identify
from app.core.modules import AVAILABLE, module_by_key, modules_payload
from app.models.evidence import RISK_LEVEL_NAMES, IndicatorType, utc_now

api = Blueprint("api", __name__, url_prefix="/api")

EXTERNAL_DATA_NOTICE = (
    "Local analysis runs on this computer. When an external intelligence source is used, "
    "the indicator you analyze may be sent to that provider. Passwords are never sent."
)


def ctx():
    return current_app.extensions["csx"]


def error(code: str, message: str, status: int):
    return jsonify({"error": {"code": code, "message": message}}), status


def json_body(max_bytes: int = 64 * 1024) -> dict[str, Any] | None:
    if (request.content_length or 0) > max_bytes:
        return None
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def demo_mode_enabled() -> bool:
    c = ctx()
    return bool(c.db.get_setting("demo_mode", c.settings.demo_mode_default))


@api.get("/health")
def health():
    c = ctx()
    return jsonify({"status": "ok" if c.db.ping() else "degraded", "app": APP_NAME,
                    "version": APP_VERSION, "time": utc_now(), "database": c.db.ping()})


@api.get("/config")
def config():
    c = ctx()
    payload = c.settings.public_dict()
    payload["demo_mode"] = demo_mode_enabled()
    payload["external_data_notice"] = EXTERNAL_DATA_NOTICE
    ai = resolve_config(c.settings, c.db)
    payload["ai"] = {"configured": ai.configured, "model": ai.model, "base_url": ai.base_url,
                     "notice": ("When you request an AI enhancement, the scan's evidence summary "
                                "is sent to your configured AI provider. Passwords are never sent.")} 
    return jsonify(payload)


@api.put("/settings")
def update_settings():
    body = json_body()
    if body is None:
        return error("invalid_body", "Send a JSON object.", 400)
    if "demo_mode" not in body or not isinstance(body["demo_mode"], bool):
        return error("invalid_value", "demo_mode must be true or false.", 400)
    ctx().db.set_setting("demo_mode", body["demo_mode"])
    return jsonify({"demo_mode": body["demo_mode"]})


def _ai_status() -> dict[str, Any]:
    c = ctx()
    ai = resolve_config(c.settings, c.db)
    return {"configured": ai.configured, "model": ai.model, "base_url": ai.base_url}


@api.put("/settings/ai")
def update_ai_settings():
    """Store the user-supplied AI key server-side. The key is never returned."""
    body = json_body(max_bytes=4 * 1024)
    if body is None:
        return error("invalid_body", "Send a JSON object.", 400)
    c = ctx()
    if "api_key" in body:
        key = body["api_key"]
        if not isinstance(key, str):
            return error("invalid_value", "api_key must be a string.", 400)
        key = key.strip()
        if key and (len(key) < 8 or len(key) > 500):
            return error("invalid_value", "That key does not look valid.", 400)
        c.db.set_setting("ai_api_key", key)  # empty string clears it
    if "model" in body:
        model = body["model"]
        if not isinstance(model, str) or not 1 <= len(model.strip()) <= 100:
            return error("invalid_value", "model must be 1-100 characters.", 400)
        c.db.set_setting("ai_model", model.strip())
    if "base_url" in body:
        base_url = body["base_url"]
        if (not isinstance(base_url, str) or not 1 <= len(base_url.strip()) <= 500
                or not base_url.strip().lower().startswith(("http://", "https://"))):
            return error("invalid_value", "base_url must be an http(s) URL.", 400)
        c.db.set_setting("ai_base_url", base_url.strip().rstrip("/"))
    return jsonify(_ai_status())


@api.post("/scans/<scan_id>/ai")
def enhance_scan(scan_id: str):
    """Generate (or return cached) LLM enhancement for a saved scan."""
    if len(scan_id) > 40:
        return error("not_found", "Scan not found.", 404)
    c = ctx()
    scan = c.db.get_scan(scan_id)
    if scan is None:
        return error("not_found", "Scan not found.", 404)
    cached = c.db.get_ai_enhancement(scan_id)
    if cached is not None and request.args.get("refresh") != "1":
        return jsonify(cached)
    config = resolve_config(c.settings, c.db)
    if not config.configured:
        return error("not_configured",
                     "No AI key set. Add one in Settings to enable AI-enhanced reports.", 400)
    report = scan.get("report") or {}
    report.setdefault("scan_id", scan["id"])
    enhancement, failure = generate_enhancement(report, config)
    if enhancement is None:
        messages = {
            "rate_limited": "The AI provider is rate-limited. Try again in a minute.",
            "unreachable": "The AI provider could not be reached. Check the base URL and connection.",
            "bad_key": "The AI provider rejected the key. Check it in Settings.",
            "bad_response": "The AI provider returned something unusable. Try again.",
        }
        return error("ai_failed", messages.get(failure, "AI enhancement failed."), 502)
    enhancement["scan_id"] = scan_id
    enhancement["generated_at"] = utc_now()
    c.db.save_ai_enhancement(scan_id, enhancement)
    return jsonify(enhancement)


@api.get("/modules")
def modules():
    return jsonify(modules_payload())


@api.post("/identify")
def identify_input():
    body = json_body(max_bytes=MAX_INDICATOR_LENGTH * 4 + 1024)
    if body is None or not isinstance(body.get("input"), str):
        return error("invalid_body", "Send a JSON object with a text field named 'input'.", 400)
    result = identify(body["input"]).to_dict()
    mod = module_by_key(result["module"]) if result["module"] else None
    result["module_label"] = mod.label if mod else None
    result["module_path"] = mod.path if mod else None
    result["module_available"] = bool(mod and mod.status == AVAILABLE)
    result["module_phase"] = mod.phase if mod else None
    return jsonify(result)


@api.get("/sources")
def sources():
    items = ctx().registry.describe_all()
    counts: dict[str, int] = {}
    for item in items:
        counts[item["state"]] = counts.get(item["state"], 0) + 1
    return jsonify({"items": items, "counts": counts, "total": len(items)})


@api.put("/sources/<key>")
def update_source(key: str):
    body = json_body()
    if body is None or not isinstance(body.get("enabled"), bool):
        return error("invalid_value", "enabled must be true or false.", 400)
    try:
        ctx().registry.set_enabled(key, body["enabled"])
    except KeyError:
        return error("not_found", "Unknown source.", 404)
    item = next(i for i in ctx().registry.describe_all() if i["key"] == key)
    return jsonify(item)


@api.get("/dashboard")
def dashboard():
    c = ctx()
    stats = c.db.dashboard_stats()
    sources_list = c.registry.describe_all()
    stats["sources"] = {
        "total": len(sources_list),
        "ready": sum(1 for s in sources_list if s["state"] in ("AVAILABLE", "UNCHECKED")),
        "items": [{"key": s["key"], "name": s["name"], "state": s["state"], "reason": s["reason"],
                   "category": s["category"]} for s in sources_list],
    }
    stats["demo_mode"] = demo_mode_enabled()
    return jsonify(stats)


@api.get("/scans")
def list_scans():
    try:
        limit = int(request.args.get("limit", 25))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return error("invalid_value", "limit and offset must be whole numbers.", 400)
    risk = request.args.get("risk") or None
    if risk and risk not in RISK_LEVEL_NAMES:
        return error("invalid_value", f"risk must be one of: {', '.join(RISK_LEVEL_NAMES)}.", 400)
    kind = request.args.get("type") or None
    if kind and kind not in {t.value for t in IndicatorType}:
        return error("invalid_value", "Unknown indicator type.", 400)
    return jsonify(ctx().db.list_scans(limit=limit, offset=offset, risk_level=risk, indicator_type=kind))


@api.delete("/scans")
def delete_all_scans():
    return jsonify({"deleted": ctx().db.delete_all_scans()})


@api.delete("/scans/<scan_id>")
def delete_scan(scan_id: str):
    if len(scan_id) > 40 or not ctx().db.delete_scan(scan_id):
        return error("not_found", "Scan not found.", 404)
    return jsonify({"deleted": scan_id})


@api.get("/scans/<scan_id>")
def get_scan(scan_id: str):
    if len(scan_id) > 40:
        return error("not_found", "Scan not found.", 404)
    scan = ctx().db.get_scan(scan_id)
    if scan is None:
        return error("not_found", "Scan not found.", 404)
    scan["ai_enhanced"] = ctx().db.get_ai_enhancement(scan_id)
    return jsonify(scan)


@api.post("/scans")
def create_scan():
    body = json_body(max_bytes=MAX_INDICATOR_LENGTH * 4 + 1024)
    if body is None or not isinstance(body.get("input"), str):
        return error("invalid_body", "Send a JSON object with a text field named 'input'.", 400)
    raw = body["input"]
    if not raw.strip():
        return error("invalid_value", "Input is empty. Paste a link to analyze.", 400)
    if len(raw) > MAX_INDICATOR_LENGTH:
        return error("invalid_value", f"Input is longer than {MAX_INDICATOR_LENGTH} characters.", 400)
    result = identify(raw)
    c = ctx()
    demo = demo_mode_enabled()
    try:
        if result.indicator_type == IndicatorType.URL:
            report = run_phishing_scan(raw, c.settings, c.db, c.registry, demo=demo)
        elif result.indicator_type in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256):
            report = run_file_scan(result.normalized, c.settings, c.db, c.registry, demo=demo)
        elif result.indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6, IndicatorType.DOMAIN):
            report = run_network_scan(raw, c.settings, c.db, c.registry, demo=demo)
        elif result.indicator_type == IndicatorType.CVE:
            report = run_cve_scan(result.normalized, c.settings, c.db, c.registry, demo=demo)
        else:
            return error("unsupported_type",
                         "This input is not recognized as a URL, hash, IP, domain or CVE ID. "
                         "Passwords are checked in Account Security, never here.", 422)
    except ValueError as exc:
        return error("invalid_value", str(exc), 400)
    except Exception:
        return error("internal_error", "The scan failed. The details were logged.", 500)
    return jsonify(report), 201


MAX_PASSWORD_LENGTH = 512


@api.post("/scans/password")
def create_password_scan():
    """Strength + breach-exposure check. The password is never stored or logged."""
    body = json_body(max_bytes=MAX_PASSWORD_LENGTH + 1024)
    if body is None or not isinstance(body.get("password"), str):
        return error("invalid_body", "Send a JSON object with a text field named 'password'.", 400)
    password = body["password"]
    if not password:
        return error("invalid_value", "Password is empty.", 400)
    if len(password) > MAX_PASSWORD_LENGTH:
        return error("invalid_value", f"Password is longer than {MAX_PASSWORD_LENGTH} characters.", 400)
    c = ctx()
    try:
        report = run_password_scan(password, c.settings, c.db, c.registry,
                                   demo=demo_mode_enabled())
    except ValueError as exc:
        return error("invalid_value", str(exc), 400)
    except Exception:
        return error("internal_error", "The scan failed. The details were logged.", 500)
    return jsonify(report), 201


@api.post("/scans/file")
def create_file_scan():
    """Static file analysis. The file is hashed in memory, never executed, never stored."""
    if "file" not in request.files:
        return error("invalid_body", "Send multipart form data with a 'file' field.", 400)
    upload = request.files["file"]
    filename = (upload.filename or "upload")[:255]
    try:
        data = upload.read()
    except Exception:
        return error("invalid_body", "The upload could not be read.", 400)
    c = ctx()
    if len(data) > c.settings.max_upload_bytes:
        return error("too_large",
                     f"File is larger than {c.settings.max_upload_bytes // (1024 * 1024)} MB.", 413)
    if not data:
        return error("invalid_value", "The file is empty.", 400)
    from app.analyzers.files import hash_bytes
    digests = hash_bytes(data)
    try:
        report = run_file_scan(digests["sha256"], c.settings, c.db, c.registry,
                               demo=demo_mode_enabled(),
                               uploaded={"data": data, "filename": filename})
    except ValueError as exc:
        return error("invalid_value", str(exc), 400)
    except Exception:
        return error("internal_error", "The scan failed. The details were logged.", 500)
    finally:
        data = b""  # drop the bytes as soon as analysis has them
    return jsonify(report), 201


@api.get("/reports/<scan_id>")
def get_report(scan_id: str):
    if len(scan_id) > 40:
        return error("not_found", "Report not found.", 404)
    scan = ctx().db.get_scan(scan_id)
    if scan is None:
        return error("not_found", "Report not found.", 404)
    report = scan.get("report") or {}
    report.setdefault("scan_id", scan["id"])
    report["ai_enhanced"] = ctx().db.get_ai_enhancement(scan_id)
    return jsonify(report)


MAX_TEXT_LENGTH = 20000


@api.post("/scans/text")
def create_text_scan():
    body = json_body(max_bytes=MAX_TEXT_LENGTH + 1024)
    if body is None or not isinstance(body.get("text"), str):
        return error("invalid_body", "Send a JSON object with a text field named 'text'.", 400)
    if not body["text"].strip():
        return error("invalid_value", "Text is empty.", 400)
    if len(body["text"]) > MAX_TEXT_LENGTH:
        return error("invalid_value", f"Text is longer than {MAX_TEXT_LENGTH} characters.", 400)
    c = ctx()
    try:
        report = run_text_scan(body["text"], c.settings, c.db, c.registry,
                               demo=demo_mode_enabled())
    except ValueError as exc:
        return error("invalid_value", str(exc), 400)
    except Exception:
        return error("internal_error", "The scan failed. The details were logged.", 500)
    return jsonify(report), 201


@api.post("/scans/media")
def create_media_scan():
    """Image forensics. Headers/metadata are parsed, never rendered server-side as code."""
    if "file" not in request.files:
        return error("invalid_body", "Send multipart form data with a 'file' field.", 400)
    upload = request.files["file"]
    filename = (upload.filename or "image")[:255]
    try:
        data = upload.read()
    except Exception:
        return error("invalid_body", "The upload could not be read.", 400)
    c = ctx()
    if len(data) > c.settings.max_upload_bytes:
        return error("too_large",
                     f"File is larger than {c.settings.max_upload_bytes // (1024 * 1024)} MB.", 413)
    from app.analyzers.media import identify_image
    if identify_image(data) is None:
        return error("unsupported_type",
                     "Not a recognised image. PNG, JPEG, GIF, BMP and WebP are supported.", 415)
    try:
        report = run_media_scan(data, filename, c.settings, c.db, c.registry,
                                demo=demo_mode_enabled())
    except ValueError as exc:
        return error("invalid_value", str(exc), 400)
    except Exception:
        return error("internal_error", "The scan failed. The details were logged.", 500)
    finally:
        data = b""
    return jsonify(report), 201


@api.get("/lab/modules")
def lab_modules():
    from app.lab.quizzes import LAB_MODULES
    return jsonify({"modules": LAB_MODULES})


@api.get("/lab/quiz/<key>")
def lab_quiz(key: str):
    from app.lab.quizzes import LAB_MODULES, public_quiz
    if key not in {m["key"] for m in LAB_MODULES}:
        return error("not_found", "Unknown lab module.", 404)
    questions = public_quiz(key)
    if questions is None:
        return error("not_found", "Unknown lab module.", 404)
    return jsonify({"module": key, "total": len(questions), "questions": questions})


@api.post("/lab/submit")
def lab_submit():
    from app.lab.quizzes import LAB_MODULES, grade
    body = json_body(max_bytes=8 * 1024)
    if body is None or not isinstance(body.get("module"), str) or not isinstance(body.get("answers"), list):
        return error("invalid_body", "Send a JSON object with 'module' and 'answers'.", 400)
    if body["module"] not in {m["key"] for m in LAB_MODULES}:
        return error("not_found", "Unknown lab module.", 404)
    result = grade(body["module"], body["answers"][:50])
    if result is None:
        return error("invalid_body", "Answers could not be graded.", 400)
    return jsonify(result)


@api.get("/reports/<scan_id>.pdf")
def get_report_pdf(scan_id: str):
    if len(scan_id) > 44:
        return error("not_found", "Report not found.", 404)
    scan = ctx().db.get_scan(scan_id)
    if scan is None:
        return error("not_found", "Report not found.", 404)
    try:
        from app.reports.pdf import render_pdf
    except ImportError:
        return error("unavailable", "PDF export needs the optional reportlab package.", 501)
    try:
        pdf_bytes = render_pdf(scan.get("report") or {}, scan)
    except Exception:
        return error("internal_error", "The PDF could not be generated.", 500)
    from flask import Response
    return Response(pdf_bytes, mimetype="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{scan_id}.pdf"'})
