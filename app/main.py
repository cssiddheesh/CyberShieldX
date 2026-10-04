"""CyberShield X application entry point.

Run:  python -m app.main
"""
from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass
from typing import Optional

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

from app.api.routes import api
from app.core.config import APP_NAME, Settings, load_settings
from app.core.security import SECURITY_HEADERS, RateLimiter
from app.database.db import Database
from app.intelligence.providers import ALL_ADAPTERS
from app.intelligence.registry import ProviderRegistry

log = logging.getLogger("cybershieldx")


@dataclass
class AppContext:
    settings: Settings
    db: Database
    registry: ProviderRegistry
    limiter: RateLimiter


def create_app(settings: Optional[Settings] = None) -> Flask:
    settings = settings or load_settings()
    app = Flask(__name__, static_folder=None)
    # Upload ceiling for later file endpoints; small JSON endpoints enforce their own limits.
    app.config["MAX_CONTENT_LENGTH"] = settings.max_upload_bytes + 1024 * 1024
    app.json.sort_keys = False

    db = Database(settings.db_path)
    db.init()
    registry = ProviderRegistry(settings, db)
    for adapter in ALL_ADAPTERS:
        try:
            registry.register(adapter)
        except ValueError:
            continue
    app.extensions["csx"] = AppContext(
        settings=settings, db=db, registry=registry,
        limiter=RateLimiter(settings.rate_limit_per_minute),
    )
    app.register_blueprint(api)

    @app.before_request
    def limit_requests():
        if request.path.startswith("/api/"):
            allowed, retry_after = app.extensions["csx"].limiter.allow(request.remote_addr or "local")
            if not allowed:
                response = jsonify({"error": {"code": "rate_limited",
                                              "message": "Too many requests. Please wait a moment and try again."}})
                response.status_code = 429
                response.headers["Retry-After"] = str(int(retry_after) + 1)
                return response
        return None

    @app.after_request
    def add_headers(response):
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException):
        messages = {404: "Not found.", 405: "Method not allowed.", 413: "The upload is too large.",
                    400: "Bad request.", 415: "Unsupported content type."}
        return jsonify({"error": {"code": (exc.name or "error").lower().replace(" ", "_"),
                                  "message": messages.get(exc.code or 500, exc.description or "Request failed.")}}), exc.code

    @app.errorhandler(Exception)
    def unexpected_error(exc: Exception):
        # Log the exception type and stack frames only. The message is deliberately omitted because
        # exceptions can carry URLs, tokens or user input. Never log request bodies, headers or settings.
        frames = " <- ".join(f"{f.name}:{f.lineno}" for f in reversed(traceback.extract_tb(exc.__traceback__)[-4:]))
        log.error("Unhandled %s on %s %s (%s)", type(exc).__name__, request.method, request.path, frames)
        return jsonify({"error": {"code": "internal_error",
                                  "message": "Something went wrong on the server. The details were logged."}}), 500

    @app.get("/", defaults={"path": ""})
    @app.get("/<path:path>")
    def frontend(path: str):
        if path.startswith("api/") or path == "api":
            return jsonify({"error": {"code": "not_found", "message": "Not found."}}), 404
        dist = settings.frontend_dist
        if not (dist / "index.html").is_file():
            return ("CyberShield X frontend has not been built yet. Run build_frontend.bat "
                    "(or: cd frontend && npm install && npm run build).", 503)
        if path and "." in path.rsplit("/", 1)[-1]:
            return send_from_directory(dist, path)  # static asset; refuses paths outside dist
        return send_from_directory(dist, "index.html")  # client-side routes

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings()
    app = create_app(settings)
    shown = "localhost" if settings.host in ("127.0.0.1", "0.0.0.0") else settings.host
    print(f"\n  {APP_NAME} is running at http://{shown}:{settings.port}\n  Press Ctrl+C to stop.\n")
    if settings.host == "0.0.0.0":
        print("  LAN mode: other devices on your network can open this app. Only use on a network you trust.\n")
    app.run(host=settings.host, port=settings.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
