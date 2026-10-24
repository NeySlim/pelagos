# SPDX-License-Identifier: Apache-2.0
"""Flask application factory for the web process (`pelagos serve`)."""

from __future__ import annotations

import logging
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException, NotFound

from pelagos.api.errors import PROBLEM_MIME, PROBLEM_TYPE, ApiError, translate
from pelagos.core.context import NodeContext
from pelagos.core.paths import Paths

log = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self' wss:"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


def create_app(
    paths: Paths | None = None, context: NodeContext | None = None, static_dir: Path | None = None
) -> Flask:
    """Build the app around a NodeContext; tests pass a context built on a temp tree."""
    paths = paths or Paths.from_env()
    context = context or NodeContext.build(paths)
    static_dir = static_dir or (paths.opt / "frontend" / "dist")

    # No Flask static route: its `/<path:filename>` rule would shadow the SPA catch-all below.
    app = Flask("pelagos", static_folder=None)
    app.config["JSON_SORT_KEYS"] = False
    app.config["RESTX_MASK_SWAGGER"] = False
    app.config["RESTX_ERROR_404_HELP"] = False
    app.extensions["pelagos"] = context
    from pelagos.services.container import Services

    # Connectors are built from node.toml [engines]; tests inject fakes beforehand.
    Services.of(context)

    @app.before_request
    def _engines_follow_node_toml() -> None:
        # An import or install (root helper, CLI) changes [engines] under the running process.
        Services.of(context).refresh_engines()

    from pelagos.api import register_api

    register_api(app)

    @app.errorhandler(ApiError)
    def _api_error(err: ApiError) -> Response:
        return _problem(err.to_problem(), err.status, err.headers)

    @app.errorhandler(HTTPException)
    def _http_error(err: HTTPException) -> Response:
        code = {404: "not_found", 405: "method_not_allowed", 429: "rate_limited"}.get(
            err.code or 500, "internal_error"
        )
        if err.code and 400 <= err.code < 500 and code == "internal_error":
            code = "validation_error"
        return _problem(
            {
                "type": PROBLEM_TYPE + code,
                "title": err.name,
                "status": err.code or 500,
                "detail": err.description,
                "instance": request.path,
                "code": code,
            },
            err.code or 500,
        )

    @app.errorhandler(Exception)
    def _unexpected(err: Exception) -> Response:
        mapped = translate(err)
        if mapped is not None:
            return _problem(mapped.to_problem(), mapped.status, mapped.headers)
        log.exception("unhandled error")
        return _problem(
            {
                "type": PROBLEM_TYPE + "internal_error",
                "title": "Internal error",
                "status": 500,
                "detail": "unexpected error; see the server log",
                "instance": request.path,
                "code": "internal_error",
            },
            500,
        )

    @app.after_request
    def _headers(resp: Response) -> Response:
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        if request.is_secure:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        # Flask-RESTX answers its own errors as application/json; the contract says problem+json.
        if resp.status_code >= 400 and resp.mimetype == "application/json":
            resp.mimetype = PROBLEM_MIME
        return resp

    _register_spa(app, static_dir)

    return app


def _register_spa(app: Flask, static_dir: Path) -> None:
    """The SPA owns every non-API path: real files are served, anything else gets index.html."""
    root = static_dir.resolve()

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def _spa(path: str) -> Response:
        if path == "api" or path.startswith("api/"):
            raise NotFound()
        if not (root / "index.html").is_file():
            raise NotFound("the web interface is not installed (frontend/dist is missing)")
        if path:
            try:
                return send_from_directory(root, path)
            except NotFound:
                # A missing build asset is a real 404; HTML in its place only confuses the browser.
                if path.startswith("assets/"):
                    raise

        resp = send_from_directory(root, "index.html")
        # The shell must be revalidated so a new release is picked up; hashed assets cache normally.
        resp.headers["Cache-Control"] = "no-cache"
        return resp


def _problem(doc: dict, status: int, headers: dict | None = None) -> Response:
    resp = jsonify(doc)
    resp.status_code = status
    resp.mimetype = PROBLEM_MIME
    for k, v in (headers or {}).items():
        resp.headers[k] = v
    return resp


def wsgi_app() -> Flask:
    """gunicorn entry: `pelagos.app:wsgi_app()`; also listens to collector events on events.sock."""
    app = create_app()
    from pelagos.services.container import Services

    Services.of(app.extensions["pelagos"]).start_event_listener()
    return app
