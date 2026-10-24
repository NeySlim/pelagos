# SPDX-License-Identifier: Apache-2.0
"""REST API (section 17): one Flask-RESTX namespace per section, mounted under /api/v1."""

from __future__ import annotations

import logging

from flask import Blueprint, Flask, request
from flask_restx import Api
from werkzeug.exceptions import HTTPException

from pelagos import API_VERSION, __version__
from pelagos.api.errors import PROBLEM_TYPE, ApiError, translate
from pelagos.api.security import load_session

API_PREFIX = f"/api/{API_VERSION}"
log = logging.getLogger(__name__)


def register_api(app: Flask) -> Api:
    from pelagos.api import (
        account,
        admin,
        advanced,
        alerts,
        audit,
        auth,
        dashboard,
        dhcp,
        dns,
        hosts,
        install,
        meta,
        nodes,
        plans,
        series,
    )
    from pelagos.api.ws import register_ws

    blueprint = Blueprint("api", __name__, url_prefix=API_PREFIX)
    blueprint.before_request(load_session)
    api = Api(
        blueprint,
        version=__version__,
        title="Pelagos API",
        description=(
            "DNS and DHCP management for BIND 9 and Kea. Contracts: docs/architecture.md section 17. "
            "Authentication: session cookie pelagos_session from POST /auth/login; every POST, PUT, "
            "PATCH and DELETE carries the X-CSRF-Token returned at login. Errors are RFC 7807 problem "
            "documents (model Problem). WebSocket: GET /api/v1/ws (section 18)."
        ),
        doc="/docs",
        validate=False,
        authorizations={
            "session": {"type": "apiKey", "in": "cookie", "name": "pelagos_session"},
            "csrf": {"type": "apiKey", "in": "header", "name": "X-CSRF-Token"},
        },
        security=[{"session": [], "csrf": []}],
    )

    @api.errorhandler(ApiError)
    def _api_error(err: ApiError):
        return err.to_problem(), err.status, err.headers

    @api.errorhandler(HTTPException)
    def _http_error(err: HTTPException):
        code = {404: "not_found", 405: "method_not_allowed", 400: "validation_error"}.get(
            err.code or 500, "internal_error"
        )
        return {
            "type": PROBLEM_TYPE + code,
            "title": err.name,
            "status": err.code or 500,
            "detail": err.description,
            "instance": request.path,
            "code": code,
        }, err.code or 500

    @api.errorhandler(Exception)
    def _any_error(err: Exception):
        mapped = translate(err)
        if mapped is None:
            log.exception("unhandled error on %s", request.path)
            mapped = ApiError("internal_error", "unexpected error; see the server log")
        return mapped.to_problem(), mapped.status, mapped.headers

    for module in (
        meta,
        auth,
        account,
        nodes,
        dashboard,
        dns,
        dhcp,
        hosts,
        plans,
        alerts,
        series,
        audit,
        advanced,
        install,
        admin,
    ):
        api.add_namespace(module.ns)
    from pelagos.api.models import all_models

    # Models are module-level RESTX objects shared by the namespaces; the document needs them all.
    for name, definition in all_models().items():
        api.models.setdefault(name, definition)
    app.register_blueprint(blueprint)
    register_ws(app, API_PREFIX)
    return api
