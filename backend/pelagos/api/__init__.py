# SPDX-License-Identifier: Apache-2.0
"""REST API (section 17): one Flask-RESTX namespace per section, mounted under /api/v1."""

from __future__ import annotations

from flask import Blueprint, Flask
from flask_restx import Api
from werkzeug.exceptions import HTTPException

from pelagos import API_VERSION, __version__
from pelagos.api.errors import ApiError
from pelagos.api.security import load_session

API_PREFIX = f"/api/{API_VERSION}"


def register_api(app: Flask) -> Api:
    from pelagos.api import (
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

    blueprint = Blueprint("api", __name__, url_prefix=API_PREFIX)
    blueprint.before_request(load_session)
    api = Api(
        blueprint,
        version=__version__,
        title="Pelagos API",
        description="DNS and DHCP management for BIND 9 and Kea. Contracts: docs/architecture.md section 17.",
        doc="/docs",
        validate=False,
    )

    @api.errorhandler(ApiError)
    def _api_error(err: ApiError):
        return err.to_problem(), err.status, err.headers

    @api.errorhandler(HTTPException)
    def _http_error(err: HTTPException):
        from pelagos.api.errors import PROBLEM_TYPE

        code = {404: "not_found", 405: "method_not_allowed", 400: "validation_error"}.get(
            err.code or 500, "internal_error"
        )
        return {
            "type": PROBLEM_TYPE + code,
            "title": err.name,
            "status": err.code or 500,
            "detail": err.description,
            "code": code,
        }, err.code or 500

    for module in (
        meta,
        auth,
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
    app.register_blueprint(blueprint)
    return api
