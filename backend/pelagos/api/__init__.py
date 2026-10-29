# SPDX-License-Identifier: Apache-2.0
"""REST API (section 17): one Flask-RESTX namespace per section, mounted under /api/v1."""

from __future__ import annotations

import logging

from flask import Blueprint, Flask, request
from flask_restx import Api
from werkzeug.exceptions import HTTPException

from pelagos import API_VERSION, __version__
from pelagos.api.errors import PROBLEM_TYPE, TITLES, ApiError, title_message, translate, unexpected_detail
from pelagos.api.security import audit_token_call, load_session, token_audit_enricher

API_PREFIX = f"/api/{API_VERSION}"
log = logging.getLogger(__name__)


class PelagosApi(Api):
    """Known failures (engine down, not built yet) answer their problem document without a traceback
    in the log; Flask-RESTX would otherwise log every 5xx as an unhandled exception."""

    def handle_error(self, e: Exception):
        mapped = None if isinstance(e, HTTPException) else translate(e)
        if mapped is None or mapped.code == "internal_error":
            return super().handle_error(e)
        if mapped.status >= 500:
            log.warning("%s %s: %s %s", request.method, request.path, mapped.code, mapped.detail)
        return self.make_response(mapped.to_problem(), mapped.status, headers=mapped.headers)


def register_api(app: Flask) -> Api:
    from pelagos.api import (
        account,
        admin,
        advanced,
        alerts,
        archives,
        audit,
        auth,
        certs,
        dashboard,
        ddns_failover,
        dhcp,
        dns,
        hosts,
        install,
        ipv6,
        kea_migration,
        meta,
        nodes,
        notifications,
        ops,
        plans,
        resolver_health,
        series,
    )
    from pelagos.api.ws import register_ws

    blueprint = Blueprint("api", __name__, url_prefix=API_PREFIX)
    blueprint.before_request(load_session)
    blueprint.after_request(audit_token_call)
    blueprint.url_value_preprocessor(dns.root_zone_alias)
    api = PelagosApi(
        blueprint,
        version=__version__,
        title="Pelagos API",
        description=(
            "DNS and DHCP management for BIND 9 and Kea. Contracts: docs/architecture.md section 17. "
            "Authentication: session cookie pelagos_session from POST /auth/login; every POST, PUT, "
            "PATCH and DELETE carries the X-CSRF-Token returned at login. Scripts use an API token "
            "instead: Authorization: Bearer pel_<id>_<secret>, no cookie, no CSRF. Errors are RFC 7807 "
            "problem documents (model Problem). WebSocket: GET /api/v1/ws (section 18)."
        ),
        doc="/docs",
        validate=False,
        authorizations={
            "session": {"type": "apiKey", "in": "cookie", "name": "pelagos_session"},
            "csrf": {"type": "apiKey", "in": "header", "name": "X-CSRF-Token"},
            "token": {"type": "apiKey", "in": "header", "name": "Authorization"},
        },
        security=[{"session": [], "csrf": []}, {"token": []}],
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
            "title": TITLES[code],
            "status": err.code or 500,
            "detail": err.description,
            "instance": request.path,
            "code": code,
            "title_message": title_message(code),
        }, err.code or 500

    @api.errorhandler(Exception)
    def _any_error(err: Exception):
        mapped = translate(err)
        if mapped is None:
            log.exception("unhandled error on %s", request.path)
            mapped = ApiError(
                "internal_error",
                "unexpected error; see the server log",
                extra={"detail_message": unexpected_detail()},
            )
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
        certs,
        ops,
        notifications,
        archives,
        ddns_failover,
        resolver_health,
        kea_migration,
    ):
        api.add_namespace(module.ns)
    for extra in (resolver_health.series_ns, ipv6.hosts_ns, ipv6.admin_ns):
        api.add_namespace(extra)
    from pelagos.api.models import all_models

    # Models are module-level RESTX objects shared by the namespaces; the document needs them all.
    for name, definition in all_models().items():
        api.models.setdefault(name, definition)
    app.register_blueprint(blueprint)
    if "pelagos" in app.extensions:
        app.extensions["pelagos"].audit_log.enrich(token_audit_enricher)
    register_ws(app, API_PREFIX)
    return api
