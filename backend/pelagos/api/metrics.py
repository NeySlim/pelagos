# SPDX-License-Identifier: Apache-2.0
"""GET /metrics (section 30): Prometheus text, outside /api/v1. A Bearer token with read:series, or a
client address inside metrics.allowed_networks. Never audited: it is supervision reading."""

from __future__ import annotations

import ipaddress

from flask import Flask, Response, request

from pelagos.api.errors import ApiError
from pelagos.api.security import _token_session, client_ip, ctx, services
from pelagos.auth import api_tokens
from pelagos.auth.rbac import has_permission
from pelagos.core import settings_registry as reg
from pelagos.services.metrics_service import CONTENT_TYPE


def network_allowed(networks: list[str], address: str | None) -> bool:
    try:
        ip = ipaddress.ip_address(address or "")
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    for raw in networks:
        try:
            if ip in ipaddress.ip_network(raw, strict=False):
                return True
        except ValueError:
            continue
    return False


def metrics() -> Response:
    settings = ctx().settings()
    if not reg.get(settings, "metrics.endpoint_enabled"):
        raise ApiError("not_found", "metrics are disabled (metrics.endpoint_enabled)")
    presented = api_tokens.bearer(request.headers.get("Authorization"))
    perms: set[str] | None = None  # a listed network reads everything the scrape holds
    if presented is not None:
        # A presented token decides alone: a wrong one is refused even from an allowed network.
        perms = set(_token_session(presented).permissions)
        if not has_permission(perms, "read:series"):
            raise ApiError("forbidden", "requires read:series")
    elif not network_allowed(list(reg.get(settings, "metrics.allowed_networks")), client_ip()):
        raise ApiError("unauthenticated", "an API token with read:series or an allowed network is required")
    resp = Response(services().metrics.render(perms), mimetype="text/plain")
    resp.headers["Content-Type"] = CONTENT_TYPE
    resp.headers["Cache-Control"] = "no-store"
    return resp


def register_metrics(app: Flask) -> None:
    app.add_url_rule("/metrics", "metrics", metrics, methods=["GET"])
