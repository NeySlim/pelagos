# SPDX-License-Identifier: Apache-2.0
"""Observed IPv6 addresses (section 27): hosts with their observed addresses, observation sources."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, json_body, page_of
from pelagos.api.errors import ApiError
from pelagos.api.security import client_ip, require, services, username

hosts_ns = Namespace("hosts-ipv6", description="Hosts and their observed IPv6 addresses", path="/hosts/ipv6")
admin_ns = Namespace("admin-ipv6", description="IPv6 observation sources", path="/admin/ipv6")


def ipv6():
    return services().ipv6


@hosts_ns.route("")
class Hosts(Resource):
    @require("read:hosts")
    @hosts_ns.doc(
        params={
            "filter": "missing_aaaa, missing_ptr, stale, unknown or random_mac",
            "zone": "forward zone of the host or its proposal",
            "page": "1-based",
            "per_page": "1 to 500",
        }
    )
    @hosts_ns.response(200, "Paginated hosts with observed addresses, records and proposal")
    @hosts_ns.response(400, "validation_error", m.Problem)
    def get(self):
        rows, meta = ipv6().hosts_list(arg("filter"), arg("zone"))
        return page_of(rows, meta)


@admin_ns.route("")
class Sources(Resource):
    @require("admin:settings")
    @admin_ns.response(200, "Sources (secrets as booleans), prefixes, status per source and node")
    def get(self):
        return ipv6().overview()

    @require("admin:settings")
    @admin_ns.response(200, "Sources, prefixes, status")
    @admin_ns.response(400, "validation_error", m.Problem)
    def put(self):
        return ipv6().replace(json_body(), username(), client_ip())


@admin_ns.route("/sources/test")
class TestSource(Resource):
    @require("admin:settings")
    @admin_ns.response(200, "One poll of the source from this node")
    @admin_ns.response(404, "not_found", m.Problem)
    @admin_ns.response(429, "rate_limited", m.Problem)
    def post(self):
        svc = ipv6()
        body = json_body()
        user = username()
        if not svc.test_limiter.allow(user):
            retry = svc.test_limiter.retry_after(user)
            raise ApiError("rate_limited", "too many source tests", headers={"Retry-After": str(retry)})
        return svc.test(body, user)
