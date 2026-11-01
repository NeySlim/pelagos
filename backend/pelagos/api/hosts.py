# SPDX-License-Identifier: Apache-2.0
"""Hosts: the DNS/DHCP join view and the combined host plan."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, bool_arg, int_arg, json_body, page_of, plan_answer, time_arg
from pelagos.api.errors import ApiError
from pelagos.api.security import check_permission, require, require_module, services, username
from pelagos.auth.rbac import host_plan_permissions

ns = Namespace("hosts", description="Lease + reservation + records join", path="/hosts")


@ns.route("")
class Hosts(Resource):
    @require("read:hosts")
    @ns.doc(
        params={
            "q": "mac, ip, hostname or identifier",
            "subnet_id": "subnet id",
            "zone": "zone suffix",
            "only_inconsistent": "true: hosts with open inconsistencies",
            "page": "1-based",
            "per_page": "default 50, max 500",
        }
    )
    @ns.response(200, "Hosts; meta.errors lists the sources that could not be read", m.HostPage)
    def get(self):
        hosts, errors = services().hosts.list(
            arg("q"), int_arg("subnet_id"), arg("zone"), bool_arg("only_inconsistent")
        )
        return page_of(hosts, {"errors": errors})


@ns.route("/plan")
class HostPlan(Resource):
    @ns.expect(m.HostRequest)
    @ns.response(200, "Plan of scope host: dns.rrset and dhcp.reservation changes", m.Plan)
    @ns.response(403, "forbidden: needs write:hosts or the dns/dhcp writes it expands into", m.Problem)
    @ns.response(422, "engine_validation_failed", m.Problem)
    def post(self):
        session = check_permission(None)
        body = json_body()
        # write:hosts is the union of the writes the plan expands into (section 16).
        if not host_plan_permissions(session.permissions, True, bool(body.get("reservation"))):
            raise ApiError("forbidden", "requires write:hosts")
        return plan_answer(services().hosts.plan(body, username()))


# B1-DISCOVERY: IPv4 neighbors seen over the cluster and the OUI vendor (section 27).
@ns.route("/discovered")
class DiscoveredHosts(Resource):
    @require("read:hosts")
    @ns.doc(
        params={
            "filter": "unknown (no host holds the MAC or an address) or known",
            "q": "part of the MAC, an address or the vendor",
            "page": "1-based",
            "per_page": "default 50, max 500",
        }
    )
    @ns.response(200, "One row per MAC, latest sighting first; meta.unavailable, meta.errors", m.RawList)
    @ns.response(404, "module_disabled", m.Problem)
    def get(self):
        require_module("discovery")
        rows, meta = services().discovery.discovered(arg("filter"), arg("q"))
        return page_of(rows, meta)


@ns.route("/vendor/<string:mac>")
class HostVendor(Resource):
    @require("read:hosts")
    @ns.response(200, "{mac, vendor, prefix}: the OUI manufacturer, null when none matches")
    @ns.response(400, "validation_error", m.Problem)
    @ns.response(404, "module_disabled", m.Problem)
    def get(self, mac: str):
        require_module("discovery")
        return services().discovery.vendor_of(mac)


# B1-LEASEHIST: one host's lease events (section 15, Lease history); before /<path:key>.
@ns.route("/<path:key>/timeline")
class HostTimeline(Resource):
    @require("read:hosts")
    @ns.doc(
        params={
            "since": "RFC 3339 or Unix seconds (default: the retention window)",
            "until": "RFC 3339 or Unix seconds (default now)",
            "page": "1-based",
            "per_page": "default 50, max 500",
        }
    )
    @ns.response(200, "Events of one host key (mac:, ip:, name:), newest first", m.RawList)
    def get(self, key: str):
        from pelagos.services.lease_history import LeaseHistoryService

        svc = services()
        v6 = bool(svc.ctx.cluster().modules.get("dhcpv6", False))
        rows, meta = LeaseHistoryService.of(svc).timeline(key, time_arg("since"), time_arg("until"), v6)
        return page_of(rows, meta)


@ns.route("/<path:key>")
class OneHost(Resource):
    @require("read:hosts")
    @ns.response(200, "One host (key mac:..., ip:... or name:...)", m.Host)
    @ns.response(404, "not_found", m.Problem)
    def get(self, key: str):
        return services().hosts.get(key).to_dict()
