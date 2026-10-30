# SPDX-License-Identifier: Apache-2.0
"""Observed IPv6 addresses (section 27): hosts with their observed addresses, observation status."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, json_body, page_of, plan_answer
from pelagos.api.security import client_ip, require, services, username

hosts_ns = Namespace("hosts-ipv6", description="Hosts and their observed IPv6 addresses", path="/hosts/ipv6")
admin_ns = Namespace("admin-ipv6", description="IPv6 observation status, prefixes", path="/admin/ipv6")


def ipv6():
    return services().ipv6


@hosts_ns.route("")
class Hosts(Resource):
    @require("read:hosts")
    @hosts_ns.doc(
        params={
            "filter": "missing_aaaa, missing_ptr, stale, unknown or random_mac",
            "zone": "forward zone of the host or its proposal",
            "host_key": "the rows of one host (hosts view key), as the host card reads them",
            "page": "1-based",
            "per_page": "1 to 500",
        }
    )
    @hosts_ns.response(200, "Paginated hosts with observed addresses, records and proposal")
    @hosts_ns.response(400, "validation_error", m.Problem)
    def get(self):
        rows, meta = ipv6().hosts_list(arg("filter"), arg("zone"), arg("host_key"))
        return page_of(rows, meta)


def plans():
    return services().ipv6_plans


@hosts_ns.route("/plan")
class SelectionPlan(Resource):
    @require("write:dns.records")
    @hosts_ns.response(200, "Plan: AAAA of each selected address and its PTR", m.Plan)
    @hosts_ns.response(400, "validation_error", m.Problem)
    @hosts_ns.response(409, "precondition_failed: reverse_zones lists the zones to create", m.Problem)
    def post(self):
        return plan_answer(plans().plan_selection(json_body(), username()))


@hosts_ns.route("/replace-prefix/plan")
class ReplacePrefixPlan(Resource):
    @require("write:dns.records")
    @hosts_ns.response(200, "Plan: every AAAA of old_prefix moved to new_prefix, PTR along", m.Plan)
    @hosts_ns.response(400, "validation_error", m.Problem)
    @hosts_ns.response(409, "conflict or precondition_failed (reverse_zones)", m.Problem)
    def post(self):
        return plan_answer(plans().plan_replace_prefix(json_body(), username()))


@hosts_ns.route("/reverse-zone/plan")
class ReverseZonePlan(Resource):
    @require("write:dns.zones")
    @hosts_ns.response(200, "Plan: a dynamic primary ip6.arpa zone for the prefix", m.Plan)
    @hosts_ns.response(400, "validation_error", m.Problem)
    @hosts_ns.response(409, "conflict: a served zone already holds the prefix", m.Problem)
    def post(self):
        return plan_answer(plans().plan_reverse_zone(json_body(), username()))


@admin_ns.route("")
class Observation(Resource):
    @require("admin:settings")
    @admin_ns.response(200, "Prefixes, settings, status per source and node")
    def get(self):
        return ipv6().overview()

    @require("admin:settings")
    @admin_ns.response(200, "Prefixes, settings, status")
    @admin_ns.response(400, "validation_error", m.Problem)
    def put(self):
        return ipv6().replace(json_body(), username(), client_ip())
