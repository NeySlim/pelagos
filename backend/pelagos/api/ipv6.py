# SPDX-License-Identifier: Apache-2.0
"""Observed IPv6 addresses (section 27): hosts with their observed addresses, observation sources.

Registered by the contract batch; each route answers 501 until batch V2 builds it on V1.
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.errors import not_implemented
from pelagos.api.security import require

hosts_ns = Namespace("hosts-ipv6", description="Hosts and their observed IPv6 addresses", path="/hosts/ipv6")
admin_ns = Namespace("admin-ipv6", description="IPv6 observation sources", path="/admin/ipv6")


def _todo():
    raise not_implemented("batch V2")


@hosts_ns.route("")
class Hosts(Resource):
    @require("read:hosts")
    @hosts_ns.response(200, "Paginated hosts with observed addresses, records and proposal")
    @hosts_ns.response(501, "not_implemented", m.Problem)
    def get(self):
        _todo()


@admin_ns.route("")
class Sources(Resource):
    @require("admin:settings")
    @admin_ns.response(200, "Sources (secrets as booleans), prefixes, status per source and node")
    @admin_ns.response(501, "not_implemented", m.Problem)
    def get(self):
        _todo()

    @require("admin:settings")
    @admin_ns.response(200, "Sources, prefixes, status")
    def put(self):
        _todo()


@admin_ns.route("/sources/test")
class TestSource(Resource):
    @require("admin:settings")
    @admin_ns.response(200, "One poll of the source from this node")
    def post(self):
        _todo()
