# SPDX-License-Identifier: Apache-2.0
"""Hosts: the DNS/DHCP join view and the combined host plan."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api.errors import not_implemented
from pelagos.api.security import require

ns = Namespace("hosts", description="Lease + reservation + records join", path="/hosts")
OWNER = "WP-API-AUTH"


@ns.route("")
class Hosts(Resource):
    @require("read:hosts")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/plan")
class HostPlan(Resource):
    @require("read:hosts")
    def post(self):
        # write:hosts is checked as the union of the dns/dhcp writes the plan expands into.
        raise not_implemented(OWNER)


@ns.route("/<path:key>")
class OneHost(Resource):
    @require("read:hosts")
    def get(self, key: str):
        raise not_implemented(OWNER)
