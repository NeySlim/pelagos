# SPDX-License-Identifier: Apache-2.0
"""Alerts and inconsistencies, read from the collector's SQLite cache."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api.errors import not_implemented
from pelagos.api.security import require

ns = Namespace("alerts", description="Alerts and DNS/DHCP inconsistencies", path="/alerts")
OWNER = "WP-API-AUTH"


@ns.route("")
class Alerts(Resource):
    @require("read:alerts")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/summary")
class Summary(Resource):
    @require("read:alerts")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/consistency/run")
class RunConsistency(Resource):
    @require("write:alerts")
    def post(self):
        raise not_implemented(OWNER)


@ns.route("/<string:alert_id>/ack")
class Ack(Resource):
    @require("write:alerts")
    def post(self, alert_id: str):
        raise not_implemented(OWNER)
