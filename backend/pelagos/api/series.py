# SPDX-License-Identifier: Apache-2.0
"""Time series from the collector cache: pool fill, serials, HA transitions."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api.errors import not_implemented
from pelagos.api.security import require

ns = Namespace("series", description="Series from the local SQLite cache", path="/series")
OWNER = "WP-API-AUTH"


@ns.route("/pools")
class Pools(Resource):
    @require("read:series")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/serials")
class Serials(Resource):
    @require("read:series")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/ha-transitions")
class HaTransitions(Resource):
    @require("read:series")
    def get(self):
        raise not_implemented(OWNER)
