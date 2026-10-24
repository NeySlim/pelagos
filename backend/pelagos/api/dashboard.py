# SPDX-License-Identifier: Apache-2.0
"""Dashboard summary and per-user layout."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api.errors import not_implemented
from pelagos.api.security import require

ns = Namespace("dashboard", description="Dashboard tiles", path="/dashboard")


@ns.route("/summary")
class Summary(Resource):
    @require()
    def get(self):
        raise not_implemented("WP-API-AUTH")


@ns.route("/layout")
class Layout(Resource):
    @require()
    def get(self):
        raise not_implemented("WP-API-AUTH")

    @require()
    def put(self):
        raise not_implemented("WP-API-AUTH")
