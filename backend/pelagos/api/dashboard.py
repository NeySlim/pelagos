# SPDX-License-Identifier: Apache-2.0
"""Dashboard summary and per-user layout."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body
from pelagos.api.errors import ApiError
from pelagos.api.security import current_session, require, services

ns = Namespace("dashboard", description="Dashboard tiles", path="/dashboard")


@ns.route("/summary")
class Summary(Resource):
    @require()
    @ns.response(200, "Every tile; tiles the caller may not read come back empty", m.DashboardSummary)
    def get(self):
        return services().dashboard.summary(set(current_session().permissions))


@ns.route("/layout")
class Layout(Resource):
    @require()
    @ns.response(200, "react-grid-layout items of the current user", m.Layout)
    def get(self):
        return {"layout": services().account.layout(current_session().user_id)}

    @require()
    @ns.expect(m.Layout)
    @ns.response(200, "The stored layout", m.Layout)
    @ns.response(400, "validation_error", m.Problem)
    def put(self):
        body = json_body()
        if "layout" not in body:
            raise ApiError(
                "validation_error", "layout is required", errors=[{"field": "layout", "message": "required"}]
            )
        return {"layout": services().account.update_layout(current_session().user_id, body["layout"])}
