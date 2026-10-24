# SPDX-License-Identifier: Apache-2.0
"""Account preferences of the logged-in user (theme, language, dashboard layout)."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body
from pelagos.api.security import current_session, require, services

ns = Namespace("account", description="Preferences of the current user", path="/account")


@ns.route("/preferences")
class Preferences(Resource):
    @require()
    @ns.response(200, "Preferences with defaults filled in", m.Preferences)
    def get(self):
        return services().account.preferences(current_session().user_id)

    @require()
    @ns.expect(m.Preferences)
    @ns.response(200, "The merged preferences", m.Preferences)
    @ns.response(400, "validation_error", m.Problem)
    def put(self):
        return services().account.update_preferences(current_session().user_id, json_body())
