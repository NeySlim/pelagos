# SPDX-License-Identifier: Apache-2.0
"""Install, import and security audit endpoints (WP-INSTALLER provides the services)."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api.errors import not_implemented
from pelagos.api.security import require

ns = Namespace("install", description="Detect, install, import, security audit", path="/install")
OWNER = "WP-INSTALLER"


@ns.route("/detect")
class Detect(Resource):
    @require("admin:install")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/plan")
class InstallPlan(Resource):
    @require("admin:install")
    def post(self):
        raise not_implemented(OWNER)


@ns.route("/import/plan")
class ImportPlan(Resource):
    @require("admin:install")
    def post(self):
        raise not_implemented(OWNER)


@ns.route("/security")
class Security(Resource):
    @require("admin:install")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/security/plan")
class SecurityPlan(Resource):
    @require("admin:install")
    def post(self):
        raise not_implemented(OWNER)
