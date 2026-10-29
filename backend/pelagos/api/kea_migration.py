# SPDX-License-Identifier: Apache-2.0
"""Kea 2.6 to 3.x migration, read-only analysis (section 26): series per node, targets, report.

The prepare, migrate and rollback plans come with release 0.3.0 (batch C5).
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body
from pelagos.api.security import client_ip, require, services, username

ns = Namespace("kea-migration", description="Kea 3.x migration analysis", path="/install/kea-migration")


@ns.route("")
class Overview(Resource):
    @require("admin:install")
    @ns.response(200, "Kea series and package source per node, targets, the last analysis")
    def get(self):
        return services().kea_migration.overview()


@ns.route("/analyze")
class Analyze(Resource):
    @require("admin:install")
    @ns.response(200, "Report: findings, diffs, packages, validation, blocking")
    @ns.response(400, "validation_error", m.Problem)
    def post(self):
        return services().kea_migration.analyze(json_body(), username(), client_ip())
