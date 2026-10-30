# SPDX-License-Identifier: Apache-2.0
"""Kea 2.6 to 3.x migration: series per node, targets, analysis report (section 26), and the
prepare, migrate and rollback plans with the replicated migration state (section 28).

`POST /{id}/plan` answers 501 until batches K3 to K5 build the phases on the C5 contract.
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body
from pelagos.api.errors import not_implemented
from pelagos.api.security import check_permission, client_ip, require, services, username

ns = Namespace("kea-migration", description="Kea 3.x migration", path="/install/kea-migration")


@ns.route("")
class Overview(Resource):
    @require("admin:install")
    @ns.response(200, "Kea series and package source per node, targets, the last analysis, the migration")
    def get(self):
        return services().kea_migration.overview()


@ns.route("/analyze")
class Analyze(Resource):
    @require("admin:install")
    @ns.response(200, "Report: findings, diffs, packages, validation, blocking")
    @ns.response(400, "validation_error", m.Problem)
    def post(self):
        return services().kea_migration.analyze(json_body(), username(), client_ip())


@ns.route("/<string:migration_id>")
class Migration(Resource):
    @require("admin:install")
    @ns.response(200, "Migration: state, phase, stage, nodes, outage, rollback_possible")
    @ns.response(404, "not_found: not the migration cluster.toml holds", m.Problem)
    def get(self, migration_id: str):
        return services().kea_migration.migration(migration_id)


@ns.route("/<string:migration_id>/plan")
class PhasePlan(Resource):
    @require("admin:install")
    @ns.response(200, "Composite plan (scope kea.migration, requires_confirmation)", m.Plan)
    @ns.response(
        409, "conflict: a blocking finding is open, or the phase does not follow the state", m.Problem
    )
    @ns.response(501, "not_implemented", m.Problem)
    def post(self, migration_id: str):
        check_permission("ops:dhcp.ha")
        raise not_implemented("batches K3 to K5")
