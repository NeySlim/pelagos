# SPDX-License-Identifier: Apache-2.0
"""Kea 2.6 to 3.x migration: series per node, targets, analysis report (section 26), and the
prepare, migrate and rollback plans with the replicated migration state (section 28).

`POST /{id}/plan` builds the prepare phase (K3), time 1 and its return (K4); the window and time 3
come with K5.
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body, plan_answer
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
    @ns.response(404, "not_found: not the last analysis (prepare) or the migration", m.Problem)
    @ns.response(501, "not_implemented: a phase after time 1 (batch K5)", m.Problem)
    def post(self, migration_id: str):
        check_permission("ops:dhcp.ha")
        return plan_answer(services().kea_migration.plan(migration_id, json_body(), username(), client_ip()))
