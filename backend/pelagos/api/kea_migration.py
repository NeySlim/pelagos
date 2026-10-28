# SPDX-License-Identifier: Apache-2.0
"""Kea 2.6 to 3.x migration, read-only analysis (section 26): series per node, targets, report.

Registered by the contract batch; each route answers 501 until batch K2 builds it on K1.
The prepare, migrate and rollback plans come with release 0.3.0 (batch C5).
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.errors import not_implemented
from pelagos.api.security import require

ns = Namespace("kea-migration", description="Kea 3.x migration analysis", path="/install/kea-migration")


def _todo():
    raise not_implemented("batch K2")


@ns.route("")
class Overview(Resource):
    @require("admin:install")
    @ns.response(200, "Kea series and package source per node, targets, the last analysis")
    @ns.response(501, "not_implemented", m.Problem)
    def get(self):
        _todo()


@ns.route("/analyze")
class Analyze(Resource):
    @require("admin:install")
    @ns.response(200, "Report: findings, diffs, packages, validation, blocking")
    @ns.response(501, "not_implemented", m.Problem)
    def post(self):
        _todo()
