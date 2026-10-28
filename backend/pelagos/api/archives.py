# SPDX-License-Identifier: Apache-2.0
"""Scheduled archives and restore (section 23): destinations, runs, list, inspect, restore plans, keys.

Registered by the contract batch; inspect and restore plans are batch B4, the other routes answer
501 until batch B6 builds them.
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body, plan_dict
from pelagos.api.errors import not_implemented
from pelagos.api.security import current_session, require, services, username
from pelagos.auth.rbac import has_permission

ns = Namespace("archives", description="Scheduled archives and restore", path="/admin/archives")

PERM = "admin:archives"


def _todo(batch: str = "B6"):
    raise not_implemented(f"WP-API-AUTH, batch {batch}")


@ns.route("")
class Overview(Resource):
    @require(PERM)
    @ns.response(200, "Settings, recipients, identity state, destinations, per node state")
    @ns.response(501, "not_implemented", m.Problem)
    def get(self):
        _todo()


@ns.route("/destinations")
class Destinations(Resource):
    @require(PERM)
    @ns.response(201, "Destination")
    def post(self):
        _todo()


@ns.route("/destinations/test")
class TestDestination(Resource):
    @require(PERM)
    @ns.response(200, "Write, read back and delete a probe file")
    def post(self):
        _todo()


@ns.route("/destinations/<string:destination_id>")
class OneDestination(Resource):
    @require(PERM)
    @ns.response(200, "Destination")
    def put(self, destination_id: str):
        _todo()

    @require(PERM)
    @ns.response(204, "Deleted")
    def delete(self, destination_id: str):
        _todo()


@ns.route("/run")
class Run(Resource):
    @require(PERM)
    @ns.response(202, "Job")
    def post(self):
        _todo()


@ns.route("/list")
class ArchiveList(Resource):
    @require(PERM)
    @ns.response(200, "Paginated archives of every node")
    def get(self):
        _todo()


@ns.route("/upload")
class Upload(Resource):
    @require(PERM)
    @ns.response(201, "The archive, registered")
    def post(self):
        _todo()


@ns.route("/identity")
class Identity(Resource):
    @require(PERM)
    @ns.response(200, "Recipients; the cluster identity once, on generate and rotate")
    def post(self):
        _todo()


@ns.route("/<string:archive_id>/download")
class Download(Resource):
    @require(PERM)
    @ns.response(200, "The encrypted file, audited")
    def get(self, archive_id: str):
        _todo()


@ns.route("/<string:archive_id>/inspect")
class Inspect(Resource):
    @require(PERM)
    @ns.response(200, "Manifest and restorable parts")
    @ns.response(400, "validation_error: no identity opens the archive, unknown target node", m.Problem)
    @ns.response(404, "not_found: no reachable node holds the archive", m.Problem)
    def post(self, archive_id: str):
        body = json_body(required=False)
        return services().archive_restore.inspect(archive_id, body, username())


@ns.route("/<string:archive_id>/restore/plan")
class RestorePlan(Resource):
    @require(PERM)
    @ns.response(200, "Plan (scope restore, requires_confirmation), applied as a Job", m.Plan)
    @ns.response(403, "forbidden: a chosen part needs a write permission the caller lacks", m.Problem)
    @ns.response(409, "conflict: every chosen part already matches the archive", m.Problem)
    def post(self, archive_id: str):
        perms = current_session().permissions
        plan = services().archive_restore.plan(
            archive_id, json_body(), username(), lambda perm: has_permission(perms, perm)
        )
        return plan_dict(plan)
