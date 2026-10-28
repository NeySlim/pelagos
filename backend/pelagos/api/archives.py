# SPDX-License-Identifier: Apache-2.0
"""Scheduled archives and restore (section 23): destinations, runs, list, inspect, restore plans, keys.

Registered by the contract batch; each route answers 501 until its work package builds it (B6, B4).
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.errors import not_implemented
from pelagos.api.security import require

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
    def post(self, archive_id: str):
        _todo("B4")


@ns.route("/<string:archive_id>/restore/plan")
class RestorePlan(Resource):
    @require(PERM)
    @ns.response(200, "Plan (scope restore)")
    def post(self, archive_id: str):
        _todo("B4")
