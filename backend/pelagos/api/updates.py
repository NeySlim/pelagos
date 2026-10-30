# SPDX-License-Identifier: Apache-2.0
"""Updates from the UI (section 29): available releases, upload, plans, the rollout and its history.

Registered by the contract batch C3; each route answers 501 until batch U5 builds it on U3.
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.errors import not_implemented
from pelagos.api.security import require

ns = Namespace("updates", description="Updates of Pelagos and of the engine packages", path="/admin/updates")

PERM = "admin:updates"


def _todo():
    raise not_implemented("batch U5")


@ns.route("")
class Overview(Resource):
    @require(PERM)
    @ns.response(200, "Nodes and versions, available releases, the rollout, settings, engine packages")
    @ns.response(501, "not_implemented", m.Problem)
    def get(self):
        _todo()


@ns.route("/check")
class Check(Resource):
    @require(PERM)
    @ns.response(200, "Available releases, checked now")
    @ns.response(501, "not_implemented", m.Problem)
    def post(self):
        _todo()


@ns.route("/upload")
class Upload(Resource):
    @require(PERM)
    @ns.response(201, "The release: version, files, signature state")
    @ns.response(422, "release_invalid: signature, checksum, name, architecture or manifest", m.Problem)
    @ns.response(501, "not_implemented", m.Problem)
    def post(self):
        _todo()


@ns.route("/settings")
class Settings(Resource):
    @require(PERM)
    @ns.response(200, "The [settings.updates] values")
    @ns.response(501, "not_implemented", m.Problem)
    def put(self):
        _todo()


@ns.route("/plan")
class PlanRoute(Resource):
    @require(PERM)
    @ns.response(200, "Plan (scope update, requires_confirmation)")
    @ns.response(400, "validation_error: unsigned release not accepted, unknown version or node", m.Problem)
    @ns.response(409, "conflict: a rollout is active", m.Problem)
    @ns.response(501, "not_implemented", m.Problem)
    def post(self):
        _todo()


@ns.route("/rollout")
class RolloutRoute(Resource):
    @require(PERM)
    @ns.response(200, "The active or last rollout, null when none")
    @ns.response(501, "not_implemented", m.Problem)
    def get(self):
        _todo()


@ns.route("/rollout/<string:rollout_id>/action")
class RolloutAction(Resource):
    @require(PERM)
    @ns.response(200, "The rollout after the action")
    @ns.response(409, "conflict: the action does not fit the rollout state", m.Problem)
    @ns.response(501, "not_implemented", m.Problem)
    def post(self, rollout_id: str):
        _todo()


@ns.route("/history")
class History(Resource):
    @require(PERM)
    @ns.response(200, "Past rollouts, paginated")
    @ns.response(501, "not_implemented", m.Problem)
    def get(self):
        _todo()
