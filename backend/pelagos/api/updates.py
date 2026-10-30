# SPDX-License-Identifier: Apache-2.0
"""Updates from the UI (section 29): available releases, upload, plans, the rollout and its history."""

from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body, page_of, plan_answer
from pelagos.api.errors import ApiError
from pelagos.api.security import client_ip, current_session, require, services, username

ns = Namespace("updates", description="Updates of Pelagos and of the engine packages", path="/admin/updates")

PERM = "admin:updates"


def _svc():
    return services().updates


@ns.route("")
class Overview(Resource):
    @require(PERM)
    @ns.response(200, "Nodes and versions, available releases, the rollout, settings, engine packages")
    def get(self):
        return _svc().overview()


@ns.route("/check")
class Check(Resource):
    @require(PERM)
    @ns.response(200, "Available releases, checked now")
    @ns.response(409, "conflict: the github source has no repository", m.Problem)
    def post(self):
        json_body(required=False)
        return _svc().check(username(), client_ip())


@ns.route("/upload")
class Upload(Resource):
    @require(PERM)
    @ns.doc(params={"files": "multipart: the files of a release directory"})
    @ns.response(201, "The release: version, files, signature state")
    @ns.response(400, "validation_error: no file sent", m.Problem)
    @ns.response(422, "release_invalid: signature, checksum, name, architecture or manifest", m.Problem)
    def post(self):
        uploads = request.files.getlist("files")
        files = [(u.filename or "", u.stream) for u in uploads]
        return _svc().upload(files, username(), client_ip()), 201


@ns.route("/settings")
class Settings(Resource):
    @require(PERM)
    @ns.response(200, "The [settings.updates] values")
    @ns.response(400, "validation_error: a bad value, or the github source without a repository", m.Problem)
    def put(self):
        return _svc().save_settings(json_body(), username(), client_ip())


@ns.route("/plan")
class PlanRoute(Resource):
    @require(PERM)
    @ns.response(200, "Plan (scope update, requires_confirmation)", m.Plan)
    @ns.response(400, "validation_error: unsigned release not accepted, unknown version or node", m.Problem)
    @ns.response(409, "conflict: a rollout is active", m.Problem)
    @ns.response(422, "release_invalid: the release signature does not verify", m.Problem)
    def post(self):
        return plan_answer(_svc().plan(json_body(), username()))


@ns.route("/rollout")
class RolloutRoute(Resource):
    @require(PERM)
    @ns.response(200, "The active rollout, null when none")
    def get(self):
        return _svc().rollout()


@ns.route("/rollout/<string:rollout_id>/action")
class RolloutAction(Resource):
    @require(PERM)
    @ns.response(200, "The rollout after the action (the new one after rollback)")
    @ns.response(401, "invalid_credentials: rollback needs the user's password", m.Problem)
    @ns.response(404, "not_found: not the current rollout", m.Problem)
    @ns.response(409, "conflict: the action does not fit the rollout state", m.Problem)
    def post(self, rollout_id: str):
        session = current_session()
        body = json_body()
        if not isinstance(body, dict):
            raise ApiError("validation_error", "a JSON object is required")
        return _svc().action(rollout_id, body, session.user_id, session.username, client_ip())


@ns.route("/history")
class History(Resource):
    @require(PERM)
    @ns.response(200, "Past rollouts, paginated")
    def get(self):
        return page_of(_svc().history())
