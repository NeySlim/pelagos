# SPDX-License-Identifier: Apache-2.0
"""Outgoing notifications (section 22): channels, test sends, sender order, mute, history.

Registered by the contract batch; each route answers 501 until its work package builds it (N3).
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.errors import not_implemented
from pelagos.api.security import require

ns = Namespace("notifications", description="Alert notifications", path="/admin/notifications")

OWNER = "WP-API-AUTH, batch N3"
PERM = "admin:notifications"


def _todo():
    raise not_implemented(OWNER)


@ns.route("")
class Overview(Resource):
    @require(PERM)
    @ns.response(200, "Channels (secrets as booleans), settings, sender, mute, queue")
    @ns.response(501, "not_implemented", m.Problem)
    def get(self):
        _todo()


@ns.route("/channels")
class Channels(Resource):
    @require(PERM)
    @ns.response(201, "Channel")
    def post(self):
        _todo()


@ns.route("/channels/<string:channel_id>")
class OneChannel(Resource):
    @require(PERM)
    @ns.response(200, "Channel")
    def put(self, channel_id: str):
        _todo()

    @require(PERM)
    @ns.response(204, "Deleted")
    def delete(self, channel_id: str):
        _todo()


@ns.route("/test")
class Test(Resource):
    @require(PERM)
    @ns.response(200, "Result of a real send from this node")
    def post(self):
        _todo()


@ns.route("/order")
class Order(Resource):
    @require(PERM)
    @ns.response(200, "Sender order")
    def put(self):
        _todo()


@ns.route("/mute")
class Mute(Resource):
    @require(PERM)
    @ns.response(200, "Mute set")
    def put(self):
        _todo()

    @require(PERM)
    @ns.response(200, "Mute lifted")
    def delete(self):
        _todo()


@ns.route("/history")
class History(Resource):
    @require(PERM)
    @ns.response(200, "Paginated sends and failures")
    def get(self):
        _todo()
