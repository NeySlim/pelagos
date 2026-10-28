# SPDX-License-Identifier: Apache-2.0
"""Outgoing notifications (section 22): channels, test sends, sender order, mute, history."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, json_body, paged, pagination, time_arg
from pelagos.api.errors import ApiError
from pelagos.api.security import client_ip, require, services, username

ns = Namespace("notifications", description="Alert notifications", path="/admin/notifications")

PERM = "admin:notifications"


def notify():
    return services().notifications


@ns.route("")
class Overview(Resource):
    @require(PERM)
    @ns.response(200, "Channels (secrets as booleans), settings, sender, mute, queue")
    def get(self):
        return notify().overview()


@ns.route("/channels")
class Channels(Resource):
    @require(PERM)
    @ns.response(201, "Channel")
    @ns.response(400, "validation_error", m.Problem)
    def post(self):
        return notify().create(json_body(), username(), client_ip()), 201


@ns.route("/channels/<string:channel_id>")
class OneChannel(Resource):
    @require(PERM)
    @ns.response(200, "Channel")
    @ns.response(404, "not_found", m.Problem)
    def put(self, channel_id: str):
        return notify().update(channel_id, json_body(), username(), client_ip())

    @require(PERM)
    @ns.response(204, "Deleted")
    @ns.response(404, "not_found", m.Problem)
    def delete(self, channel_id: str):
        notify().delete(channel_id, username(), client_ip())
        return "", 204


@ns.route("/test")
class Test(Resource):
    @require(PERM)
    @ns.response(200, "Result of a real send from this node")
    @ns.response(429, "rate_limited", m.Problem)
    def post(self):
        svc = notify()
        body = json_body()
        user = username()
        if not svc.test_limiter.allow(user):
            retry = svc.test_limiter.retry_after(user)
            raise ApiError("rate_limited", "too many test sends", headers={"Retry-After": str(retry)})
        return svc.test(body, user, client_ip())


@ns.route("/order")
class Order(Resource):
    @require(PERM)
    @ns.response(200, "Sender order")
    def put(self):
        return notify().set_order(json_body(), username(), client_ip())


@ns.route("/mute")
class Mute(Resource):
    @require(PERM)
    @ns.response(200, "Mute set")
    def put(self):
        return notify().set_mute(json_body(), username(), client_ip())

    @require(PERM)
    @ns.response(204, "Mute ended")
    def delete(self):
        notify().unmute(username(), client_ip())
        return "", 204


@ns.route("/history")
class History(Resource):
    @require(PERM)
    @ns.doc(
        params={
            "channel_id": "one channel",
            "result": "ok or failed",
            "alert_id": "batches that carried this alert",
            "from": "RFC 3339 or Unix seconds",
            "to": "RFC 3339 or Unix seconds",
            "page": "1-based",
            "per_page": "1 to 500",
        }
    )
    @ns.response(200, "Paginated sends and failures, newest first")
    def get(self):
        page, per_page = pagination()
        rows, total = notify().history(
            channel_id=arg("channel_id"),
            result=arg("result"),
            alert_id=arg("alert_id"),
            since=time_arg("from"),
            until=time_arg("to"),
            page=page,
            per_page=per_page,
        )
        return paged(rows, page, per_page, total)
