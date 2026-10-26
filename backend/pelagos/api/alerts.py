# SPDX-License-Identifier: Apache-2.0
"""Alerts and inconsistencies, read from the collector's SQLite cache."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, json_body, paged, pagination
from pelagos.api.security import client_ip, require, services, username

ns = Namespace("alerts", description="Alerts and DNS/DHCP inconsistencies", path="/alerts")

FILTERS = {
    "kind": "alert kind",
    "severity": "info, warning, critical",
    "state": "open, acked, resolved",
    "node_id": "node",
    "engine": "bind, kea4, kea6, d2",
    "page": "1-based",
    "per_page": "default 50, max 500",
}


@ns.route("")
class Alerts(Resource):
    @require("read:alerts")
    @ns.doc(params=FILTERS)
    @ns.response(200, "Alerts, newest first", m.AlertPage)
    def get(self):
        page, per_page = pagination()
        rows, total = services().alerts.query(
            kind=arg("kind"),
            severity=arg("severity"),
            state=arg("state"),
            node_id=arg("node_id"),
            engine=arg("engine"),
            page=page,
            per_page=per_page,
        )
        return paged(rows, page, per_page, total)


@ns.route("/summary")
class Summary(Resource):
    @require("read:alerts")
    @ns.response(200, "Counts of open and acknowledged alerts", m.AlertSummary)
    def get(self):
        return services().alerts.summary()


@ns.route("/consistency/run")
class RunConsistency(Resource):
    @require("write:alerts")
    @ns.response(202, "A job that runs one consistency pass and signals the collector", m.JobRef)
    def post(self):
        s = services()
        job = s.jobs.submit(lambda _job, _progress: s.hosts.consistency_pass())
        return {"job_id": job.id}, 202


@ns.route("/exceptions")
class Exceptions(Resource):
    @require("read:alerts")
    @ns.doc(params={"kind": "alert kind"})
    @ns.response(200, "Admin exceptions to the consistency checks", m.ConsistencyExceptions)
    def get(self):
        return {"items": services().exceptions.list(arg("kind"))}

    @require("write:alerts")
    @ns.expect(m.ConsistencyExceptionBody)
    @ns.response(201, "Created in cluster.toml (audit entry alert.exception.add)", m.ConsistencyException)
    @ns.response(409, "conflict: already an exception", m.Problem)
    def post(self):
        return services().exceptions.create(json_body(), username(), client_ip()), 201


@ns.route("/exceptions/<string:exception_id>")
class ExceptionItem(Resource):
    @require("write:alerts")
    @ns.response(204, "Revoked (audit entry alert.exception.revoke)")
    @ns.response(404, "not_found", m.Problem)
    def delete(self, exception_id: str):
        services().exceptions.revoke(exception_id, username(), client_ip())
        return "", 204


@ns.route("/<string:alert_id>/ack")
class Ack(Resource):
    @require("write:alerts")
    @ns.expect(m.AckBody)
    @ns.response(200, "Acknowledged (audit entry alert.ack, applied by every collector)", m.Alert)
    @ns.response(404, "not_found", m.Problem)
    @ns.response(409, "conflict: resolved alerts cannot be acknowledged", m.Problem)
    def post(self, alert_id: str):
        comment = json_body(required=False).get("comment")
        return services().alerts.ack(alert_id, username(), comment, client_ip()).to_dict()
