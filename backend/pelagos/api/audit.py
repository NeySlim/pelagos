# SPDX-License-Identifier: Apache-2.0
"""Audit log endpoints, served straight from the JSONL log."""

from __future__ import annotations

from flask import Response
from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, paged, pagination, time_arg
from pelagos.api.errors import ApiError
from pelagos.api.security import ctx, require
from pelagos.domain import AuditResult, Engine

ns = Namespace("audit", description="Replicated audit log", path="/audit")

FILTERS = {
    "user": "username",
    "action": "action prefix",
    "target": "target prefix",
    "node_id": "node",
    "engine": "bind, kea4, kea6, d2",
    "result": "ok, error, rolled_back, denied",
    "from": "RFC 3339 or Unix seconds",
    "to": "RFC 3339 or Unix seconds",
    "page": "1-based",
    "per_page": "default 50, max 500",
}


@ns.route("")
class Audit(Resource):
    @require("read:audit")
    @ns.doc(params=FILTERS)
    @ns.response(200, "Entries sorted by (ts, id) descending", m.AuditPage)
    def get(self):
        page, per_page = pagination()
        engine, result = arg("engine"), arg("result")
        if engine is not None and engine not in {e.value for e in Engine}:
            raise ApiError("validation_error", f"unknown engine {engine}")
        if result is not None and result not in {r.value for r in AuditResult}:
            raise ApiError("validation_error", f"unknown result {result}")
        rows, total = ctx().audit_log.query(
            user=arg("user"),
            action=arg("action"),
            target=arg("target"),
            node_id=arg("node_id"),
            engine=engine,
            result=result,
            since=time_arg("from"),
            until=time_arg("to"),
            page=page,
            per_page=per_page,
        )
        return paged(rows, page, per_page, total)


@ns.route("/export")
class Export(Resource):
    @require("read:audit")
    @ns.doc(params={"from": "RFC 3339 or Unix seconds", "to": "RFC 3339 or Unix seconds"})
    @ns.produces(["application/x-ndjson"])
    @ns.response(200, "One AuditEntry per line")
    def get(self):
        lines = ctx().audit_log.export_lines(time_arg("from"), time_arg("to"))
        return Response(lines, mimetype="application/x-ndjson")


@ns.route("/<string:entry_id>")
class OneEntry(Resource):
    @require("read:audit")
    @ns.response(200, "One entry", m.AuditEntry)
    @ns.response(404, "not_found", m.Problem)
    def get(self, entry_id: str):
        entry = ctx().audit_log.get(entry_id)
        if entry is None:
            raise ApiError("not_found", f"audit entry {entry_id}")
        return entry.to_dict()
