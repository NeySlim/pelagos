# SPDX-License-Identifier: Apache-2.0
"""Audit log endpoints, served straight from the JSONL log."""

from __future__ import annotations

from flask import Response, request
from flask_restx import Namespace, Resource

from pelagos.api.errors import ApiError
from pelagos.api.security import ctx, require
from pelagos.domain.common import from_rfc3339

ns = Namespace("audit", description="Replicated audit log", path="/audit")


def _time(name: str):
    raw = request.args.get(name)
    if not raw:
        return None
    try:
        return from_rfc3339(int(raw) if raw.isdigit() else raw)
    except ValueError:
        raise ApiError("validation_error", f"{name} must be RFC 3339 or Unix seconds") from None


def pagination() -> tuple[int, int]:
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(500, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        raise ApiError("validation_error", "page and per_page must be integers") from None
    return page, per_page


@ns.route("")
class Audit(Resource):
    @require("read:audit")
    def get(self):
        page, per_page = pagination()
        rows, total = ctx().audit_log.query(
            user=request.args.get("user"),
            action=request.args.get("action"),
            target=request.args.get("target"),
            node_id=request.args.get("node_id"),
            engine=request.args.get("engine"),
            result=request.args.get("result"),
            since=_time("from"),
            until=_time("to"),
            page=page,
            per_page=per_page,
        )
        return {
            "items": [e.to_dict() for e in rows],
            "page": page,
            "per_page": per_page,
            "total": total,
            "meta": {},
        }


@ns.route("/export")
class Export(Resource):
    @require("read:audit")
    def get(self):
        since, until = _time("from"), _time("to")
        lines = ctx().audit_log.export_lines(since, until)
        return Response(lines, mimetype="application/x-ndjson")


@ns.route("/<string:entry_id>")
class OneEntry(Resource):
    @require("read:audit")
    def get(self, entry_id: str):
        entry = ctx().audit_log.get(entry_id)
        if entry is None:
            raise ApiError("not_found", f"audit entry {entry_id}")
        return entry.to_dict()
