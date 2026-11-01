# SPDX-License-Identifier: Apache-2.0
"""Audit log endpoints, served straight from the JSONL log."""

from __future__ import annotations

from flask import Response
from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, paged, pagination, time_arg
from pelagos.api.errors import ApiError
from pelagos.api.security import ctx, require, services
from pelagos.core.audit_log import SEGMENT_RE
from pelagos.domain import AuditResult, Engine
from pelagos.domain.common import to_rfc3339

ns = Namespace("audit", description="Replicated audit log", path="/audit")

FILTERS = {
    "user": "username",
    "action": "action prefix",
    "target": "target prefix",
    "node_id": "node",
    "engine": "bind, kea4, kea6, d2",
    "result": "ok, error, rolled_back, denied",
    "plan_id": "plan id (exact): its summary and every node entry",
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
            plan_id=arg("plan_id"),
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


@ns.route("/segments")
class Segments(Resource):
    @require("read:audit")
    @ns.response(200, "Sealed segments, the live file and the retention setting")
    def get(self):
        from pelagos.core import settings_registry as reg

        c = ctx()
        log_ = c.audit_log
        first, count = log_.opening()
        size = log_.path.stat().st_size if log_.path.exists() else 0
        return {
            "segments": [s.to_dict() for s in log_.segments()],
            "live": {
                "name": log_.path.name,
                "bytes": size,
                "entries": count,
                "first_ts": to_rfc3339(first) if first else None,
            },
            "retention_years": int(reg.get(c.settings(), "retention.audit_sealed_years")),
        }


@ns.route("/segments/<string:name>/verify")
class VerifySegment(Resource):
    @require("read:audit")
    @ns.response(200, "Verdict: ok, reason, note, lines, entries, peers_checked, checked_at")
    @ns.response(404, "not_found", m.Problem)
    def post(self, name: str):
        from pelagos.core import audit_segments

        if not SEGMENT_RE.match(name):
            raise ApiError("not_found", f"audit segment {name}")
        c = ctx()
        try:
            verdicts = audit_segments.verify(c.audit_log, c.node.id, name, peers=_peer_copies, pause=_pause)
        except KeyError:
            raise ApiError("not_found", f"audit segment {name}") from None
        return verdicts[0].to_dict()


def _pause() -> None:
    """Hand the gevent hub a turn between two blocks of a long hash (one web worker)."""
    try:
        import gevent
    except ImportError:  # pragma: no cover
        return
    gevent.sleep(0)


def _peer_copies(entry_id: str) -> list[dict | None]:
    from pelagos.core.audit_segments import peer_fetch

    return peer_fetch(services().peers)(entry_id)


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
