# SPDX-License-Identifier: Apache-2.0
"""Time series from the collector cache: pool fill, serials, HA transitions."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, int_arg, time_range
from pelagos.api.errors import ApiError
from pelagos.api.security import require, services

ns = Namespace("series", description="Series from the local SQLite cache", path="/series")

RANGE = {"from": "RFC 3339 or Unix seconds (default 24 h before to)", "to": "default now"}


@ns.route("/pools")
class Pools(Resource):
    @require("read:series")
    @ns.doc(
        params={
            **RANGE,
            "engine": "kea4 or kea6",
            "subnet_id": "subnet id",
            "pool": "pool text",
            "node_id": "node",
            "step": "seconds; raw data under one hour, hourly above",
        }
    )
    @ns.response(200, "One series per (node, engine, subnet, pool): [ts, assigned, total]", m.Series)
    def get(self):
        since, until = time_range()
        step = int_arg("step", minimum=1) or 300
        if arg("engine") not in (None, "kea4", "kea6"):
            raise ApiError("validation_error", "engine must be kea4 or kea6")
        rows = services().series.pools(
            engine=arg("engine"),
            subnet_id=int_arg("subnet_id"),
            pool=arg("pool"),
            node_id=arg("node_id"),
            since=since,
            until=until,
            step=step,
        )
        return {"series": rows}


@ns.route("/serials")
class Serials(Resource):
    @require("read:series")
    @ns.doc(params={**RANGE, "zone": "zone name (required)", "view": "default _default"})
    @ns.response(200, "One series per node: [ts, serial, divergent]", m.Series)
    def get(self):
        zone = arg("zone")
        if not zone:
            raise ApiError(
                "validation_error", "zone is required", errors=[{"field": "zone", "message": "required"}]
            )
        since, until = time_range()
        zone = zone.lower().rstrip(".") + "."
        rows = services().series.serials(zone=zone, view=arg("view") or "_default", since=since, until=until)
        return {"series": rows}


@ns.route("/ha-transitions")
class HaTransitions(Resource):
    @require("read:series")
    @ns.doc(params={**RANGE, "engine": "kea4 or kea6", "node_id": "node"})
    @ns.response(200, "HA state changes", m.RawList)
    def get(self):
        since, until = time_range()
        rows = services().series.ha_transitions(
            engine=arg("engine"), node_id=arg("node_id"), since=since, until=until
        )
        return rows
