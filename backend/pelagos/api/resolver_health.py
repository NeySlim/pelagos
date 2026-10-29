# SPDX-License-Identifier: Apache-2.0
"""Resolver health and forwarder fallback (section 25): per node measures and probes, fallback plans.

Registered by the contract batch; each route answers 501 until its batch builds it (R1, R3).
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, int_arg, time_range
from pelagos.api.errors import ApiError, not_implemented
from pelagos.api.security import require, services
from pelagos.collector.resolver import METRICS

ns = Namespace("resolver-health", description="Resolver health and forwarder fallback", path="/dns/resolver")
series_ns = Namespace("resolver-series", description="Resolver measures over time", path="/series/resolver")


def _todo(batch: str = "R3"):
    raise not_implemented(f"batch {batch}")


@ns.route("/health")
class Health(Resource):
    @require("read:dns")
    @ns.response(200, "Measures, root and TLD probes per node, the fallback, the thresholds")
    @ns.response(501, "not_implemented", m.Problem)
    def get(self):
        _todo()


@ns.route("/fallback")
class Fallback(Resource):
    @require("write:dns.config")
    @ns.response(200, "The fallback with its new deadline")
    @ns.response(409, "conflict: no fallback is active", m.Problem)
    def put(self):
        _todo()


@ns.route("/fallback/plan")
class FallbackPlan(Resource):
    @require("write:dns.config")
    @ns.response(200, "Composite plan (scope dns.resolver, requires_confirmation)")
    @ns.response(409, "conflict: a fallback is already active", m.Problem)
    def post(self):
        _todo()


@ns.route("/fallback/return/plan")
class ReturnPlan(Resource):
    @require("write:dns.config")
    @ns.response(200, "Composite plan that puts back forward and forwarders as before")
    @ns.response(409, "conflict: no fallback is active", m.Problem)
    def post(self):
        _todo()


@series_ns.route("")
class ResolverSeries(Resource):
    @require("read:series")
    @series_ns.doc(
        params={
            "metric": "one of " + ", ".join(METRICS) + " (required)",
            "node_id": "node (default: every node serving DNS)",
            "from": "RFC 3339 or Unix seconds (default 24 h before to)",
            "to": "default now",
            "step": "seconds, default 300; points are averages per step",
        }
    )
    @series_ns.response(200, "One series per node: [ts, value]; peers that did not answer in unavailable")
    @series_ns.response(400, "validation_error: metric missing or unknown", m.Problem)
    def get(self):
        metric = arg("metric")
        if metric not in METRICS:
            raise ApiError(
                "validation_error",
                "metric must be one of " + ", ".join(METRICS),
                errors=[{"field": "metric", "message": "required" if metric is None else "unknown"}],
            )
        since, until = time_range()
        step = int_arg("step", minimum=1) or 300
        return services().series.resolver(
            metric=metric, node_id=arg("node_id"), since=since, until=until, step=step
        )
