# SPDX-License-Identifier: Apache-2.0
"""Resolver health and forwarder fallback (section 25): per node measures and probes, fallback plans.

Registered by the contract batch; each route answers 501 until its batch builds it (R1, R3).
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.errors import not_implemented
from pelagos.api.security import require

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
    @series_ns.response(200, "Series of one resolver metric, like /series/pools")
    @series_ns.response(501, "not_implemented", m.Problem)
    def get(self):
        _todo("R1")
