# SPDX-License-Identifier: Apache-2.0
"""DDNS without a single point of failure (section 24): resilience state, prepare, failover,
switchover and replay plans.

Registered by the contract batch; each route answers 501 until its work package builds it (D2 to D4).
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body, plan_answer
from pelagos.api.errors import not_implemented
from pelagos.api.security import check_permission, require, services, username

ns = Namespace("ddns-failover", description="DDNS failover and replay", path="/dhcp/ddns")


def _todo(batch: str):
    raise not_implemented(f"batch {batch}")


@ns.route("/resilience")
class Resilience(Resource):
    @require("read:dhcp")
    @ns.response(200, "Active primary per dynamic zone, D2 server lists, outage, replay candidates")
    def get(self):
        check_permission("read:dns")
        return services().ddns_failover.resilience()


@ns.route("/resilience/plan")
class Prepare(Resource):
    @require("write:dns.zones")
    @ns.response(200, "Composite plan: keys on the secondaries, D2 lists, ddns.roles", m.Plan)
    @ns.response(409, "conflict: every selected zone is prepared, or none can be", m.Problem)
    def post(self):
        check_permission("write:dhcp.config")
        return plan_answer(services().ddns_failover.plan(json_body(required=False), username()))


@ns.route("/failover/plan")
class Failover(Resource):
    @require("write:dns.zones")
    @ns.response(200, "Composite plan (requires_confirmation)")
    @ns.response(409, "conflict: the active primary still answers", m.Problem)
    def post(self):
        check_permission("write:dhcp.config")
        _todo("D3")


@ns.route("/switchover/plan")
class Switchover(Resource):
    @require("write:dns.zones")
    @ns.response(200, "Composite plan (requires_confirmation)")
    def post(self):
        check_permission("write:dhcp.config")
        _todo("D4")


@ns.route("/replay/plan")
class Replay(Resource):
    @require("ops:dhcp.leases")
    @ns.response(200, "Plan: one lease4/6-resend-ddns per lease (scope dhcp.lease)", m.Plan)
    @ns.response(409, "conflict: no lease of the window lacks its records", m.Problem)
    def post(self):
        return plan_answer(services().ddns_replay.plan(json_body(required=False), username()))
