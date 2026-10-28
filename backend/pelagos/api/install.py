# SPDX-License-Identifier: Apache-2.0
"""Install, import and security audit endpoints; WP-INSTALLER provides the work behind them."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, json_body, plan_answer
from pelagos.api.security import require, services, username

ns = Namespace("install", description="Detect, install, import, security audit", path="/install")


@ns.route("/detect")
class Detect(Resource):
    @require("admin:install")
    @ns.response(200, "Distribution, engines installed and running, Pelagos integration state")
    def get(self):
        return services().install.detect()


@ns.route("/plan")
class InstallPlan(Resource):
    @require("admin:install")
    @ns.expect(m.InstallBody)
    @ns.response(200, "Plan of scope install; apply returns a Job", m.Plan)
    @ns.response(400, "validation_error", m.Problem)
    def post(self):
        return plan_answer(services().install.plan_install(json_body(), username()))


@ns.route("/import/plan")
class ImportPlan(Resource):
    @require("admin:install")
    @ns.expect(m.InstallBody)
    @ns.response(200, "Plan of scope import", m.Plan)
    @ns.response(400, "validation_error", m.Problem)
    def post(self):
        return plan_answer(services().install.plan_import(json_body(), username()))


@ns.route("/security")
class Security(Resource):
    @require("admin:install")
    @ns.doc(params={"node": "a node id, or all; this node when absent"})
    @ns.response(200, "Security findings with their node and exception, and the nodes that answered")
    @ns.response(400, "validation_error", m.Problem)
    def get(self):
        return services().install.security_report(arg("node"))


@ns.route("/security/plan")
class SecurityPlan(Resource):
    @require("admin:install")
    @ns.expect(m.FindingIds)
    @ns.response(200, "Plan of scope security", m.Plan)
    @ns.response(400, "validation_error", m.Problem)
    def post(self):
        return plan_answer(services().install.plan_security(json_body(), username()))


@ns.route("/security/ha-guard")
class HAGuard(Resource):
    @require("admin:install")
    @ns.doc(params={"node": "a node id; this node when absent"})
    @ns.response(200, "The guard of the Kea HA listeners: managed, loaded, set up by hand, differences")
    @ns.response(400, "validation_error", m.Problem)
    def get(self):
        return services().install.ha_guard(arg("node"))


@ns.route("/security/ha-guard/plan")
class HAGuardPlan(Resource):
    @require("admin:install")
    @ns.expect(m.HAGuardPlan)
    @ns.response(200, "Plan of scope security that loads the guard with these addresses", m.Plan)
    @ns.response(400, "validation_error", m.Problem)
    def post(self):
        return plan_answer(services().install.plan_ha_guard(json_body(), username()))
