# SPDX-License-Identifier: Apache-2.0
"""Meta endpoints: health, version, capabilities."""

from __future__ import annotations

import platform

from flask_restx import Namespace, Resource

from pelagos import API_VERSION, __version__
from pelagos.api import models as m
from pelagos.api.security import ctx, require, services
from pelagos.domain.common import to_rfc3339, utcnow

ns = Namespace("meta", description="Health, version and capabilities", path="/")


@ns.route("/health")
class Health(Resource):
    @ns.doc(security=[])
    @ns.response(200, "Liveness and replication state (anonymous)", m.Health)
    def get(self):
        c = ctx()
        status = "ok" if c.replication_state == "ready" else "degraded"
        return {
            "status": status,
            "replication": c.replication_state,
            "node_id": c.node.id,
            "time": to_rfc3339(utcnow()),
        }


@ns.route("/version")
class Version(Resource):
    @ns.doc(security=[])
    @ns.response(200, "Package and API versions (anonymous)", m.Version)
    def get(self):
        return {
            "version": __version__,
            "api": API_VERSION,
            "python": platform.python_version(),
            "build": None,
        }


@ns.route("/capabilities")
class Capabilities(Resource):
    @require()
    @ns.response(
        200, "This node, the cluster modules and the capabilities of the local engines", m.Capabilities
    )
    def get(self):
        c = ctx()
        cluster = c.cluster()
        return {
            "node": c.self_node().to_dict(),
            "modules": {k: cluster.modules.get(k) for k in ("dhcpv6", "advanced_editor")},
            "engines": services().dashboard.engines(),
            "engines_configured": c.node.modules.to_dict(),
        }
