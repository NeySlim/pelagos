# SPDX-License-Identifier: Apache-2.0
"""Meta endpoints: health, version, capabilities."""

from __future__ import annotations

import platform

from flask_restx import Namespace, Resource

from pelagos import API_VERSION, __version__
from pelagos.api.errors import not_implemented
from pelagos.api.security import ctx, require
from pelagos.domain.common import to_rfc3339, utcnow

ns = Namespace("meta", description="Health, version and capabilities", path="/")


@ns.route("/health")
class Health(Resource):
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
    def get(self):
        c = ctx()
        cluster = c.cluster()
        # Engine capability probes are wired by WP-API-AUTH once the connectors land.
        return {
            "node": c.self_node().to_dict(),
            "modules": cluster.modules,
            "engines": {"bind": None, "kea4": None, "kea6": None, "d2": None},
            "engines_configured": c.node.modules.to_dict(),
        }


@ns.route("/account/preferences")
class Preferences(Resource):
    @require()
    def get(self):
        raise not_implemented("WP-API-AUTH")

    @require()
    def put(self):
        raise not_implemented("WP-API-AUTH")
