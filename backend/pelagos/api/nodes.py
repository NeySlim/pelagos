# SPDX-License-Identifier: Apache-2.0
"""Nodes and replication endpoints."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api.errors import ApiError, not_implemented
from pelagos.api.security import ctx, require
from pelagos.domain.cluster import Node, NodeStatus

ns = Namespace("nodes", description="Cluster nodes and replication", path="/nodes")


def _nodes() -> list[Node]:
    c = ctx()
    out = []
    for peer in c.cluster().nodes:
        if peer.id == c.node.id:
            out.append(c.self_node())
        else:
            # Liveness comes from the collector's peer poll (WP-CORE/WP-COLLECTOR); unknown until then.
            out.append(Node(peer=peer, is_self=False, status=NodeStatus.UNKNOWN))
    return out


@ns.route("")
class Nodes(Resource):
    @require("read:nodes")
    def get(self):
        return {"items": [n.to_dict() for n in _nodes()]}


@ns.route("/self")
class SelfNode(Resource):
    @require("read:nodes")
    def get(self):
        return ctx().self_node().to_dict()


@ns.route("/replication")
class Replication(Resource):
    @require("read:nodes")
    def get(self):
        c = ctx()
        peers = [n for n in _nodes() if not n.is_self]
        return {
            "state": c.replication_state,
            "peers": [
                {
                    "node_id": n.peer.id,
                    "reachable": n.status is NodeStatus.ONLINE,
                    "config_version": n.config_version,
                    "audit_count": n.audit_count,
                    "last_seen": n.last_seen,
                    "error": n.error,
                }
                for n in peers
            ],
        }


@ns.route("/enroll-token")
class EnrollToken(Resource):
    @require("admin:nodes")
    def post(self):
        raise not_implemented("WP-CORE")


@ns.route("/<string:node_id>")
class OneNode(Resource):
    @require("read:nodes")
    def get(self, node_id: str):
        node = next((n for n in _nodes() if n.peer.id == node_id), None)
        if node is None:
            raise ApiError("not_found", f"node {node_id}")
        return node.to_dict()

    @require("admin:nodes")
    def delete(self, node_id: str):
        raise not_implemented("WP-CORE")


@ns.route("/<string:node_id>/sync")
class SyncNode(Resource):
    @require("admin:nodes")
    def post(self, node_id: str):
        raise not_implemented("WP-CORE")
