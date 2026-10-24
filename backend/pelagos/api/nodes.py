# SPDX-License-Identifier: Apache-2.0
"""Nodes and replication endpoints."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body
from pelagos.api.errors import ApiError
from pelagos.api.security import client_ip, ctx, require, services, username
from pelagos.domain.cluster import Node, NodeStatus

ns = Namespace("nodes", description="Cluster nodes and replication", path="/nodes")


def _nodes() -> list[Node]:
    c = ctx()
    peers = services().peers
    out = []
    for peer in c.cluster().nodes:
        out.append(c.self_node() if peer.id == c.node.id else peers.node(peer))
    return out


@ns.route("")
class Nodes(Resource):
    @require("read:nodes")
    @ns.response(200, "Every enrolled node with its liveness", m.NodeList)
    def get(self):
        return {"items": [n.to_dict() for n in _nodes()]}


@ns.route("/self")
class SelfNode(Resource):
    @require("read:nodes")
    @ns.response(200, "This node", m.Node)
    def get(self):
        return ctx().self_node().to_dict()


@ns.route("/replication")
class Replication(Resource):
    @require("read:nodes")
    @ns.response(200, "Replication state and per-peer heads", m.Replication)
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
                    "last_seen": n.to_dict()["last_seen"],
                    "error": n.error,
                }
                for n in peers
            ],
        }


@ns.route("/enroll-token")
class EnrollToken(Resource):
    @require("admin:nodes")
    @ns.expect(m.EnrollTokenRequest)
    @ns.response(200, "One-time enrollment token and the command to run on the new node")
    @ns.response(409, "conflict: this node does not hold the cluster CA key", m.Problem)
    def post(self):
        body = json_body(required=False)
        return services().admin.enroll_token(
            body.get("ttl_seconds", 900), username(), client_ip(), body.get("ca", False)
        )


@ns.route("/<string:node_id>")
class OneNode(Resource):
    @require("read:nodes")
    @ns.response(200, "One node", m.Node)
    @ns.response(404, "not_found", m.Problem)
    def get(self, node_id: str):
        node = next((n for n in _nodes() if n.peer.id == node_id), None)
        if node is None:
            raise ApiError("not_found", f"node {node_id}")
        return node.to_dict()

    @require("admin:nodes")
    @ns.response(204, "Node removed and its certificate revoked")
    @ns.response(409, "conflict: a node cannot remove itself", m.Problem)
    def delete(self, node_id: str):
        services().admin.remove_node(node_id, username(), client_ip())
        services().peers.forget(node_id)
        return "", 204


@ns.route("/<string:node_id>/sync")
class SyncNode(Resource):
    @require("admin:nodes")
    @ns.response(200, "Pulled configuration and audit from the peer", m.SyncAnswer)
    @ns.response(503, "engine_unavailable: peer unreachable", m.Problem)
    def post(self, node_id: str):
        s = services()
        peer = s.peers.peer(node_id)
        if peer is None:
            raise ApiError("not_found", f"node {node_id} (or this node)")
        status = s.peers.sync(peer)
        s.admin.audit_sync(peer, status, username(), client_ip())
        if not status.reachable:
            raise ApiError("engine_unavailable", f"{peer.name}: {status.error or 'unreachable'}")
        return {
            "config_adopted": bool(status.config_adopted),
            "audit_added": int(status.audit_added),
            "status": status.to_dict(),
        }
