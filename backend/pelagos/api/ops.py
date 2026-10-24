# SPDX-License-Identifier: Apache-2.0
"""Runtime operations: allow-listed rndc commands and Kea control commands (services.ops_service).

Each operation carries its own permission; changes need ops:dns, ops:dhcp.leases, ops:dhcp.ha or
write:dhcp.config, and are audited. Reads may target a peer, changes run on this node.
"""

from __future__ import annotations

from flask_restx import Namespace, Resource, fields

from pelagos.api.common import arg, json_body
from pelagos.api.errors import ApiError
from pelagos.api.security import check_permission, client_ip, require, require_module, services, username

ns = Namespace("ops", description="Runtime operations on BIND and Kea", path="/")

OpSpec = ns.model(
    "OpSpec",
    {
        "name": fields.String(required=True),
        "permission": fields.String(required=True),
        "write": fields.Boolean(required=True, description="true: changes the daemon's state (audited)"),
        "params": fields.List(fields.String),
        "required": fields.List(fields.String),
        "confirm": fields.Boolean(description="true: the request needs confirm=true"),
        "choices": fields.Raw,
        "available": fields.Boolean(description="Kea: the daemon offers the command (hooks loaded)"),
    },
)
OpCatalog = ns.model(
    "OpCatalog",
    {
        "node_id": fields.String,
        "family": fields.String,
        "operations": fields.List(fields.Nested(OpSpec)),
        "error": fields.String,
    },
)
BindOpRequest = ns.model(
    "BindOpRequest",
    {
        "op": fields.String(required=True, example="flushname"),
        "params": fields.Raw(description="zone, view, name, lifetime, mode, clean as the operation lists"),
        "node_id": fields.String(description="default: this node; peers answer read operations only"),
        "confirm": fields.Boolean,
    },
)
KeaOpRequest = ns.model(
    "KeaOpRequest",
    {
        "command": fields.String(required=True, example="ha-sync"),
        "params": fields.Raw(description="Typed arguments the command lists (server-name, ip-address...)"),
        "node_id": fields.String,
        "confirm": fields.Boolean,
    },
)


def _family(family: str) -> None:
    if family not in ("v4", "v6", "d2"):
        raise ApiError("not_found", f"unknown family {family}")
    if family == "v6":
        require_module("dhcpv6")


def _body() -> tuple[dict, str | None, bool]:
    body = json_body()
    params = body.get("params") or {}
    if not isinstance(params, dict):
        raise ApiError("validation_error", "params must be an object")
    node_id = body.get("node_id")
    if node_id is not None and not isinstance(node_id, str):
        raise ApiError("validation_error", "node_id must be a string")
    return params, node_id, body.get("confirm") is True


@ns.route("/dns/ops")
class BindOps(Resource):
    @require("read:dns")
    @ns.response(200, "The rndc operations Pelagos runs, with their permission", OpCatalog)
    def get(self):
        return services().ops.bind_catalog()

    @require()
    @ns.expect(BindOpRequest)
    @ns.response(200, "rndc output (changes are audited as dns.ops)")
    @ns.response(428, "confirmation_required")
    def post(self):
        body = json_body()
        op = str(body.get("op") or "")
        ops = services().ops
        check_permission(ops.spec("bind", op).permission)
        params, node_id, confirm = _body()
        return ops.run_bind(op, params, node_id, confirm, username(), client_ip())


@ns.route("/dhcp/<string:family>/ops")
class KeaOps(Resource):
    @require("read:dhcp")
    @ns.doc(params={"family": "v4, v6 or d2", "node_id": "node whose daemon lists its commands"})
    @ns.response(200, "Allow-listed Kea commands, `available` when the daemon offers them", OpCatalog)
    def get(self, family: str):
        _family(family)
        return services().ops.kea_catalog(family, arg("node_id"))

    @require()
    @ns.expect(KeaOpRequest)
    @ns.response(200, "Kea answer arguments (changes are audited as dhcp.ops)")
    @ns.response(428, "confirmation_required")
    def post(self, family: str):
        _family(family)
        body = json_body()
        command = str(body.get("command") or "")
        ops = services().ops
        check_permission(ops.spec(family, command).permission)
        params, node_id, confirm = _body()
        return ops.run_kea(family, command, params, node_id, confirm, username(), client_ip())
