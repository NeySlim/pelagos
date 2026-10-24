# SPDX-License-Identifier: Apache-2.0
"""DNS endpoints (section 17, DNS table) over the DNS service.

`{zone}` in paths is the zone name with or without the trailing dot; answers
use the absolute lowercase form.
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, items, json_body, page_of, plan_answer
from pelagos.api.errors import ApiError
from pelagos.api.security import client_ip, require, services, username

ns = Namespace("dns", description="Zones, records, BIND configuration", path="/dns")

NODE = {"node_id": "node to read (default: this node, else the first node running BIND)"}
VIEW = {"view": "BIND view (default: every view, or _default for one zone)"}


def dns():
    return services().dns


def _changes(body: dict) -> list:
    changes = body.get("changes")
    if not isinstance(changes, list):
        raise ApiError(
            "validation_error", "changes must be a list", errors=[{"field": "changes", "message": "list"}]
        )
    return changes


def _change(body: dict) -> dict:
    change = body.get("change")
    if not isinstance(change, dict):
        raise ApiError(
            "validation_error", "change is required", errors=[{"field": "change", "message": "object"}]
        )
    return change


@ns.route("/instances")
class Instances(Resource):
    @require("read:dns")
    @ns.response(200, "BIND on every node: capabilities and rndc status", m.Instances)
    def get(self):
        return {"items": dns().instances()}


@ns.route("/zones")
class Zones(Resource):
    @require("read:dns")
    @ns.doc(params={**VIEW, "kind": "primary, secondary, ...", "q": "substring of the zone name"})
    @ns.response(200, "Zones with serials per node; transfer-fed zones carry their status", m.ZoneList)
    def get(self):
        return {"items": dns().zones(arg("view"), arg("kind"), arg("q"), status=True)}


@ns.route("/zones/plan")
class ZonesPlan(Resource):
    @require("write:dns.zones")
    @ns.expect(m.ChangeBody)
    @ns.response(200, "Plan (target <view>/<zone>, after = Zone)", m.Plan)
    @ns.response(422, "engine_validation_failed", m.Problem)
    def post(self):
        return plan_answer(dns().plan_zone(_change(json_body()), username()))


@ns.route("/zones/<string:zone>")
class OneZone(Resource):
    @require("read:dns")
    @ns.doc(params=VIEW)
    @ns.response(200, "Zone and its status on each node", m.ZoneDetail)
    @ns.response(404, "not_found", m.Problem)
    def get(self, zone: str):
        z, statuses = dns().zone(zone, arg("view"))
        return {"zone": z.to_dict(), "status": {k: v.to_dict() for k, v in statuses.items()}}


@ns.route("/zones/<string:zone>/records")
class Records(Resource):
    @require("read:dns")
    @ns.doc(
        params={
            **VIEW,
            **NODE,
            "type": "RR type",
            "name": "owner, relative or absolute",
            "q": "substring of owner or rdata",
            "page": "1-based",
            "per_page": "default 50, max 500",
        }
    )
    @ns.response(200, "RRsets read by AXFR; meta.node_id is the node read", m.RRsetPage)
    def get(self, zone: str):
        rrsets, node_id = dns().records(zone, arg("view"), arg("type"), arg("name"), arg("q"), arg("node_id"))
        return page_of(rrsets, {"node_id": node_id})


@ns.route("/zones/<string:zone>/records/plan")
class RecordsPlan(Resource):
    @require("write:dns.records")
    @ns.expect(m.ChangesBody)
    @ns.response(200, "Plan of one atomic UPDATE (targets <owner>/<type> or <zone>/<owner>/<type>)", m.Plan)
    @ns.response(422, "engine_validation_failed", m.Problem)
    def post(self, zone: str):
        body = json_body()
        return plan_answer(dns().plan_records(zone, _changes(body), body.get("view"), username()))


def _operation(op: str, zone: str):
    body = json_body(required=False)
    output = dns().operation(op, zone, body.get("node_id"), body.get("view"), username(), client_ip())
    return {"output": output, "node_id": body.get("node_id") or services().ctx.node.id}


@ns.route("/zones/<string:zone>/retransfer")
class Retransfer(Resource):
    @require("ops:dns")
    @ns.expect(m.ZoneOp)
    @ns.response(200, "rndc retransfer output (audited)", m.OpOutput)
    def post(self, zone: str):
        return _operation("retransfer", zone)


@ns.route("/zones/<string:zone>/notify")
class Notify(Resource):
    @require("ops:dns")
    @ns.expect(m.ZoneOp)
    @ns.response(200, "rndc notify output (audited)", m.OpOutput)
    def post(self, zone: str):
        return _operation("notify", zone)


@ns.route("/zones/<string:zone>/reload")
class Reload(Resource):
    @require("ops:dns")
    @ns.expect(m.ZoneOp)
    @ns.response(200, "rndc reload output (audited)", m.OpOutput)
    def post(self, zone: str):
        return _operation("reload", zone)


@ns.route("/zones/<string:zone>/dnssec")
class Dnssec(Resource):
    @require("read:dns")
    @ns.doc(params={**VIEW, **NODE})
    @ns.response(200, "rndc dnssec -status, parsed", m.Dnssec)
    def get(self, zone: str):
        return dns().dnssec(zone, arg("view"), arg("node_id"))


@ns.route("/config")
class Config(Resource):
    @require("read:dns")
    @ns.doc(params=NODE)
    @ns.response(200, "Resolved named.conf with provenance; key material masked", m.BindConfigTree)
    def get(self):
        return dns().config(arg("node_id"))


@ns.route("/config/plan")
class ConfigPlan(Resource):
    @require("write:dns.config")
    @ns.expect(m.ChangesBody)
    @ns.response(200, "Plan over the Pelagos include files", m.Plan)
    @ns.response(422, "engine_validation_failed", m.Problem)
    def post(self):
        body = json_body()
        return plan_answer(dns().plan_config(_changes(body), body.get("node_ids"), username()))


@ns.route("/keys")
class Keys(Resource):
    @require("read:dns")
    @ns.response(200, "TSIG keys (never the secret) and the zones that use them", m.KeyList)
    def get(self):
        return {"items": dns().keys(arg("node_id"))}


@ns.route("/keys/plan")
class KeysPlan(Resource):
    @require("write:dns.config")
    @ns.expect(m.ChangeBody)
    @ns.response(200, "Plan; a missing secret is generated and never shown", m.Plan)
    @ns.response(400, "validation_error: weak algorithm", m.Problem)
    def post(self):
        return plan_answer(dns().plan_key(_change(json_body()), username()))


@ns.route("/keys/<string:name>/secret")
class KeySecret(Resource):
    @require("read:dns.secrets")
    @ns.response(200, "The key material (audited dns.key.reveal)", m.KeySecret)
    def get(self, name: str):
        return dns().key_secret(name, username(), client_ip())


@ns.route("/acls")
class Acls(Resource):
    @require("read:dns")
    @ns.response(200, "ACL statements", m.AclList)
    def get(self):
        return {"items": dns().acls(arg("node_id"))}


@ns.route("/acls/plan")
class AclsPlan(Resource):
    @require("write:dns.config")
    @ns.expect(m.ChangeBody)
    @ns.response(200, "Plan over acls.conf", m.Plan)
    def post(self):
        return plan_answer(dns().plan_acl(_change(json_body()), username()))


@ns.route("/resolver")
class Resolver(Resource):
    @require("read:dns")
    @ns.response(200, "Recursion and forwarding options, per node", m.Resolver)
    def get(self):
        return dns().resolver()


@ns.route("/resolver/plan")
class ResolverPlan(Resource):
    @require("write:dns.config")
    @ns.expect(m.ResolverBody)
    @ns.response(200, "Plan over options.conf; null removes a statement", m.Plan)
    def post(self):
        return plan_answer(dns().plan_resolver(json_body(), username()))


@ns.route("/rpz")
class Rpz(Resource):
    @require("read:dns")
    @ns.response(200, "Response policy zones", m.RawList)
    def get(self):
        return items(dns().rpz(arg("node_id")))


@ns.route("/catalog-zones")
class CatalogZones(Resource):
    @require("read:dns")
    @ns.response(200, "Catalog zones and their members", m.RawList)
    def get(self):
        return items(dns().catalog_zones(arg("node_id")))


@ns.route("/stats")
class Stats(Resource):
    @require("read:dns")
    @ns.doc(params=NODE)
    @ns.response(200, "statistics-channel counters", m.BindInstanceStats)
    def get(self):
        return dns().stats(arg("node_id"))
