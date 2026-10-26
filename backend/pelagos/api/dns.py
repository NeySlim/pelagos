# SPDX-License-Identifier: Apache-2.0
"""DNS endpoints (section 17, DNS table) over the DNS service.

`{zone}` in paths is the zone name with or without the trailing dot; answers
use the absolute lowercase form.
"""

from __future__ import annotations

from flask_restx import Namespace, Resource, fields

from pelagos.api import models as m
from pelagos.api.common import arg, items, json_body, page_of, plan_answer, plan_dict
from pelagos.api.errors import ApiError
from pelagos.api.security import client_ip, require, services, username
from pelagos.services.dns_extras import zone_mode

ns = Namespace("dns", description="Zones, records, BIND configuration", path="/dns")

NODE = {"node_id": "node to read (default: this node, else the first node running BIND)"}
VIEW = {"view": "BIND view (default: every view, or _default for one zone)"}

CatalogMemberBody = ns.model(
    "CatalogMemberBody",
    {
        "op": fields.String(required=True, enum=["add", "delete"]),
        "member": fields.String(required=True, description="member zone name"),
        "group": fields.String(description="catalog group property (add only)"),
        "view": fields.String,
    },
)
DnssecOpBody = ns.model(
    "DnssecOpBody",
    {
        "action": fields.String(required=True, enum=["rollover", "checkds"]),
        "key_id": fields.Integer(description="key tag (required for rollover)"),
        "when": fields.String(description="now or YYYYMMDDHHMMSS"),
        "state": fields.String(enum=["published", "withdrawn"], description="checkds only"),
        "view": fields.String,
        "node_id": fields.String(description="node that runs the command (default: this node)"),
    },
)


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
        body = json_body()
        node_ids = body.get("node_ids")
        if node_ids is not None and not isinstance(node_ids, list):
            raise ApiError(
                "validation_error",
                "node_ids must be a list",
                errors=[{"field": "node_ids", "message": "list"}],
            )
        node_id = body.get("node_id")
        if node_id is not None and not isinstance(node_id, str):
            raise ApiError(
                "validation_error",
                "node_id must be a string",
                errors=[{"field": "node_id", "message": "string"}],
            )
        return plan_answer(dns().plan_zone(_change(body), username(), node_ids or None, node_id))


@ns.route("/zones/<string:zone>")
class OneZone(Resource):
    @require("read:dns")
    @ns.doc(params=VIEW)
    @ns.response(200, "Zone and its status on each node", m.ZoneDetail)
    @ns.response(404, "not_found", m.Problem)
    def get(self, zone: str):
        z, statuses = dns().zone(zone, arg("view"))
        copies = dns().zone_copies(z.name, z.view)
        return {
            "zone": z.to_dict(),
            "status": {k: v.to_dict() for k, v in statuses.items()},
            "mode": zone_mode(z),
            "views": dns().zone_views(z.name),
            "copies": copies,
        }


@ns.route("/zones/<string:zone>/secondaries/plan")
class ZoneSecondariesPlan(Resource):
    @require("write:dns.zones")
    @ns.expect(m.SecondariesBody)
    @ns.response(
        200, "Plan: one part on the primary (also-notify) and one per secondary added or dropped", m.Plan
    )
    @ns.response(409, "conflict: the zone already has exactly these secondaries", m.Problem)
    def post(self, zone: str):
        body = json_body()
        return plan_answer(
            dns().plan_secondaries(
                zone,
                body.get("view"),
                body.get("node_ids"),
                username(),
                body.get("primaries"),
                body.get("also_notify"),
            )
        )


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


@ns.route("/handover")
class Handover(Resource):
    @require("read:dns")
    @ns.response(200, "Statements set in user files that can be handed over, with their nodes", m.RawList)
    def get(self):
        return dns().handover()


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


def rpz():
    return services().rpz


def rpz_result(result: dict) -> dict:
    """Plan and overview of a subscription change; a plan the engine refused is shown, not raised."""
    plan = result.get("plan")
    return {**result, "plan": plan_dict(plan) if plan is not None else None}


@ns.route("/rpz/overview")
class RpzOverviewRoute(Resource):
    @require("read:dns")
    @ns.response(200, "Catalog, selections, subscriptions with status per node, allow list", m.RpzOverview)
    def get(self):
        return rpz().overview()


@ns.route("/rpz/catalog")
class RpzCatalogRoute(Resource):
    @require("read:dns")
    @ns.response(200, "Built-in catalog: lists, categories with their levels", m.RpzData)
    def get(self):
        return rpz().catalog()


@ns.route("/rpz/categories/<string:category>")
class RpzCategory(Resource):
    @require("write:dns.config")
    @ns.expect(m.RpzBody)
    @ns.response(200, "Selection saved; plan to apply on the nodes (null when nothing differs)", m.RpzResult)
    @ns.response(400, "validation_error", m.Problem)
    def put(self, category: str):
        return rpz_result(rpz().set_category(category, json_body(), username(), client_ip()))

    @require("write:dns.config")
    @ns.response(200, "Category removed; plan to apply", m.RpzResult)
    def delete(self, category: str):
        return rpz_result(rpz().clear_category(category, username(), client_ip()))


@ns.route("/rpz/subscriptions/<string:sub_id>")
class RpzSubscription(Resource):
    @require("write:dns.config")
    @ns.expect(m.RpzBody)
    @ns.response(200, "Custom subscription (URL list or zone transfer) saved; plan to apply", m.RpzResult)
    @ns.response(400, "validation_error", m.Problem)
    def put(self, sub_id: str):
        return rpz_result(rpz().put_subscription(sub_id, json_body(), username(), client_ip()))

    @require("write:dns.config")
    @ns.response(200, "Subscription removed; plan to apply", m.RpzResult)
    @ns.response(404, "not_found", m.Problem)
    def delete(self, sub_id: str):
        return rpz_result(rpz().delete_subscription(sub_id, username(), client_ip()))


@ns.route("/rpz/order")
class RpzOrder(Resource):
    @require("write:dns.config")
    @ns.expect(m.RpzBody)
    @ns.response(200, "Order of the zones in response-policy saved; plan to apply", m.RpzResult)
    def put(self):
        return rpz_result(rpz().set_order(json_body().get("order"), username(), client_ip()))


@ns.route("/rpz/plan")
class RpzPlan(Resource):
    @require("write:dns.config")
    @ns.response(
        200,
        "Plan that brings every node to the saved subscriptions (plan null: nothing differs)",
        m.RpzResult,
    )
    def post(self):
        plan = rpz().plan(username())
        return rpz_result({"plan": plan, "overview": rpz().overview()})


@ns.route("/rpz/estimate")
class RpzEstimate(Resource):
    @require("read:dns")
    @ns.expect(m.RpzBody)
    @ns.response(
        200, "Memory estimate per node if the lists or the category level were subscribed", m.RpzData
    )
    def post(self):
        return rpz().estimate(json_body())


@ns.route("/rpz/refresh")
class RpzRefresh(Resource):
    @require("write:dns.config")
    @ns.expect(m.RpzBody)
    @ns.response(200, "This node's collector updates the lists now (body id: one list)", m.RpzData)
    def post(self):
        body = json_body(required=False)
        return rpz().refresh(body.get("id"), username(), client_ip(), bool(body.get("accept_shrink")))


@ns.route("/rpz/why")
class RpzWhy(Resource):
    @require("read:dns")
    @ns.doc(params={"domain": "name to look up", **NODE})
    @ns.response(
        200, "Rules that match the name, in response-policy order, with list and category", m.RpzData
    )
    def get(self):
        domain = arg("domain")
        if not domain:
            raise ApiError(
                "validation_error", "domain is required", errors=[{"field": "domain", "message": "required"}]
            )
        return rpz().why(domain, arg("node_id"))


@ns.route("/rpz/activity")
class RpzActivity(Resource):
    @require("read:dns")
    @ns.response(200, "Rewrite counters per list and category, latest rewritten answers", m.RpzData)
    def get(self):
        return rpz().activity()


@ns.route("/rpz/allow")
class RpzAllow(Resource):
    @require("write:dns.config")
    @ns.expect(m.RpzBody)
    @ns.response(200, "Domain allowed (passthru in the local zone)", m.RpzData)
    def post(self):
        body = json_body()
        return rpz().allow(body.get("domain"), body.get("note", ""), username(), client_ip())

    @require("write:dns.config")
    @ns.doc(params={"domain": "allowed domain to remove"})
    @ns.response(200, "Allow entry removed", m.RpzData)
    def delete(self):
        return rpz().disallow(arg("domain") or "", username(), client_ip())


@ns.route("/rpz/exempt")
class RpzExempt(Resource):
    @require("write:dns.config")
    @ns.expect(m.RpzBody)
    @ns.response(200, "Client address or network exempt from every list (rpz-client-ip passthru)", m.RpzData)
    def post(self):
        body = json_body()
        return rpz().exempt(body.get("cidr"), body.get("note", ""), username(), client_ip())

    @require("write:dns.config")
    @ns.doc(params={"cidr": "exempt client or network to remove"})
    @ns.response(200, "Exemption removed", m.RpzData)
    def delete(self):
        return rpz().unexempt(arg("cidr") or "", username(), client_ip())


@ns.route("/catalog-zones")
class CatalogZones(Resource):
    @require("read:dns")
    @ns.doc(params=NODE)
    @ns.response(200, "Consumed and produced catalog zones with their members, read now", m.RawList)
    def get(self):
        return items(dns().catalog_zones_live(arg("node_id")))


@ns.route("/catalog-zones/<string:zone>/members/plan")
class CatalogMembersPlan(Resource):
    @require("write:dns.records")
    @ns.expect(CatalogMemberBody)
    @ns.response(200, "Record plan on the producer catalog zone (PTR, and TXT for the group)", m.Plan)
    @ns.response(400, "validation_error: consumer catalog, unknown member", m.Problem)
    def post(self, zone: str):
        return plan_answer(dns().plan_catalog_member(zone, json_body(), username()))


@ns.route("/dnssec/policies")
class DnssecPolicies(Resource):
    @require("read:dns")
    @ns.response(200, "dnssec-policy statements with the zones using them; built-in policy names", m.RawList)
    def get(self):
        return dns().dnssec_policies()


@ns.route("/dnssec/policies/plan")
class DnssecPoliciesPlan(Resource):
    @require("write:dns.config")
    @ns.expect(m.ChangeBody)
    @ns.response(
        200, "Plan over policies.conf (target dnssec-policy/<name>, after {name, statements})", m.Plan
    )
    @ns.response(422, "engine_validation_failed", m.Problem)
    def post(self):
        return plan_answer(dns().plan_dnssec_policy(_change(json_body()), username()))


@ns.route("/zones/<string:zone>/dnssec/plan")
class DnssecOperationPlan(Resource):
    @require("write:dns.zones")
    @ns.expect(DnssecOpBody)
    @ns.response(200, "Plan of rndc dnssec -rollover or -checkds (confirmation required)", m.Plan)
    @ns.response(400, "validation_error", m.Problem)
    def post(self, zone: str):
        return plan_answer(dns().plan_dnssec_operation(zone, json_body(), username()))


@ns.route("/stats")
class Stats(Resource):
    @require("read:dns")
    @ns.doc(params=NODE)
    @ns.response(200, "statistics-channel counters", m.BindInstanceStats)
    def get(self):
        return dns().stats(arg("node_id"))
