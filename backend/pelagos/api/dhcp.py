# SPDX-License-Identifier: Apache-2.0
"""DHCP endpoints (section 17, DHCP table). `family` is v4 or v6; v6 needs the dhcpv6 module."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, int_arg, items, json_body, page_of, paged, plan_answer, time_range
from pelagos.api.errors import ApiError
from pelagos.api.security import require, require_module, services, username
from pelagos.domain import Family

ns = Namespace("dhcp", description="Kea subnets, reservations, leases, HA, D2", path="/dhcp")

NODE = {"node_id": "node to read (default: this node, else the first node running the engine)"}
PAGE = {"page": "1-based", "per_page": "default 50, max 500"}


def check_family(family: str) -> None:
    if family not in ("v4", "v6"):
        raise ApiError("not_found", f"unknown family {family}")
    if family == "v6":
        require_module("dhcpv6")


class FamilyResource(Resource):
    """Resources under /dhcp/<family>/ validate the family before anything else."""

    def dispatch_request(self, *args, **kwargs):
        if "family" in kwargs:
            check_family(kwargs["family"])
        return super().dispatch_request(*args, **kwargs)


def dhcp(family: str):
    return services().dhcp(Family(family))


def _plan(family: str, kind: str, body: dict | None = None):
    return plan_answer(dhcp(family).plan(kind, json_body() if body is None else body, username()))


@ns.route("/<string:family>/servers")
class Servers(FamilyResource):
    @require("read:dhcp")
    @ns.response(200, "Kea on every node: capabilities, status-get, HA, config hash", m.Instances)
    def get(self, family: str):
        return {"items": dhcp(family).servers()}


@ns.route("/<string:family>/subnets")
class Subnets(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params={**NODE, "shared_network": "name", "q": "prefix, id, notes or network substring"})
    @ns.response(200, "Subnets with utilization by subnet id", m.SubnetList)
    def get(self, family: str):
        subnets, util, node_id = dhcp(family).subnets(arg("shared_network"), arg("q"), arg("node_id"))
        return {
            "items": [s.to_dict() for s in subnets],
            "utilization": {str(k): v for k, v in util.items()},
            "node_id": node_id,
        }


@ns.route("/<string:family>/subnets/<int:subnet_id>")
class OneSubnet(FamilyResource):
    @require("read:dhcp")
    @ns.response(200, "One subnet", m.Subnet)
    @ns.response(404, "not_found", m.Problem)
    def get(self, family: str, subnet_id: int):
        return dhcp(family).subnet(subnet_id, arg("node_id")).to_dict()


@ns.route("/<string:family>/subnets/plan")
class SubnetsPlan(FamilyResource):
    @require("write:dhcp.subnets")
    @ns.expect(m.SubnetChangeBody)
    @ns.response(400, "validation_error: malformed target or object", m.Problem)
    @ns.response(200, "Plan applied on every node running the engine", m.Plan)
    @ns.response(422, "engine_validation_failed", m.Problem)
    def post(self, family: str):
        return _plan(family, "subnet")


@ns.route("/<string:family>/shared-networks")
class SharedNetworks(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params=NODE)
    @ns.response(200, "Shared networks", m.SharedNetworkList)
    def get(self, family: str):
        return items(dhcp(family).shared_networks(arg("node_id")))


@ns.route("/<string:family>/shared-networks/plan")
class SharedNetworksPlan(FamilyResource):
    @require("write:dhcp.subnets")
    @ns.expect(m.SharedNetworkChangeBody)
    @ns.response(400, "validation_error: malformed target or object", m.Problem)
    @ns.response(200, "Plan", m.Plan)
    def post(self, family: str):
        return _plan(family, "shared_network")


@ns.route("/<string:family>/client-classes")
class ClientClasses(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params=NODE)
    @ns.response(200, "Client classes", m.ClientClassList)
    def get(self, family: str):
        return items(dhcp(family).client_classes(arg("node_id")))


@ns.route("/<string:family>/client-classes/plan")
class ClientClassesPlan(FamilyResource):
    @require("write:dhcp.classes")
    @ns.expect(m.ClientClassChangeBody)
    @ns.response(400, "validation_error: malformed target or object", m.Problem)
    @ns.response(200, "Plan", m.Plan)
    def post(self, family: str):
        return _plan(family, "class")


@ns.route("/<string:family>/options")
class Options(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params=NODE)
    @ns.response(200, "Global option-data and option definitions", m.OptionList)
    def get(self, family: str):
        options, defs = dhcp(family).options(arg("node_id"))
        return items(options, option_defs=defs)


@ns.route("/<string:family>/options/plan")
class OptionsPlan(FamilyResource):
    @require("write:dhcp.options")
    @ns.expect(m.OptionChangesBody)
    @ns.response(400, "validation_error: malformed target or object", m.Problem)
    @ns.response(200, "Plan (config-test, config-set, config-write)", m.Plan)
    def post(self, family: str):
        return _plan(family, "options")


@ns.route("/<string:family>/reservations")
class Reservations(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params={**NODE, **PAGE, "subnet_id": "subnet id", "q": "identifier, address or hostname"})
    @ns.response(200, "Reservations", m.ReservationPage)
    def get(self, family: str):
        return page_of(dhcp(family).reservations(int_arg("subnet_id"), arg("q"), arg("node_id")))


@ns.route("/<string:family>/reservations/plan")
class ReservationsPlan(FamilyResource):
    @require("write:dhcp.reservations")
    @ns.expect(m.ReservationChangeBody)
    @ns.response(400, "validation_error: malformed target or object", m.Problem)
    @ns.response(200, "Plan", m.Plan)
    def post(self, family: str):
        return _plan(family, "reservation")


@ns.route("/<string:family>/leases")
class Leases(FamilyResource):
    @require("read:dhcp")
    @ns.doc(
        params={
            **NODE,
            "from_address": "cursor: meta.next of the previous page (default: the first lease)",
            "limit": "leases per page, default 100, max 1000",
            "subnet_id": "subnet id",
            "q": "IP address, MAC address, DUID or exact hostname (Kea lookups, no paging)",
            "state": "default, declined, expired-reclaimed, released, registered",
        }
    )
    @ns.response(200, "Leases; meta.node_id is the node read, meta.next the next cursor", m.LeasePage)
    def get(self, family: str):
        limit = int_arg("limit")
        limit = 100 if limit is None else limit
        if limit < 1 or limit > 1000:
            raise ApiError("validation_error", "limit must be between 1 and 1000")
        rows, node_id, cursor = dhcp(family).lease_page(
            int_arg("subnet_id"), arg("q"), arg("state"), arg("node_id"), arg("from_address"), limit
        )
        return paged(rows, 1, limit, len(rows), {"node_id": node_id, "next": cursor, "limit": limit})


@ns.route("/<string:family>/leases/recent")
class RecentLeases(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params={"limit": "leases, default 20, max 50"})
    @ns.response(
        200,
        "Latest client transactions by cltt across the nodes (collector lease watch); as_of: oldest walk",
    )
    def get(self, family: str):
        limit = int_arg("limit")
        limit = 20 if limit is None else limit
        if limit < 1 or limit > 50:
            raise ApiError("validation_error", "limit must be between 1 and 50")
        return dhcp(family).recent_leases(limit)


@ns.route("/<string:family>/leases/<string:ip>")
class OneLease(FamilyResource):
    @require("read:dhcp")
    @ns.response(200, "The lease as each node sees it (HA agreement)", m.LeaseList)
    @ns.response(404, "not_found", m.Problem)
    def get(self, family: str, ip: str):
        return items(dhcp(family).lease_everywhere(ip))


@ns.route("/<string:family>/leases/<string:ip>/delete/plan")
class LeaseDeletePlan(FamilyResource):
    @require("ops:dhcp.leases")
    @ns.response(200, "Plan (requires_confirmation)", m.Plan)
    def post(self, family: str, ip: str):
        body = json_body(required=False)
        return _plan(family, "lease_delete", {**body, "ip": ip})


@ns.route("/<string:family>/utilization")
class UtilizationRes(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params=NODE)
    @ns.response(200, "Pool utilization", m.Utilization)
    def get(self, family: str):
        return {"items": dhcp(family).utilization(arg("node_id"))}


@ns.route("/<string:family>/stats")
class Stats(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params=NODE)
    @ns.response(200, "statistic-get-all", m.DhcpStats)
    def get(self, family: str):
        return dhcp(family).statistics(arg("node_id"))


@ns.route("/<string:family>/ha")
class Ha(FamilyResource):
    @require("read:dhcp")
    @ns.response(200, "HA state on every node, and the relationships they form", m.HAList)
    def get(self, family: str):
        service = dhcp(family)
        states = service.ha()
        return {**items(states), "relationships": service.relationships(states)}


@ns.route("/<string:family>/ha/setup/plan")
class HaSetupPlan(FamilyResource):
    @require("write:dhcp.config")
    @ns.expect(m.HASetupBody)
    @ns.response(200, "Plan with one part per node of the relationship (requires_confirmation)", m.Plan)
    @ns.response(400, "validation_failed: roles, names or urls", m.Problem)
    def post(self, family: str):
        return plan_answer(dhcp(family).plan_ha_setup(json_body(), username()))


@ns.route("/<string:family>/ha/maintenance/plan")
class HaMaintenancePlan(FamilyResource):
    @require("ops:dhcp.ha")
    @ns.expect(m.MaintenanceBody)
    @ns.response(200, "Plan (requires_confirmation)", m.Plan)
    def post(self, family: str):
        return _plan(family, "ha_maintenance")


@ns.route("/<string:family>/ha/repair/plan")
class HaRepairPlan(FamilyResource):
    @require("ops:dhcp.ha")
    @ns.expect(m.RepairBody)
    @ns.response(200, "Plan resetting each terminated server in turn (requires_confirmation)", m.Plan)
    @ns.response(409, "conflict: no server is terminated", m.Problem)
    def post(self, family: str):
        return _plan(family, "ha_repair", json_body(required=False))


@ns.route("/<string:family>/ha/transitions")
class HaTransitions(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params={"from": "RFC 3339 or Unix seconds (default 24 h ago)", "to": "default now", **NODE})
    @ns.response(200, "HA state changes from the series cache", m.RawList)
    def get(self, family: str):
        since, until = time_range()
        rows = services().series.ha_transitions(
            engine=Family(family).kea_engine.value, node_id=arg("node_id"), since=since, until=until
        )
        return rows


@ns.route("/<string:family>/service/plan")
class ServicePlan(FamilyResource):
    @require("ops:dhcp.ha")
    @ns.expect(m.ServiceBody)
    @ns.response(200, "Plan for dhcp-enable / dhcp-disable (requires_confirmation)", m.Plan)
    def post(self, family: str):
        return _plan(family, "service")


@ns.route("/<string:family>/ddns")
class Ddns(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params=NODE)
    @ns.response(200, "dhcp-ddns and ddns-* parameters", m.Ddns)
    def get(self, family: str):
        return dhcp(family).ddns(arg("node_id"))


@ns.route("/<string:family>/ddns/plan")
class DdnsPlan(FamilyResource):
    @require("write:dhcp.options")
    @ns.expect(m.ChangesBody)
    @ns.response(200, "Plan over ddns-* keys and dhcp-ddns", m.Plan)
    def post(self, family: str):
        return _plan(family, "ddns")


@ns.route("/<string:family>/hooks")
class Hooks(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params=NODE)
    @ns.response(200, "Loaded hook libraries and the known ones", m.Hooks)
    def get(self, family: str):
        return dhcp(family).hooks(arg("node_id"))


@ns.route("/<string:family>/hooks/plan")
class HooksPlan(FamilyResource):
    @require("write:dhcp.config")
    @ns.expect(m.ChangesBody)
    @ns.response(200, "Plan over hooks-libraries", m.Plan)
    def post(self, family: str):
        return _plan(family, "hooks")


@ns.route("/<string:family>/config")
class Config(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params=NODE)
    @ns.response(200, "config-get and config-hash-get", m.DhcpConfig)
    def get(self, family: str):
        return dhcp(family).config(arg("node_id"))


@ns.route("/<string:family>/config/plan")
class ConfigPlan(FamilyResource):
    @require("write:dhcp.config")
    @ns.expect(m.ConfigBody)
    @ns.response(200, "Plan replacing the whole Dhcp4/Dhcp6 object", m.Plan)
    def post(self, family: str):
        return _plan(family, "config")


@ns.route("/<string:family>/config/file")
class ConfigFile(FamilyResource):
    @require("read:dhcp")
    @ns.response(200, "Per node: does the configuration file agree with config-get (section 9)", m.RawList)
    def get(self, family: str):
        return {"items": dhcp(family).file_status()}


@ns.route("/<string:family>/config/adopt/plan")
class ConfigAdoptPlan(FamilyResource):
    @require("write:dhcp.config")
    @ns.expect(m.AdoptBody)
    @ns.response(200, "Plan: adopt the file (config-set) or the running configuration (file rewrite)", m.Plan)
    def post(self, family: str):
        return plan_answer(dhcp(family).plan_adopt(json_body(), username()))


@ns.route("/d2/config/file")
class D2ConfigFile(Resource):
    @require("read:dhcp")
    @ns.response(200, "Per node: does the D2 configuration file agree with config-get", m.RawList)
    def get(self):
        return {"items": services().dhcp4.d2_file_status()}


@ns.route("/d2/config/adopt/plan")
class D2ConfigAdoptPlan(Resource):
    @require("write:dhcp.config")
    @ns.expect(m.AdoptBody)
    @ns.response(200, "Plan: adopt the D2 file or the running D2 configuration", m.Plan)
    def post(self):
        return plan_answer(services().dhcp4.plan_d2_adopt(json_body(), username()))


@ns.route("/d2/servers")
class D2Servers(Resource):
    @require("read:dhcp")
    @ns.response(200, "kea-dhcp-ddns on every node", m.Instances)
    def get(self):
        return {"items": services().dhcp4.d2_servers()}


@ns.route("/d2/stats")
class D2StatsRes(Resource):
    @require("read:dhcp")
    @ns.doc(params=NODE)
    @ns.response(200, "D2 counters, per key", m.D2Stats)
    def get(self):
        return services().dhcp4.d2_stats(arg("node_id")).to_dict()


@ns.route("/d2/config")
class D2ConfigRes(Resource):
    @require("read:dhcp")
    @ns.doc(params=NODE)
    @ns.response(200, "DhcpDdns object, TSIG secrets masked", m.D2Config)
    def get(self):
        return services().dhcp4.d2_config(arg("node_id"))


@ns.route("/d2/config/plan")
class D2ConfigPlan(Resource):
    @require("write:dhcp.config")
    @ns.expect(m.ConfigBody)
    @ns.response(200, "Plan replacing the DhcpDdns object", m.Plan)
    def post(self):
        return plan_answer(services().dhcp4.plan_d2_config(json_body(), username()))
