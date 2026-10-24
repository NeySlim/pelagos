# SPDX-License-Identifier: Apache-2.0
"""DNS endpoints (section 17, DNS table). Bodies are WP-API-AUTH work over the BIND connector."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api.errors import not_implemented
from pelagos.api.security import require

ns = Namespace("dns", description="Zones, records, BIND configuration", path="/dns")
OWNER = "WP-API-AUTH"


@ns.route("/instances")
class Instances(Resource):
    @require("read:dns")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/zones")
class Zones(Resource):
    @require("read:dns")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/zones/plan")
class ZonesPlan(Resource):
    @require("write:dns.zones")
    def post(self):
        raise not_implemented(OWNER)


@ns.route("/zones/<string:zone>")
class OneZone(Resource):
    @require("read:dns")
    def get(self, zone: str):
        raise not_implemented(OWNER)


@ns.route("/zones/<string:zone>/records")
class Records(Resource):
    @require("read:dns")
    def get(self, zone: str):
        raise not_implemented(OWNER)


@ns.route("/zones/<string:zone>/records/plan")
class RecordsPlan(Resource):
    @require("write:dns.records")
    def post(self, zone: str):
        raise not_implemented(OWNER)


@ns.route("/zones/<string:zone>/retransfer")
class Retransfer(Resource):
    @require("ops:dns")
    def post(self, zone: str):
        raise not_implemented(OWNER)


@ns.route("/zones/<string:zone>/notify")
class Notify(Resource):
    @require("ops:dns")
    def post(self, zone: str):
        raise not_implemented(OWNER)


@ns.route("/zones/<string:zone>/reload")
class Reload(Resource):
    @require("ops:dns")
    def post(self, zone: str):
        raise not_implemented(OWNER)


@ns.route("/zones/<string:zone>/dnssec")
class Dnssec(Resource):
    @require("read:dns")
    def get(self, zone: str):
        raise not_implemented(OWNER)


@ns.route("/config")
class Config(Resource):
    @require("read:dns")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/config/plan")
class ConfigPlan(Resource):
    @require("write:dns.config")
    def post(self):
        raise not_implemented(OWNER)


@ns.route("/keys")
class Keys(Resource):
    @require("read:dns")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/keys/plan")
class KeysPlan(Resource):
    @require("write:dns.config")
    def post(self):
        raise not_implemented(OWNER)


@ns.route("/keys/<string:name>/secret")
class KeySecret(Resource):
    @require("read:dns.secrets")
    def get(self, name: str):
        raise not_implemented(OWNER)


@ns.route("/acls")
class Acls(Resource):
    @require("read:dns")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/acls/plan")
class AclsPlan(Resource):
    @require("write:dns.config")
    def post(self):
        raise not_implemented(OWNER)


@ns.route("/resolver")
class Resolver(Resource):
    @require("read:dns")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/resolver/plan")
class ResolverPlan(Resource):
    @require("write:dns.config")
    def post(self):
        raise not_implemented(OWNER)


@ns.route("/rpz")
class Rpz(Resource):
    @require("read:dns")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/catalog-zones")
class CatalogZones(Resource):
    @require("read:dns")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/stats")
class Stats(Resource):
    @require("read:dns")
    def get(self):
        raise not_implemented(OWNER)
