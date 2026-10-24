# SPDX-License-Identifier: Apache-2.0
"""DHCP endpoints (section 17, DHCP table). `family` is v4 or v6; v6 needs the dhcpv6 module."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api.errors import ApiError, not_implemented
from pelagos.api.security import require, require_module

ns = Namespace("dhcp", description="Kea subnets, reservations, leases, HA, D2", path="/dhcp")
OWNER = "WP-API-AUTH"


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


def _stub_get(permission: str):
    class _Res(FamilyResource):
        @require(permission)
        def get(self, **kwargs):
            raise not_implemented(OWNER)

    return _Res


def _stub_post(permission: str):
    class _Res(FamilyResource):
        @require(permission)
        def post(self, **kwargs):
            raise not_implemented(OWNER)

    return _Res


GET_ROUTES = {
    "/<string:family>/servers": "read:dhcp",
    "/<string:family>/subnets": "read:dhcp",
    "/<string:family>/subnets/<int:subnet_id>": "read:dhcp",
    "/<string:family>/shared-networks": "read:dhcp",
    "/<string:family>/client-classes": "read:dhcp",
    "/<string:family>/options": "read:dhcp",
    "/<string:family>/reservations": "read:dhcp",
    "/<string:family>/leases": "read:dhcp",
    "/<string:family>/leases/<string:ip>": "read:dhcp",
    "/<string:family>/utilization": "read:dhcp",
    "/<string:family>/stats": "read:dhcp",
    "/<string:family>/ha": "read:dhcp",
    "/<string:family>/ha/transitions": "read:dhcp",
    "/<string:family>/ddns": "read:dhcp",
    "/<string:family>/hooks": "read:dhcp",
    "/<string:family>/config": "read:dhcp",
    "/d2/servers": "read:dhcp",
    "/d2/stats": "read:dhcp",
    "/d2/config": "read:dhcp",
}

POST_ROUTES = {
    "/<string:family>/subnets/plan": "write:dhcp.subnets",
    "/<string:family>/shared-networks/plan": "write:dhcp.subnets",
    "/<string:family>/client-classes/plan": "write:dhcp.classes",
    "/<string:family>/options/plan": "write:dhcp.options",
    "/<string:family>/reservations/plan": "write:dhcp.reservations",
    "/<string:family>/leases/<string:ip>/delete/plan": "ops:dhcp.leases",
    "/<string:family>/ha/maintenance/plan": "ops:dhcp.ha",
    "/<string:family>/service/plan": "ops:dhcp.ha",
    "/<string:family>/ddns/plan": "write:dhcp.options",
    "/<string:family>/hooks/plan": "write:dhcp.config",
    "/<string:family>/config/plan": "write:dhcp.config",
    "/d2/config/plan": "write:dhcp.config",
}

# Flask-RESTX needs a distinct class per route; build them from the tables above.
for _i, (_route, _perm) in enumerate(GET_ROUTES.items()):
    _cls = _stub_get(_perm)
    _cls.__name__ = f"DhcpGet{_i}"
    ns.route(_route)(_cls)
for _i, (_route, _perm) in enumerate(POST_ROUTES.items()):
    _cls = _stub_post(_perm)
    _cls.__name__ = f"DhcpPost{_i}"
    ns.route(_route)(_cls)
