# SPDX-License-Identifier: Apache-2.0
"""Global search across zones, records, leases, reservations, hosts, alerts and nodes (section 17)."""

from __future__ import annotations

from flask_restx import Namespace, Resource, fields

from pelagos.api import models as m
from pelagos.api.common import arg, int_arg
from pelagos.api.errors import ApiError
from pelagos.api.security import check_permission, services
from pelagos.auth.rbac import has_permission
from pelagos.services.search_service import DEFAULT_LIMIT, GROUPS, MAX_LIMIT, SEARCH_PERMISSIONS

KINDS = ["zone", "record", "lease", "reservation", "host", "alert", "node", "network"]
ns = Namespace("search", description="Search across DNS, DHCP and hosts", path="/search")

SearchResult = m.model(
    "SearchResult",
    {
        "kind": fields.String(required=True, enum=KINDS),
        "id": fields.String(required=True),
        "label": fields.String(required=True),
        "sublabel": fields.String,
        "route": fields.String(required=True, description="path of the UI page showing it"),
    },
)
SearchAnswer = m.model(
    "SearchAnswer",
    {
        "q": fields.String(required=True),
        "limit": fields.Integer(required=True),
        "results": fields.Nested(
            m.model("SearchGroups", {g: fields.List(fields.Nested(SearchResult)) for g in GROUPS}),
            required=True,
        ),
        "totals": fields.Raw(description="matches per group before the limit"),
        "errors": fields.Raw(description="sources that could not be read, as GET /hosts meta.errors"),
    },
)


@ns.route("")
class Search(Resource):
    @ns.doc(
        params={
            "q": "name or label (substring), address (prefix), MAC, DUID or client id (hex digits)",
            "limit": f"results per group, default {DEFAULT_LIMIT}, max {MAX_LIMIT}",
        }
    )
    @ns.response(200, "Results grouped by kind; a group the caller may not read is empty", SearchAnswer)
    @ns.response(403, "forbidden: needs read:hosts, read:dns or read:dhcp", m.Problem)
    def get(self):
        session = check_permission(None)
        perms = session.permissions
        if not any(has_permission(perms, p) for p in SEARCH_PERMISSIONS):
            raise ApiError("forbidden", "requires read:hosts, read:dns or read:dhcp")
        limit = int_arg("limit", 1) or DEFAULT_LIMIT
        return services().search.search(arg("q") or "", limit, lambda p: has_permission(perms, p))
