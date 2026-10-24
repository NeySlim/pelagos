# SPDX-License-Identifier: Apache-2.0
"""Advanced configuration: grammar, statement tree, Kea schema, write history.

The whole namespace answers 404 module_disabled when modules.advanced_editor is false.
"""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, page_of
from pelagos.api.dhcp import check_family
from pelagos.api.security import require, require_module, services

ns = Namespace("advanced", description="Grammar-driven editor support", path="/advanced")


class AdvancedResource(Resource):
    def dispatch_request(self, *args, **kwargs):
        require_module("advanced_editor")
        if "family" in kwargs:
            check_family(kwargs["family"])
        return super().dispatch_request(*args, **kwargs)


@ns.route("/bind/grammar")
class BindGrammar(AdvancedResource):
    @require("read:advanced")
    @ns.response(200, "BIND 9.20 statement grammar (section 8)")
    @ns.response(501, "not_implemented until WP-BIND lands", m.Problem)
    def get(self):
        return services().advanced.bind_grammar()


@ns.route("/bind/tree")
class BindTree(AdvancedResource):
    @require("read:advanced")
    @ns.doc(params={"node_id": "node to read"})
    @ns.response(200, "Statements grouped by file, with provenance", m.BindTree)
    def get(self):
        return services().advanced.bind_tree(arg("node_id"))


@ns.route("/kea/<string:family>/schema")
class KeaSchema(AdvancedResource):
    @require("read:advanced")
    @ns.response(200, "Description of the Dhcp4/Dhcp6 object for the server version")
    @ns.response(501, "not_implemented until WP-KEA lands", m.Problem)
    def get(self, family: str):
        s = services()
        return s.advanced.kea_schema(family, s.dhcp4 if family == "v4" else s.dhcp6)


@ns.route("/history")
class History(AdvancedResource):
    @require("read:advanced")
    @ns.doc(
        params={
            "engine": "bind, kea4, kea6, d2",
            "node_id": "this node only",
            "page": "1-based",
            "per_page": "default 50, max 500",
        }
    )
    @ns.response(200, "Write pipeline backups of this node, newest first", m.HistoryPage)
    def get(self):
        return page_of(services().advanced.history(arg("engine"), arg("node_id")))


@ns.route("/history/<path:history_id>")
class HistoryEntry(AdvancedResource):
    @require("read:advanced")
    @ns.response(200, "Backup manifest and file contents", m.HistoryDetail)
    @ns.response(404, "not_found", m.Problem)
    def get(self, history_id: str):
        return services().advanced.history_entry(history_id)
