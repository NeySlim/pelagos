# SPDX-License-Identifier: Apache-2.0
"""Advanced configuration: grammar, statement tree, Kea schema, write history."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api.errors import not_implemented
from pelagos.api.security import require

ns = Namespace("advanced", description="Grammar-driven editor support", path="/advanced")
OWNER = "WP-API-AUTH"


@ns.route("/bind/grammar")
class BindGrammar(Resource):
    @require("read:advanced")
    def get(self):
        raise not_implemented("WP-BIND")


@ns.route("/bind/tree")
class BindTree(Resource):
    @require("read:advanced")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/kea/<string:family>/schema")
class KeaSchema(Resource):
    @require("read:advanced")
    def get(self, family: str):
        raise not_implemented("WP-KEA")


@ns.route("/history")
class History(Resource):
    @require("read:advanced")
    def get(self):
        raise not_implemented(OWNER)


@ns.route("/history/<string:history_id>")
class HistoryEntry(Resource):
    @require("read:advanced")
    def get(self, history_id: str):
        raise not_implemented(OWNER)
