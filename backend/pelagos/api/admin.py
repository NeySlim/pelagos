# SPDX-License-Identifier: Apache-2.0
"""Administration: users, roles, permissions, settings, modules."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api.errors import not_implemented
from pelagos.api.security import ctx, require
from pelagos.auth.rbac import BUILTIN_ROLES, PERMISSIONS

ns = Namespace("admin", description="Users, roles, settings, modules", path="/admin")
OWNER = "WP-API-AUTH"


@ns.route("/users")
class Users(Resource):
    @require("admin:users")
    def get(self):
        return {"items": [u.public() for u in ctx().cluster().users]}

    @require("admin:users")
    def post(self):
        raise not_implemented(OWNER)


@ns.route("/users/<string:user_id>")
class OneUser(Resource):
    @require("admin:users")
    def get(self, user_id: str):
        raise not_implemented(OWNER)

    @require("admin:users")
    def put(self, user_id: str):
        raise not_implemented(OWNER)

    @require("admin:users")
    def delete(self, user_id: str):
        raise not_implemented(OWNER)


@ns.route("/users/<string:user_id>/reset-password")
class ResetPassword(Resource):
    @require("admin:users")
    def post(self, user_id: str):
        raise not_implemented(OWNER)


@ns.route("/users/<string:user_id>/totp")
class UserTotp(Resource):
    @require("admin:users")
    def delete(self, user_id: str):
        raise not_implemented(OWNER)


@ns.route("/roles")
class Roles(Resource):
    @require("admin:roles")
    def get(self):
        builtin = [r.to_dict() for r in BUILTIN_ROLES.values()]
        custom = [r.to_dict() for r in ctx().cluster().roles]
        return {"items": builtin + custom}

    @require("admin:roles")
    def post(self):
        raise not_implemented(OWNER)


@ns.route("/roles/<string:name>")
class OneRole(Resource):
    @require("admin:roles")
    def put(self, name: str):
        raise not_implemented(OWNER)

    @require("admin:roles")
    def delete(self, name: str):
        raise not_implemented(OWNER)


@ns.route("/permissions")
class Permissions(Resource):
    @require("admin:roles")
    def get(self):
        return {"items": list(PERMISSIONS)}


@ns.route("/settings")
class Settings(Resource):
    @require("admin:settings")
    def get(self):
        return ctx().cluster().settings

    @require("admin:settings")
    def put(self):
        raise not_implemented(OWNER)


@ns.route("/modules")
class Modules(Resource):
    @require("admin:modules")
    def get(self):
        cluster = ctx().cluster()
        return {"cluster": cluster.modules, "nodes": {n.id: n.modules.to_dict() for n in cluster.nodes}}

    @require("admin:modules")
    def put(self):
        raise not_implemented(OWNER)
