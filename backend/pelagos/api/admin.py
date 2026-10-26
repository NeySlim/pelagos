# SPDX-License-Identifier: Apache-2.0
"""Administration: users, roles, permissions, settings, modules (validated and audited)."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body
from pelagos.api.security import client_ip, require, services, username
from pelagos.auth.rbac import PERMISSIONS

ns = Namespace("admin", description="Users, roles, settings, modules", path="/admin")


def admin():
    return services().admin


def public(user) -> dict:
    """User public fields with this node's last login (auth.last_login)."""
    return services().last_login.overlay(user.public())


@ns.route("/users")
class Users(Resource):
    @require("admin:users")
    @ns.response(200, "Users (public fields only)", m.UserList)
    def get(self):
        return {"items": services().last_login.overlay_all([u.public() for u in admin().users()])}

    @require("admin:users")
    @ns.expect(m.UserCreate)
    @ns.response(201, "Created", m.UserPublic)
    @ns.response(400, "validation_error", m.Problem)
    @ns.response(409, "conflict: username taken", m.Problem)
    def post(self):
        return public(admin().create_user(json_body(), username(), client_ip())), 201


@ns.route("/users/<string:user_id>")
class OneUser(Resource):
    @require("admin:users")
    @ns.response(200, "One user", m.UserPublic)
    @ns.response(404, "not_found", m.Problem)
    def get(self, user_id: str):
        return public(admin().user(user_id))

    @require("admin:users")
    @ns.expect(m.UserUpdate)
    @ns.response(200, "Updated; the user's sessions are revoked when roles or enabled change", m.UserPublic)
    @ns.response(409, "conflict: last admin, or own account", m.Problem)
    def put(self, user_id: str):
        return public(admin().update_user(user_id, json_body(), username(), client_ip()))

    @require("admin:users")
    @ns.response(204, "Deleted")
    @ns.response(409, "conflict: last admin, or own account", m.Problem)
    def delete(self, user_id: str):
        admin().delete_user(user_id, username(), client_ip())
        services().last_login.forget(user_id)
        return "", 204


@ns.route("/users/<string:user_id>/reset-password")
class ResetPassword(Resource):
    @require("admin:users")
    @ns.expect(m.PasswordOnly)
    @ns.response(204, "Password set; the user must change it at next login")
    def post(self, user_id: str):
        admin().reset_password(user_id, json_body().get("password"), username(), client_ip())
        return "", 204


@ns.route("/users/<string:user_id>/totp")
class UserTotp(Resource):
    @require("admin:users")
    @ns.response(204, "TOTP removed from the user")
    def delete(self, user_id: str):
        admin().clear_totp(user_id, username(), client_ip())
        return "", 204


@ns.route("/roles")
class Roles(Resource):
    @require("admin:roles")
    @ns.response(200, "Built-in and custom roles", m.RoleList)
    def get(self):
        return {"items": [r.to_dict() for r in admin().roles()]}

    @require("admin:roles")
    @ns.expect(m.RoleCreate)
    @ns.response(201, "Created", m.Role)
    @ns.response(409, "conflict: name taken", m.Problem)
    def post(self):
        return admin().create_role(json_body(), username(), client_ip()).to_dict(), 201


@ns.route("/roles/<string:name>")
class OneRole(Resource):
    @require("admin:roles")
    @ns.expect(m.RoleUpdate)
    @ns.response(200, "Updated", m.Role)
    @ns.response(409, "conflict: built-in role", m.Problem)
    def put(self, name: str):
        return admin().update_role(name, json_body(), username(), client_ip()).to_dict()

    @require("admin:roles")
    @ns.response(204, "Deleted")
    @ns.response(409, "conflict: built-in or still held", m.Problem)
    def delete(self, name: str):
        admin().delete_role(name, username(), client_ip())
        return "", 204


@ns.route("/permissions")
class Permissions(Resource):
    @require("admin:roles")
    @ns.response(200, "Every permission string", m.PermissionList)
    def get(self):
        return {"items": list(PERMISSIONS)}


@ns.route("/settings")
class Settings(Resource):
    @require("admin:settings")
    @ns.response(200, "cluster.toml [settings]")
    def get(self):
        return admin().settings()

    @require("admin:settings")
    @ns.response(200, "Merged settings")
    @ns.response(400, "validation_error with one entry per bad field", m.Problem)
    def put(self):
        return admin().update_settings(json_body(), username(), client_ip())


@ns.route("/settings/schema")
class SettingsSchema(Resource):
    @require("admin:settings")
    @ns.response(200, "Every setting: key, type, default, bounds, unit, group; pairs; former names")
    def get(self):
        return admin().settings_schema()


@ns.route("/modules")
class Modules(Resource):
    @require("admin:modules")
    @ns.response(200, "Cluster switches and per-node engines", m.Modules)
    def get(self):
        return admin().modules()

    @require("admin:modules")
    @ns.expect(m.Modules)
    @ns.response(200, "Merged modules", m.Modules)
    def put(self):
        return admin().update_modules(json_body(), username(), client_ip())
