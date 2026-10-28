# SPDX-License-Identifier: Apache-2.0
"""Scheduled archives and restore (section 23): settings, destinations, runs, list, download, upload,
recipients and the cluster identity, inspect and restore plans."""

from __future__ import annotations

from flask import Response, request
from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import arg, json_body, paged, pagination, plan_dict
from pelagos.api.errors import ApiError
from pelagos.api.security import client_ip, current_session, require, services, username
from pelagos.auth.rbac import has_permission

ns = Namespace("archives", description="Scheduled archives and restore", path="/admin/archives")

PERM = "admin:archives"


def archives():
    return services().archives


@ns.route("")
class Overview(Resource):
    @require(PERM)
    @ns.response(200, "Settings, recipients, identity state, destinations, per node state")
    def get(self):
        return archives().overview()


@ns.route("/settings")
class Settings(Resource):
    @require(PERM)
    @ns.response(200, "The [settings.archives] values")
    @ns.response(400, "validation_error: a value, or scheduling without any recipient", m.Problem)
    def put(self):
        return archives().update_settings(json_body(), username(), client_ip())


@ns.route("/destinations")
class Destinations(Resource):
    @require(PERM)
    @ns.response(201, "Destination (secrets as booleans)")
    @ns.response(400, "validation_error", m.Problem)
    def post(self):
        return archives().create_destination(json_body(), username(), client_ip()), 201


@ns.route("/destinations/test")
class TestDestination(Resource):
    @require(PERM)
    @ns.response(200, "Write, read back and delete a probe file from this node")
    @ns.response(429, "rate_limited", m.Problem)
    def post(self):
        svc = archives()
        user = username()
        if not svc.test_limiter.allow(user):
            retry = svc.test_limiter.retry_after(user)
            raise ApiError("rate_limited", "too many destination tests", headers={"Retry-After": str(retry)})
        return svc.test_destination(json_body(), user, client_ip())


@ns.route("/destinations/<string:destination_id>")
class OneDestination(Resource):
    @require(PERM)
    @ns.response(200, "Destination")
    @ns.response(404, "not_found", m.Problem)
    def put(self, destination_id: str):
        return archives().update_destination(destination_id, json_body(), username(), client_ip())

    @require(PERM)
    @ns.response(204, "Deleted")
    @ns.response(404, "not_found", m.Problem)
    def delete(self, destination_id: str):
        archives().delete_destination(destination_id, username(), client_ip())
        return "", 204


@ns.route("/run")
class Run(Resource):
    @require(PERM)
    @ns.response(202, "Job: one step per node, done when its archive is written", m.Job)
    @ns.response(409, "conflict: no archive recipient", m.Problem)
    def post(self):
        job = archives().run(json_body(required=False), username(), client_ip())
        return job.to_dict(), 202


@ns.route("/list")
class ArchiveList(Resource):
    @require(PERM)
    @ns.doc(params={"node_id": "archives of one node", "destination_id": "archives held at one destination"})
    @ns.response(200, "Paginated archives every reachable node holds; meta.unreachable lists the others")
    def get(self):
        page, per_page = pagination()
        rows, total, meta = archives().list(arg("node_id"), arg("destination_id"), page, per_page)
        return paged(rows, page, per_page, total, meta)


@ns.route("/upload")
class Upload(Resource):
    @require(PERM)
    @ns.doc(
        params={"file": "multipart: the .tar.gz.age file", "identity": "multipart: an identity that opens it"}
    )
    @ns.response(201, "The archive, registered")
    @ns.response(400, "validation_error: not an archive, or no identity opens it", m.Problem)
    @ns.response(409, "conflict: already held", m.Problem)
    def post(self):
        upload = request.files.get("file")
        if upload is None:
            raise ApiError("validation_error", "a multipart field file is required")
        identity = request.form.get("identity") or None
        out = archives().upload(upload.stream, upload.filename or "", identity, username(), client_ip())
        return out, 201


@ns.route("/identity")
class Identity(Resource):
    @require(PERM)
    @ns.response(200, "Recipients; the cluster identity once, on generate and rotate")
    @ns.response(401, "invalid_credentials: generate and rotate need the user's password", m.Problem)
    def post(self):
        session = current_session()
        return archives().identity(json_body(), session.username, session.user_id, client_ip())


@ns.route("/<string:archive_id>/download")
class Download(Resource):
    @require(PERM)
    @ns.produces(["application/octet-stream"])
    @ns.response(200, "The encrypted file, audited")
    @ns.response(404, "not_found", m.Problem)
    def get(self, archive_id: str):
        chunks, meta = archives().download(archive_id, username(), client_ip())
        return Response(
            chunks,
            mimetype="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{meta.filename}"',
                "Content-Length": str(meta.size),
                "X-Pelagos-Sha256": meta.sha256,
            },
        )


@ns.route("/<string:archive_id>/inspect")
class Inspect(Resource):
    @require(PERM)
    @ns.response(200, "Manifest and restorable parts")
    @ns.response(400, "validation_error: no identity opens the archive, unknown target node", m.Problem)
    @ns.response(404, "not_found: no reachable node holds the archive", m.Problem)
    def post(self, archive_id: str):
        body = json_body(required=False)
        return services().archive_restore.inspect(archive_id, body, username())


@ns.route("/<string:archive_id>/restore/plan")
class RestorePlan(Resource):
    @require(PERM)
    @ns.response(200, "Plan (scope restore, requires_confirmation), applied as a Job", m.Plan)
    @ns.response(403, "forbidden: a chosen part needs a write permission the caller lacks", m.Problem)
    @ns.response(409, "conflict: every chosen part already matches the archive", m.Problem)
    def post(self, archive_id: str):
        perms = current_session().permissions
        plan = services().archive_restore.plan(
            archive_id, json_body(), username(), lambda perm: has_permission(perms, perm)
        )
        return plan_dict(plan)
