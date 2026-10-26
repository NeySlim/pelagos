# SPDX-License-Identifier: Apache-2.0
"""Administration > Certificates: web UI certificates per node, sources, uploads, renewals (admin only)."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body, plan_dict
from pelagos.api.security import client_ip, require, services, username

ns = Namespace("certificates", description="Web UI certificates of every node", path="/admin/certificates")
PERM = "admin:certificates"


def certs():
    return services().certs


@ns.route("")
class Overview(Resource):
    @require(PERM)
    @ns.response(200, "Every node's certificate, source and renewal state; the cluster source")
    def get(self):
        return certs().overview()


@ns.route("/cluster")
class ClusterSource(Resource):
    @require(PERM)
    @ns.response(200, "Saved; a job requests a certificate on each selected node", m.Problem)
    @ns.response(400, "validation_error", m.Problem)
    def put(self):
        return certs().set_cluster_source(json_body(), username(), client_ip())

    @require(PERM)
    @ns.response(204, "Removed: the nodes keep their certificate and stop renewing it")
    def delete(self):
        certs().clear_cluster_source(username(), client_ip())
        return "", 204


@ns.route("/test/ucm")
class TestUcm(Resource):
    @require(PERM)
    @ns.response(200, "{ok, cas, templates} or {ok: false, error}")
    def post(self):
        return certs().test_ucm(json_body())


@ns.route("/test/acme")
class TestAcme(Resource):
    @require(PERM)
    @ns.response(200, "{ok, directory_url, eab_required} or {ok: false, error}")
    def post(self):
        return certs().test_acme(json_body())


@ns.route("/test/dns")
class TestDns(Resource):
    @require(PERM)
    @ns.response(200, "{ok, detail} or {ok: false, error}")
    def post(self):
        return certs().test_dns(json_body())


@ns.route("/dns01/plan")
class Dns01Setup(Resource):
    @require(PERM)
    @ns.response(200, "{plan, manual, delegation, unserved}: the ddi-acme key and update-policy grants")
    def post(self):
        out = certs().dns01_setup(json_body(required=False), username())
        if out.get("plan") is not None:
            out["plan"] = plan_dict(out["plan"])
        return out


@ns.route("/<string:node_id>")
class NodeCert(Resource):
    @require(PERM)
    @ns.response(200, "The node's certificate, source, renewal state and log")
    @ns.response(404, "not_found", m.Problem)
    def get(self, node_id: str):
        return certs().status(node_id)


@ns.route("/<string:node_id>/source")
class NodeSource(Resource):
    @require(PERM)
    @ns.response(200, "{source, job}: with apply true, a job requests the certificate now")
    @ns.response(400, "validation_error", m.Problem)
    def put(self, node_id: str):
        return certs().set_node_source(node_id, json_body(), username(), client_ip())


@ns.route("/<string:node_id>/renew")
class Renew(Resource):
    @require(PERM)
    @ns.response(202, "A job requesting a certificate from the node's automatic source", m.Job)
    def post(self, node_id: str):
        return certs().renew(node_id, username()).to_dict(), 202


@ns.route("/<string:node_id>/request")
class NodeRequest(Resource):
    @require(PERM)
    @ns.response(200, "{csr_pem, names, key_type}: key and request made on the node, the key stays there")
    def post(self, node_id: str):
        return certs().make_request(node_id, json_body(required=False), username())

    @require(PERM)
    @ns.response(204, "The pending request and its key are removed")
    def delete(self, node_id: str):
        certs().drop_request(node_id, username())
        return "", 204


@ns.route("/<string:node_id>/check")
class Check(Resource):
    @require(PERM)
    @ns.response(200, "{ok, checks, certificate, chain}: nothing is installed")
    def post(self, node_id: str):
        return certs().check(node_id, json_body())


@ns.route("/<string:node_id>/upload")
class Upload(Resource):
    @require(PERM)
    @ns.response(
        200, "Installed (hot reload, handshake checked); `also` lists the other nodes it was sent to"
    )
    @ns.response(400, "validation_error with `checks` when a check failed", m.Problem)
    def post(self, node_id: str):
        return certs().upload(node_id, json_body(), username(), client_ip())


@ns.route("/<string:node_id>/self-signed")
class SelfSigned(Resource):
    @require(PERM)
    @ns.response(200, "A new self-signed certificate is installed")
    def post(self, node_id: str):
        return certs().self_signed(node_id, username())
