# SPDX-License-Identifier: Apache-2.0
"""Desired state verbs (section 17, "Desired state verbs"): idempotent PUT and DELETE that converge an
RRset, a zone declaration or a Kea object through the existing plan builders and PlanService.apply."""

from __future__ import annotations

from typing import Any

from flask import g, request
from flask_restx import Namespace, Resource, fields

from pelagos.api import models as m
from pelagos.api.common import arg, bool_arg, int_arg, json_body, plan_answer, plan_dict
from pelagos.api.dhcp import FamilyResource, OneSubnet
from pelagos.api.dns import OneZone
from pelagos.api.errors import ApiError
from pelagos.api.plans import _check_scope
from pelagos.api.security import client_ip, ctx, current_session, require, services, username
from pelagos.domain import AuditEntry, Family, PlanState
from pelagos.services.desired_state import Convergence, DesiredStateService

ns = Namespace("desired", description="Idempotent writes: converge an object to the state given", path="/")

DRY_RUN = {"dry_run": "1: build and return the plan without applying it"}
CONFIRM = {"confirm": "1: apply a plan that needs confirmation (also accepted as confirm in the body)"}
VIEW = {"view": "BIND view (default: _default)"}

DesiredAnswer = ns.model(
    "DesiredAnswer",
    {
        "changed": fields.Boolean(required=True, description="false: the object already was as asked"),
        "etag": fields.String(description="state read before the change (no change and dry_run answers)"),
        "plan": fields.Nested(m.Plan, description="dry_run: the plan that would be applied"),
        "plan_id": fields.String(description="the plan applied"),
        "result": fields.Nested(m.ApplyResult, description="outcome of the apply"),
    },
)
RRsetDesiredBody = ns.model(
    "RRsetDesiredBody",
    {
        "ttl": fields.Integer(description="default: the current TTL, else dns.default_ttl_seconds"),
        "records": fields.List(fields.String, required=True, description="rdata in presentation format"),
        "view": fields.String,
        "ptr": fields.Raw(description="as on records/plan: {sync, delete, reverse_view}"),
        "confirm": fields.Boolean,
    },
)


def desired() -> DesiredStateService:
    s = services()
    return DesiredStateService(s.dns, s.dhcp)


def desired_audit_enricher(entry: AuditEntry) -> None:
    """Plan entries written while serving a desired state verb carry `request.op = "desired"`."""
    from flask import has_request_context

    if has_request_context() and g.get("desired_op") and entry.plan_id:
        entry.request = {**entry.request, "op": "desired"}


def _body(required: bool) -> dict[str, Any]:
    return json_body(required=required)


def _confirm(body: dict[str, Any]) -> bool:
    raw = body.get("confirm", None)
    if raw is None:
        return bool_arg("confirm")
    if not isinstance(raw, bool):
        raise ApiError("validation_error", "confirm must be a boolean")
    return raw


def _strip(body: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: v for k, v in body.items() if k not in keys}


def _etag_header(etag: str | None) -> dict[str, str]:
    return {"ETag": f'"{etag}"'} if etag else {}


def _check_if_match(etag: str | None) -> None:
    """Optimistic concurrency: If-Match names the ETag the client read; anything else is 412."""
    header = request.headers.get("If-Match")
    if not header:
        return
    tags = [t.strip().removeprefix("W/").strip('"') for t in header.split(",")]
    if "*" in tags:
        if etag is None:
            raise ApiError("precondition_failed", "If-Match: * and the object is absent", status=412)
        return
    if etag is None or etag not in tags:
        raise ApiError(
            "precondition_failed",
            f"If-Match {header} does not match the current ETag {etag or '(none)'}",
            status=412,
            headers=_etag_header(etag),
        )


def converge(conv: Convergence, confirm: bool) -> tuple[dict[str, Any], int, dict[str, str]]:
    _check_if_match(conv.etag)
    headers = _etag_header(conv.etag)
    if conv.build is None:
        return {"changed": False, "etag": conv.etag}, 200, headers
    plan = conv.build()
    if _no_change(plan):
        ctx().plan_store.delete(plan.id)
        return {"changed": False, "etag": conv.etag}, 200, headers
    plan_answer(plan)  # 422 engine_validation_failed when the engine refuses the change
    if bool_arg("dry_run"):
        return {"changed": True, "etag": conv.etag, "plan": plan_dict(plan)}, 200, headers
    session = current_session()
    # Same rule as POST /plans/{id}/apply: a token always confirms, a session when the plan says so.
    if not confirm and (session.token is not None or plan.requires_confirmation):
        why = "a plan applied with an API token" if session.token is not None else "this plan"
        raise ApiError("confirmation_required", f"{why} needs confirm=true", extra={"plan": plan_dict(plan)})
    _check_scope(plan)
    g.desired_op = True
    ctx().audit_log.enrich(desired_audit_enricher)
    result = services().plans.apply(plan, session.username, confirm, client_ip())
    return {"changed": True, "plan_id": plan.id, "result": result.to_dict()}, 200, {}


def _no_change(plan: Any) -> bool:
    """A builder that finds nothing to do (an RRset read differently, a Kea object already equal)."""
    if plan.state is PlanState.FAILED:
        return (plan.error or "").strip() == "no change"
    return plan.engine is not None and plan.engine.value.startswith("kea") and not (plan.diff or "").strip()


def _read(conv: Convergence, what: str) -> tuple[dict[str, Any], int, dict[str, str]]:
    if conv.current is None:
        raise ApiError("not_found", what)
    return conv.current, 200, _etag_header(conv.etag)


# DNS ------------------------------------------------------------------------


@ns.route("/dns/zones/<path:zone>/rrsets/<string:owner>/<string:rtype>")
class DesiredRRset(Resource):
    @require("read:dns")
    @ns.doc(params=VIEW)
    @ns.response(200, "The RRset; ETag: the zone's SOA serial", m.RRset)
    @ns.response(404, "not_found: no such RRset", m.Problem)
    def get(self, zone: str, owner: str, rtype: str):
        return _read(desired().rrset(zone, owner, rtype, arg("view")), f"{owner} {rtype} in {zone}")

    @require("write:dns.records")
    @ns.expect(RRsetDesiredBody)
    @ns.doc(params={**DRY_RUN, "If-Match": {"in": "header", "description": "ETag of the GET"}})
    @ns.response(200, "Converged (changed false: already so)", DesiredAnswer)
    @ns.response(400, "validation_error: owner, type, TTL or records", m.Problem)
    @ns.response(412, "precondition_failed: If-Match does not match", m.Problem)
    @ns.response(422, "engine_validation_failed", m.Problem)
    @ns.response(428, "confirmation_required", m.Problem)
    def put(self, zone: str, owner: str, rtype: str):
        body = _body(True)
        view = body.get("view") or arg("view")
        conv = desired().converge_rrset(zone, owner, rtype, body, view, username())
        return converge(conv, _confirm(body))

    @require("write:dns.records")
    @ns.doc(params={**DRY_RUN, **VIEW, **CONFIRM})
    @ns.response(200, "Removed (changed false: it was absent)", DesiredAnswer)
    def delete(self, zone: str, owner: str, rtype: str):
        body = _body(False)
        view = body.get("view") or arg("view")
        conv = desired().converge_rrset(zone, owner, rtype, None, view, username())
        return converge(conv, _confirm(body))


@ns.route("/dns/zones/<path:zone>")
class DesiredZone(OneZone):
    """GET is the zone detail of the DNS namespace; PUT and DELETE converge the declaration."""

    @require("write:dns.zones")
    @ns.expect(m.Zone)
    @ns.doc(params={**DRY_RUN, **VIEW})
    @ns.response(200, "Converged; ETag: hash of the declaration", DesiredAnswer)
    @ns.response(400, "validation_error: unknown field, kind missing on a new zone", m.Problem)
    @ns.response(412, "precondition_failed", m.Problem)
    @ns.response(428, "confirmation_required", m.Problem)
    def put(self, zone: str):
        body = _body(True)
        view = body.get("view") or arg("view")
        conv = desired().converge_zone(zone, _strip(body, "view", "confirm"), view, username())
        return converge(conv, _confirm(body))

    @require("write:dns.zones")
    @ns.doc(params={**DRY_RUN, **VIEW, **CONFIRM})
    @ns.response(200, "Removed (changed false: it was absent)", DesiredAnswer)
    def delete(self, zone: str):
        body = _body(False)
        conv = desired().converge_zone(zone, None, body.get("view") or arg("view"), username())
        return converge(conv, _confirm(body))


# DHCP -----------------------------------------------------------------------


def _family(family: str) -> Family:
    return Family(family)


@ns.route("/dhcp/<string:family>/reservations/<string:key>")
class DesiredReservation(FamilyResource):
    @require("read:dhcp")
    @ns.doc(params={"subnet_id": "subnet id (absent: a global reservation)", "node_id": "node to read"})
    @ns.response(200, "The reservation; ETag: the Kea configuration hash", m.Reservation)
    @ns.response(404, "not_found", m.Problem)
    def get(self, family: str, key: str):
        conv = desired().reservation(_family(family), key, int_arg("subnet_id"), arg("node_id"))
        return _read(conv, f"reservation {key}")

    @require("write:dhcp.reservations")
    @ns.expect(m.Reservation)
    @ns.doc(params=DRY_RUN)
    @ns.response(200, "Converged", DesiredAnswer)
    @ns.response(400, "validation_error", m.Problem)
    @ns.response(412, "precondition_failed", m.Problem)
    @ns.response(428, "confirmation_required", m.Problem)
    def put(self, family: str, key: str):
        body = _body(True)
        conv = desired().converge_reservation(_family(family), key, _strip(body, "confirm"), None, username())
        return converge(conv, _confirm(body))

    @require("write:dhcp.reservations")
    @ns.doc(params={**DRY_RUN, **CONFIRM, "subnet_id": "subnet id (absent: a global reservation)"})
    @ns.response(200, "Removed (changed false: it was absent)", DesiredAnswer)
    def delete(self, family: str, key: str):
        body = _body(False)
        conv = desired().converge_reservation(_family(family), key, None, int_arg("subnet_id"), username())
        return converge(conv, _confirm(body))


@ns.route("/dhcp/<string:family>/subnets/<int:subnet_id>")
class DesiredSubnet(OneSubnet):
    """GET is the subnet read of the DHCP namespace; PUT and DELETE converge the subnet."""

    @require("write:dhcp.subnets")
    @ns.expect(m.Subnet)
    @ns.doc(params=DRY_RUN)
    @ns.response(200, "Converged; ETag: the Kea configuration hash", DesiredAnswer)
    @ns.response(400, "validation_error", m.Problem)
    @ns.response(412, "precondition_failed", m.Problem)
    @ns.response(428, "confirmation_required", m.Problem)
    def put(self, family: str, subnet_id: int):
        body = _body(True)
        conv = desired().converge_subnet(_family(family), subnet_id, _strip(body, "confirm"), username())
        return converge(conv, _confirm(body))

    @require("write:dhcp.subnets")
    @ns.doc(params={**DRY_RUN, **CONFIRM})
    @ns.response(200, "Removed (changed false: it was absent)", DesiredAnswer)
    def delete(self, family: str, subnet_id: int):
        body = _body(False)
        conv = desired().converge_subnet(_family(family), subnet_id, None, username())
        return converge(conv, _confirm(body))


@ns.route("/dhcp/<string:family>/client-classes/<string:name>")
class DesiredClientClass(FamilyResource):
    @require("read:dhcp")
    @ns.response(200, "The class; ETag: the Kea configuration hash", m.ClientClass)
    @ns.response(404, "not_found", m.Problem)
    def get(self, family: str, name: str):
        return _read(desired().client_class(_family(family), name, arg("node_id")), f"client class {name}")

    @require("write:dhcp.classes")
    @ns.expect(m.ClientClass)
    @ns.doc(params=DRY_RUN)
    @ns.response(200, "Converged", DesiredAnswer)
    @ns.response(400, "validation_error", m.Problem)
    @ns.response(412, "precondition_failed", m.Problem)
    @ns.response(428, "confirmation_required", m.Problem)
    def put(self, family: str, name: str):
        body = _body(True)
        conv = desired().converge_client_class(_family(family), name, _strip(body, "confirm"), username())
        return converge(conv, _confirm(body))

    @require("write:dhcp.classes")
    @ns.doc(params={**DRY_RUN, **CONFIRM})
    @ns.response(200, "Removed (changed false: it was absent)", DesiredAnswer)
    def delete(self, family: str, name: str):
        body = _body(False)
        conv = desired().converge_client_class(_family(family), name, None, username())
        return converge(conv, _confirm(body))


@ns.route("/dhcp/<string:family>/options/<string:space>/<string:code>")
class DesiredOption(FamilyResource):
    @require("read:dhcp")
    @ns.response(200, "The global option (code: number or name); ETag: Kea configuration hash", m.OptionData)
    @ns.response(404, "not_found", m.Problem)
    def get(self, family: str, space: str, code: str):
        conv = desired().option(_family(family), space, code, arg("node_id"))
        return _read(conv, f"option {space}/{code}")

    @require("write:dhcp.options")
    @ns.expect(m.OptionData)
    @ns.doc(params=DRY_RUN)
    @ns.response(200, "Converged", DesiredAnswer)
    @ns.response(400, "validation_error", m.Problem)
    @ns.response(412, "precondition_failed", m.Problem)
    @ns.response(428, "confirmation_required", m.Problem)
    def put(self, family: str, space: str, code: str):
        body = _body(True)
        conv = desired().converge_option(_family(family), space, code, _strip(body, "confirm"), username())
        return converge(conv, _confirm(body))

    @require("write:dhcp.options")
    @ns.doc(params={**DRY_RUN, **CONFIRM})
    @ns.response(200, "Removed (changed false: it was absent)", DesiredAnswer)
    def delete(self, family: str, space: str, code: str):
        body = _body(False)
        conv = desired().converge_option(_family(family), space, code, None, username())
        return converge(conv, _confirm(body))
