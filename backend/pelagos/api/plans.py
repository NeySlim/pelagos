# SPDX-License-Identifier: Apache-2.0
"""Plans and jobs: read, apply, rollback, delete."""

from __future__ import annotations

from typing import Any

from flask_restx import Namespace, Resource, fields

from pelagos.api import models as m
from pelagos.api.common import arg, json_body, paged, pagination, plan_dict
from pelagos.api.errors import ApiError
from pelagos.api.security import client_ip, ctx, current_session, require, services
from pelagos.auth.rbac import has_permission, host_plan_permissions
from pelagos.core.plans import PlanExpired, PlanNotFound
from pelagos.domain import Plan, PlanScope, PlanState, to_rfc3339
from pelagos.services.archive_restore import restore_permissions
from pelagos.services.hosts_service import touches
from pelagos.services.masking import mask_text_values, masked_text
from pelagos.services.plan_service import JOB_SCOPES

ns = Namespace("plans", description="Previewed writes and long-running jobs", path="/")

# Section 6: one line of the Plans page.
SUMMARY_FIELDS = (
    "id", "scope", "engine", "node_id", "summary", "summary_message", "created_by", "created_at", "state",
    "expires_at", "finished_at", "rollback_until", "interrupted", "error", "error_message",
    "target_node_ids", "requires_confirmation",
)  # fmt: skip
PlanSummary = m.model("PlanSummary", {name: fields.Raw() for name in SUMMARY_FIELDS})
PlanSummaryPage = m.page_of(PlanSummary, "PlanSummaryPage")


def summary_dict(plan: Plan) -> dict[str, Any]:
    data = plan.to_dict()
    out = {name: data.get(name) for name in SUMMARY_FIELDS}
    out["summary"] = masked_text(out["summary"] or "")
    if out["error"]:
        out["error"] = masked_text(out["error"])
    # Message params may quote engine text, like the plain fields above.
    for name in ("summary_message", "error_message"):
        out[name] = mask_text_values(out[name])
    return out


def _states(raw: str | None) -> set[PlanState] | None:
    if raw is None:
        return None
    try:
        return {PlanState(s.strip()) for s in raw.split(",") if s.strip()}
    except ValueError:
        raise ApiError(
            "validation_error", f"unknown state in {raw}", errors=[{"field": "state", "message": "unknown"}]
        ) from None


def _scope(raw: str | None) -> str | None:
    if raw is not None and not any(s.value.startswith(raw) for s in PlanScope):
        raise ApiError(
            "validation_error", f"unknown scope {raw}", errors=[{"field": "scope", "message": "unknown"}]
        )
    return raw


def _plan(plan_id: str, write: bool = True) -> Plan:
    try:
        plan = ctx().plan_store.get(plan_id)
    except PlanExpired as exc:
        raise ApiError(
            "plan_expired", f"plan {plan_id} expired at {to_rfc3339(exc.expired_at)}; build it again"
        ) from None
    except PlanNotFound:
        # Plans live on the node that built them (review B10): say so rather than a bare 404.
        raise ApiError(
            "not_found",
            f"plan {plan_id} unknown on {ctx().node.name}: a plan stays on the node where it was built",
        ) from None
    session = current_session()
    if plan.created_by != session.username and not has_permission(session.permissions, "*"):
        # read:audit shows any plan; using it stays with its creator or an admin.
        if write or not has_permission(session.permissions, "read:audit"):
            raise ApiError("forbidden", "only the creator or an admin can use this plan")
    return plan


def _check_scope(plan: Plan) -> None:
    perms = current_session().permissions
    if plan.scope is PlanScope.HOST:
        dns, dhcp = touches(plan)
        allowed = host_plan_permissions(perms, dns, dhcp)
    else:
        allowed = has_permission(perms, plan.permission)
    if not allowed:
        raise ApiError("forbidden", f"requires {plan.permission}")
    # A restore also needs the write permission of every part (section 23).
    if plan.scope is PlanScope.RESTORE:
        for perm in sorted(restore_permissions(plan, services().plans.parts(plan))):
            if not has_permission(perms, perm):
                raise ApiError("forbidden", f"requires {perm}")
    # A DDNS failover plan writes the D2 configuration too (section 24).
    if plan.scope is PlanScope.DNS_FAILOVER and not has_permission(perms, "write:dhcp.config"):
        raise ApiError("forbidden", "requires write:dhcp.config")
    # A Kea migration stops and switches HA pairs (section 28).
    if plan.scope is PlanScope.KEA_MIGRATION and not has_permission(perms, "ops:dhcp.ha"):
        raise ApiError("forbidden", "requires ops:dhcp.ha")


@ns.route("/plans")
class Plans(Resource):
    @require()
    @ns.doc(
        params={
            "state": "comma-separated plan states",
            "user": "creator (only yourself without read:audit)",
            "scope": "a plan scope or a prefix such as dhcp.",
            "page": "1-based",
            "per_page": "default 50, max 500",
        }
    )
    @ns.response(200, "Plans this node holds, newest first", PlanSummaryPage)
    @ns.response(403, "forbidden: another user's plans without read:audit", m.Problem)
    def get(self):
        page, per_page = pagination()
        states, scope, user = _states(arg("state")), _scope(arg("scope")), arg("user")
        session = current_session()
        if not has_permission(session.permissions, "read:audit"):
            if user not in (None, session.username):
                raise ApiError("forbidden", "requires read:audit to list another user's plans")
            user = session.username
        rows, total = ctx().plan_store.list(
            states=states, user=user, scope=scope, page=page, per_page=per_page
        )
        return paged([summary_dict(p) for p in rows], page, per_page, total, {"node_id": ctx().node.id})


@ns.route("/plans/<string:plan_id>")
class OnePlan(Resource):
    @require()
    @ns.response(200, "The plan (creator, admin, or read only with read:audit)", m.Plan)
    @ns.response(404, "not_found: unknown plan", m.Problem)
    @ns.response(410, "plan_expired: the plan is no longer held", m.Problem)
    def get(self, plan_id: str):
        return plan_dict(_plan(plan_id, write=False))

    @require()
    @ns.response(204, "Plan dropped")
    def delete(self, plan_id: str):
        plan = _plan(plan_id)
        ctx().plan_store.delete(plan.id)
        return "", 204


@ns.route("/plans/<string:plan_id>/apply")
class ApplyPlan(Resource):
    @require()
    @ns.expect(m.ApplyBody)
    @ns.response(200, "Applied on every target node, self first; state tells the outcome", m.ApplyResult)
    @ns.response(202, "install, import and security plans run as a Job", m.Job)
    @ns.response(409, "precondition_failed or plan_state", m.Problem)
    @ns.response(401, "invalid_credentials: an update plan needs the user's password", m.Problem)
    @ns.response(410, "plan_expired", m.Problem)
    @ns.response(428, "confirmation_required", m.Problem)
    def post(self, plan_id: str):
        plan = _plan(plan_id)
        _check_scope(plan)
        body = json_body(required=False)
        confirm = body.get("confirm", False)
        if not isinstance(confirm, bool):
            raise ApiError("validation_error", "confirm must be a boolean")
        # A script applies only what it states it means to apply: every plan, not just the risky ones.
        if current_session().token is not None and not confirm:
            raise ApiError("confirmation_required", "a plan applied with an API token needs confirm=true")
        s = services()
        user = current_session().username
        if plan.scope is PlanScope.UPDATE:
            # An update has root install packages on every node: the user's password confirms it.
            s.updates.check_password(
                current_session().user_id, body.get("password"), user, "update.apply", client_ip()
            )
            if plan.update is not None:
                plan.update["confirmed_by"] = user
        if plan.scope is PlanScope.RESTORE:
            job = s.plans.apply_in_job(plan, user, s.jobs, confirm, client_ip())
            return job.to_dict(), 202
        if plan.scope in JOB_SCOPES:
            kea = plan.scope is PlanScope.KEA_MIGRATION
            runner = s.kea_migration.runner() if kea else s.install.runner(plan.scope)
            job = s.plans.apply_as_job(plan, user, runner, s.jobs, confirm, client_ip())
            return job.to_dict(), 202
        return s.plans.apply(plan, user, confirm, client_ip()).to_dict()


@ns.route("/plans/<string:plan_id>/rollback")
class RollbackPlan(Resource):
    @require()
    @ns.response(200, "Rolled back on every node it was applied to", m.ApplyResult)
    @ns.response(409, "plan_state, or precondition_failed: the state moved since the apply", m.Problem)
    @ns.response(410, "plan_expired: past rollback_until", m.Problem)
    def post(self, plan_id: str):
        plan = _plan(plan_id)
        _check_scope(plan)
        return services().plans.rollback(plan, current_session().username, client_ip()).to_dict()


@ns.route("/jobs/<string:job_id>")
class OneJob(Resource):
    @require()
    @ns.response(200, "Job progress and steps", m.Job)
    @ns.response(404, "not_found", m.Problem)
    def get(self, job_id: str):
        job = services().jobs.get(job_id)
        if job is None:
            raise ApiError("not_found", f"job {job_id}")
        return job.to_dict()
