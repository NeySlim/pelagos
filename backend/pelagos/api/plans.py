# SPDX-License-Identifier: Apache-2.0
"""Plans and jobs: read, apply, rollback, delete."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body, plan_dict
from pelagos.api.errors import ApiError
from pelagos.api.security import client_ip, ctx, current_session, require, services
from pelagos.auth.rbac import has_permission, host_plan_permissions
from pelagos.core.plans import PlanExpired, PlanNotFound
from pelagos.domain import Plan, PlanScope, to_rfc3339
from pelagos.services.archive_restore import restore_permissions
from pelagos.services.hosts_service import touches
from pelagos.services.plan_service import JOB_SCOPES

ns = Namespace("plans", description="Previewed writes and long-running jobs", path="/")


def _plan(plan_id: str) -> Plan:
    try:
        plan = ctx().plan_store.get(plan_id)
    except PlanExpired as exc:
        raise ApiError(
            "plan_expired", f"plan {plan_id} expired at {to_rfc3339(exc.expired_at)}; build it again"
        ) from None
    except PlanNotFound:
        raise ApiError("not_found", f"plan {plan_id} unknown") from None
    session = current_session()
    if plan.created_by != session.username and not has_permission(session.permissions, "*"):
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


@ns.route("/plans/<string:plan_id>")
class OnePlan(Resource):
    @require()
    @ns.response(200, "The plan (creator or admin)", m.Plan)
    @ns.response(404, "not_found: unknown plan", m.Problem)
    @ns.response(410, "plan_expired: the plan's TTL ran out", m.Problem)
    def get(self, plan_id: str):
        return plan_dict(_plan(plan_id))

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
    @ns.response(410, "plan_expired", m.Problem)
    @ns.response(428, "confirmation_required", m.Problem)
    def post(self, plan_id: str):
        plan = _plan(plan_id)
        _check_scope(plan)
        body = json_body(required=False)
        confirm = body.get("confirm", False)
        if not isinstance(confirm, bool):
            raise ApiError("validation_error", "confirm must be a boolean")
        s = services()
        user = current_session().username
        if plan.scope is PlanScope.RESTORE:
            job = s.plans.apply_in_job(plan, user, s.jobs, confirm, client_ip())
            return job.to_dict(), 202
        if plan.scope in JOB_SCOPES:
            runner = s.install.runner(plan.scope)
            job = s.plans.apply_as_job(plan, user, runner, s.jobs, confirm, client_ip())
            return job.to_dict(), 202
        return s.plans.apply(plan, user, confirm, client_ip()).to_dict()


@ns.route("/plans/<string:plan_id>/rollback")
class RollbackPlan(Resource):
    @require()
    @ns.response(200, "Rolled back on every node it was applied to", m.ApplyResult)
    @ns.response(409, "plan_state: only applied plans, or plans a restart interrupted, roll back", m.Problem)
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
