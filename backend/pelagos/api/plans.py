# SPDX-License-Identifier: Apache-2.0
"""Plans and jobs: read, apply, rollback, delete."""

from __future__ import annotations

from flask_restx import Namespace, Resource

from pelagos.api.errors import ApiError, not_implemented
from pelagos.api.security import ctx, current_session, require
from pelagos.auth.rbac import has_permission
from pelagos.core.plans import PlanNotFound

ns = Namespace("plans", description="Previewed writes and long-running jobs", path="/")
OWNER = "WP-API-AUTH"


def _plan(plan_id: str):
    try:
        plan = ctx().plan_store.get(plan_id)
    except PlanNotFound:
        raise ApiError("not_found", f"plan {plan_id} unknown or expired") from None
    session = current_session()
    if plan.created_by != session.username and not has_permission(session.permissions, "*"):
        raise ApiError("forbidden", "only the creator or an admin can see this plan")
    return plan


@ns.route("/plans/<string:plan_id>")
class OnePlan(Resource):
    @require()
    def get(self, plan_id: str):
        return _plan(plan_id).to_dict()

    @require()
    def delete(self, plan_id: str):
        plan = _plan(plan_id)
        ctx().plan_store.delete(plan.id)
        return "", 204


@ns.route("/plans/<string:plan_id>/apply")
class ApplyPlan(Resource):
    @require()
    def post(self, plan_id: str):
        plan = _plan(plan_id)
        if not has_permission(current_session().permissions, plan.permission):
            raise ApiError("forbidden", f"requires {plan.permission}")
        raise not_implemented(OWNER)


@ns.route("/plans/<string:plan_id>/rollback")
class RollbackPlan(Resource):
    @require()
    def post(self, plan_id: str):
        plan = _plan(plan_id)
        if not has_permission(current_session().permissions, plan.permission):
            raise ApiError("forbidden", f"requires {plan.permission}")
        raise not_implemented(OWNER)


@ns.route("/jobs/<string:job_id>")
class OneJob(Resource):
    @require()
    def get(self, job_id: str):
        raise not_implemented(OWNER)
