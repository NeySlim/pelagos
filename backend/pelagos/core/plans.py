# SPDX-License-Identifier: Apache-2.0
"""In-memory plan store with TTL on the node that created the plan (section 6)."""

from __future__ import annotations

import threading
from datetime import timedelta

from pelagos.domain.common import utcnow
from pelagos.domain.plan import Plan, PlanState


class PlanNotFound(LookupError):
    pass


class PlanStore:
    def __init__(self, ttl_seconds: int = 600) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self._plans: dict[str, Plan] = {}
        self._lock = threading.Lock()

    def put(self, plan: Plan) -> Plan:
        plan.expires_at = utcnow() + self.ttl
        with self._lock:
            self._plans[plan.id] = plan
        return plan

    def get(self, plan_id: str) -> Plan:
        self.sweep()
        with self._lock:
            plan = self._plans.get(plan_id)
        if plan is None:
            raise PlanNotFound(plan_id)
        return plan

    def update(self, plan: Plan) -> Plan:
        with self._lock:
            self._plans[plan.id] = plan
        return plan

    def delete(self, plan_id: str) -> None:
        with self._lock:
            self._plans.pop(plan_id, None)

    def touch(self, plan: Plan) -> None:
        """Applied plans stay available for rollback for one more TTL."""
        plan.expires_at = utcnow() + self.ttl

    def sweep(self) -> int:
        now = utcnow()
        with self._lock:
            expired = [pid for pid, p in self._plans.items() if p.expires_at <= now]
            for pid in expired:
                plan = self._plans.pop(pid)
                if plan.state in (PlanState.DRAFT, PlanState.VALIDATED):
                    plan.state = PlanState.EXPIRED
        return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._plans)
