# SPDX-License-Identifier: Apache-2.0
"""In-memory plan store with TTL on the node that created the plan (section 6)."""

from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import datetime, timedelta

from pelagos.domain.common import utcnow
from pelagos.domain.plan import Plan, PlanState

# Expired plan ids remembered so the API answers 410 plan_expired instead of 404 (bounded, oldest out).
MAX_TOMBSTONES = 10000


class PlanNotFound(LookupError):
    pass


class PlanExpired(PlanNotFound):
    """The plan existed on this node and its TTL ran out; `expired_at` says when."""

    def __init__(self, plan_id: str, expired_at: datetime) -> None:
        super().__init__(plan_id)
        self.plan_id = plan_id
        self.expired_at = expired_at


class PlanStore:
    def __init__(self, ttl_seconds: int = 600, max_tombstones: int = MAX_TOMBSTONES) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self.max_tombstones = max_tombstones
        self._plans: dict[str, Plan] = {}
        self._expired: OrderedDict[str, datetime] = OrderedDict()
        self._lock = threading.Lock()

    def put(self, plan: Plan) -> Plan:
        plan.expires_at = utcnow() + self.ttl
        with self._lock:
            self._plans[plan.id] = plan
            self._expired.pop(plan.id, None)
        return plan

    def get(self, plan_id: str) -> Plan:
        self.sweep()
        with self._lock:
            plan = self._plans.get(plan_id)
            expired_at = self._expired.get(plan_id)
        if plan is None:
            if expired_at is not None:
                raise PlanExpired(plan_id, expired_at)
            raise PlanNotFound(plan_id)
        return plan

    def update(self, plan: Plan) -> Plan:
        with self._lock:
            self._plans[plan.id] = plan
        return plan

    def delete(self, plan_id: str) -> None:
        # An explicit delete is not an expiry: the id is forgotten entirely.
        with self._lock:
            self._plans.pop(plan_id, None)
            self._expired.pop(plan_id, None)

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
                self._expired[pid] = plan.expires_at
            while len(self._expired) > self.max_tombstones:
                self._expired.popitem(last=False)
        return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._plans)
