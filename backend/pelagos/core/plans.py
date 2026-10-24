# SPDX-License-Identifier: Apache-2.0
"""In-memory plan store with TTL on the node that created the plan (section 6).

Plans live in memory only; their ids, with when they stop being valid, are also kept in a small
file under the var directory (0600, the service user's), so after a restart, or once the TTL ran
out, the API still answers `410 plan_expired` instead of `404`. That file is bounded
(MAX_TOMBSTONES ids) and pruned of ids expired for more than TOMBSTONE_TTL.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import OrderedDict
from datetime import datetime, timedelta
from pathlib import Path

from pelagos.core.locks import FileLock
from pelagos.domain.common import from_rfc3339, to_rfc3339, utcnow
from pelagos.domain.plan import Plan, PlanState

log = logging.getLogger(__name__)

# Expired plan ids remembered so the API answers 410 plan_expired instead of 404 (bounded, oldest out).
MAX_TOMBSTONES = 10000
TOMBSTONE_TTL = timedelta(days=7)


class PlanNotFound(LookupError):
    pass


class PlanExpired(PlanNotFound):
    """The plan existed on this node and its TTL ran out; `expired_at` says when."""

    def __init__(self, plan_id: str, expired_at: datetime) -> None:
        super().__init__(plan_id)
        self.plan_id = plan_id
        self.expired_at = expired_at


class PlanStore:
    def __init__(
        self,
        ttl_seconds: int = 600,
        max_tombstones: int = MAX_TOMBSTONES,
        tombstone_path: Path | None = None,
    ) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self.max_tombstones = max_tombstones
        self.tombstone_path = tombstone_path
        self._plans: dict[str, Plan] = {}
        self._expired: OrderedDict[str, datetime] = OrderedDict()
        self._lock = threading.Lock()
        if tombstone_path is not None:
            self._load()

    def put(self, plan: Plan) -> Plan:
        plan.expires_at = utcnow() + self.ttl
        with self._lock:
            self._plans[plan.id] = plan
            self._expired.pop(plan.id, None)
        self._persist(add={plan.id: plan.expires_at})
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
        self._persist(remove={plan_id})

    def touch(self, plan: Plan) -> None:
        """Applied plans stay available for rollback for one more TTL."""
        plan.expires_at = utcnow() + self.ttl
        self._persist(add={plan.id: plan.expires_at})

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

    # Persistence -----------------------------------------------------------------------------

    def _lockfile(self) -> FileLock:
        assert self.tombstone_path is not None
        return FileLock(self.tombstone_path.with_name(self.tombstone_path.name + ".lock"))

    def _read(self) -> dict[str, datetime]:
        assert self.tombstone_path is not None
        try:
            raw = json.loads(self.tombstone_path.read_text())
            return {str(k): from_rfc3339(v) for k, v in dict(raw.get("plans") or {}).items()}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            log.warning("plan tombstones %s unreadable, starting empty: %s", self.tombstone_path, exc)
            return {}

    def _load(self) -> None:
        """Every id recorded by an earlier run is expired now: its plan was only in that run's memory."""
        now = utcnow()
        known = self._read()
        with self._lock:
            for pid, until in sorted(known.items(), key=lambda kv: kv[1]):
                if now - until <= TOMBSTONE_TTL:
                    self._expired[pid] = min(until, now)
            while len(self._expired) > self.max_tombstones:
                self._expired.popitem(last=False)

    def _persist(self, add: dict[str, datetime] | None = None, remove: set[str] | None = None) -> None:
        """Merge into the file under its lock (another process may share it), pruned and bounded."""
        if self.tombstone_path is None:
            return
        from pelagos.core.config_store import atomic_write

        try:
            with self._lockfile():
                known = self._read()
                known.update(add or {})
                for pid in remove or ():
                    known.pop(pid, None)
                now = utcnow()
                kept = sorted(
                    ((pid, until) for pid, until in known.items() if now - until <= TOMBSTONE_TTL),
                    key=lambda kv: kv[1],
                )
                kept = kept[max(0, len(kept) - self.max_tombstones) :]
                body = {"plans": {pid: to_rfc3339(until) for pid, until in kept}}
                atomic_write(self.tombstone_path, json.dumps(body).encode(), mode=0o600)
        except OSError as exc:
            # The plan itself is in memory and usable; only the 410 after a restart is lost.
            log.warning("plan tombstones %s not written: %s", self.tombstone_path, exc)
