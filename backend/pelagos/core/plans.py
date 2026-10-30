# SPDX-License-Identifier: Apache-2.0
"""Plan store with TTL on the node that created the plan (section 6).

Plans live in memory and, when the store has a directory and the master key, in one file per plan
(`<plans_dir>/<id>.plan`, 0600, the plan and its parts encrypted with the master key, AAD
`plan-store/<id>`), so a restart of the web process keeps them, until their TTL, for apply and
rollback. Their ids, with when they stop being valid, are also kept in a small file under the var
directory (0600, the service user's), so once the TTL ran out the API still answers
`410 plan_expired` instead of `404`. That file is bounded (MAX_TOMBSTONES ids) and pruned of ids
expired for more than TOMBSTONE_TTL.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from pelagos.core.locks import FileLock
from pelagos.domain.common import from_rfc3339, to_rfc3339, utcnow
from pelagos.domain.plan import Plan, PlanState

if TYPE_CHECKING:
    from pelagos.core.secrets import SecretBox

log = logging.getLogger(__name__)

# Expired plan ids remembered so the API answers 410 plan_expired instead of 404 (bounded, oldest out).
MAX_TOMBSTONES = 10000
TOMBSTONE_TTL = timedelta(days=7)
JOURNAL_MAX_BYTES = 64 * 1024
_PLAN_FILE = re.compile(r"^[0-9A-Za-z]{1,64}\.plan$")
# A plan found APPLYING after a restart: its apply or rollback died with the previous process.
INTERRUPTED = (
    "interrupted by a restart of the web process: a rollback undoes the parts every node applied;"
    " check the interrupted part by hand"
)


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
        plans_dir: Path | None = None,
        box: SecretBox | None = None,
    ) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self.max_tombstones = max_tombstones
        self.tombstone_path = tombstone_path
        # Plans reach the disk only encrypted: without the master key they stay in memory.
        self.plans_dir = plans_dir if box is not None else None
        self.box = box
        self._plans: dict[str, Plan] = {}
        self._parts: dict[str, list[Plan]] = {}
        self._expired: OrderedDict[str, datetime] = OrderedDict()
        self._lock = threading.Lock()
        # Called with each new plan (and a composite's parts) before it is stored: the permission
        # guard (services.permissions) may refuse it there. None in processes that build no plans.
        self.guard: Callable[[Plan, list[Plan] | None], None] | None = None
        loaded = self._load_plans() if self.plans_dir is not None else set()
        if tombstone_path is not None:
            self._load(loaded)

    def put(self, plan: Plan) -> Plan:
        if self.guard is not None:
            # A composite registers its parts first: the guard checks each part on its own nodes.
            with self._lock:
                parts = self._parts.get(plan.id)
            self.guard(plan, parts)
        plan.expires_at = utcnow() + self.ttl
        with self._lock:
            self._plans[plan.id] = plan
            self._expired.pop(plan.id, None)
        self._append({plan.id: plan.expires_at})
        self._save(plan)
        return plan

    def set_parts(self, plan_id: str, parts: list[Plan]) -> None:
        """The engine plans a composite plan applies in order, kept and saved with the plan."""
        if self.guard is not None and plan_id in self._plans:
            self.guard(self._plans[plan_id], parts)
        with self._lock:
            self._parts[plan_id] = parts
            plan = self._plans.get(plan_id)
        if plan is not None:
            self._save(plan)

    def parts(self, plan_id: str) -> list[Plan] | None:
        """The parts of a composite plan, None for a plan without parts."""
        with self._lock:
            return self._parts.get(plan_id)

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
        self._save(plan)
        return plan

    def delete(self, plan_id: str) -> None:
        # An explicit delete is not an expiry: the id is forgotten entirely.
        with self._lock:
            self._plans.pop(plan_id, None)
            self._parts.pop(plan_id, None)
            self._expired.pop(plan_id, None)
        self._append({plan_id: None})
        self._unlink(plan_id)

    def touch(self, plan: Plan) -> None:
        """Applied plans stay available for rollback for one more TTL."""
        plan.expires_at = utcnow() + self.ttl
        self._append({plan.id: plan.expires_at})
        self._save(plan)

    def sweep(self) -> int:
        now = utcnow()
        with self._lock:
            expired = [pid for pid, p in self._plans.items() if p.expires_at <= now]
            for pid in expired:
                plan = self._plans.pop(pid)
                self._parts.pop(pid, None)
                if plan.state in (PlanState.DRAFT, PlanState.VALIDATED):
                    plan.state = PlanState.EXPIRED
                self._expired[pid] = plan.expires_at
            while len(self._expired) > self.max_tombstones:
                self._expired.popitem(last=False)
        for pid in expired:
            self._unlink(pid)
        if expired:
            self.compact()
        return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._plans)

    # Plan files ------------------------------------------------------------------------------

    def _plan_file(self, plan_id: str) -> Path | None:
        if self.plans_dir is None or not _PLAN_FILE.match(f"{plan_id}.plan"):
            return None
        return self.plans_dir / f"{plan_id}.plan"

    def _save(self, plan: Plan) -> None:
        """The plan and its parts, encrypted; a failed write leaves the plan usable in memory."""
        path = self._plan_file(plan.id)
        if path is None or self.box is None:
            return
        from pelagos.core.config_store import atomic_write

        with self._lock:
            if plan.id not in self._plans:
                return  # deleted or expired meanwhile
            parts = self._parts.get(plan.id)
        body = {"plan": plan.to_dict(), "parts": [p.to_dict() for p in parts] if parts is not None else None}
        try:
            token = self.box.encrypt(f"plan-store/{plan.id}", json.dumps(body))
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            atomic_write(path, token.encode(), mode=0o600)
        except (OSError, ValueError, TypeError) as exc:
            log.warning("plan %s not saved, it lives in memory only: %s", plan.id, exc)

    def _unlink(self, plan_id: str) -> None:
        path = self._plan_file(plan_id)
        if path is None:
            return
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            log.warning("plan file %s not removed: %s", path, exc)

    def _load_plans(self) -> set[str]:
        """Plans saved by an earlier run and still within their TTL; an expired or unreadable file
        is removed (its id stays a tombstone). A plan caught APPLYING is FAILED and `interrupted`, as
        is its part caught APPLYING; it stays one more TTL for its rollback. Returns the ids."""
        from pelagos.core.secrets import SecretError

        assert self.plans_dir is not None and self.box is not None
        now = utcnow()
        loaded: set[str] = set()
        try:
            files = sorted(self.plans_dir.iterdir())
        except OSError:
            return loaded
        interrupted: list[Plan] = []
        for path in files:
            if not _PLAN_FILE.match(path.name):
                continue
            pid = path.name.removesuffix(".plan")
            try:
                body = json.loads(self.box.decrypt(f"plan-store/{pid}", path.read_text().strip()))
                plan = Plan.from_dict(body["plan"])
                raw_parts = body.get("parts")
                parts = [Plan.from_dict(p) for p in raw_parts] if raw_parts is not None else None
            except (OSError, ValueError, TypeError, KeyError, AttributeError, SecretError) as exc:
                log.warning("plan file %s unreadable, dropped: %s", path, exc)
                path.unlink(missing_ok=True)
                continue
            if plan.id != pid or plan.expires_at <= now:
                path.unlink(missing_ok=True)
                continue
            if plan.state is PlanState.APPLYING:
                plan.state = PlanState.FAILED
                plan.error = INTERRUPTED
                plan.interrupted = True
                plan.expires_at = max(plan.expires_at, now + self.ttl)
                for part in parts or []:
                    if part.state is PlanState.APPLYING:
                        part.state = PlanState.FAILED
                        part.interrupted = True
                interrupted.append(plan)
            self._plans[pid] = plan
            if parts is not None:
                self._parts[pid] = parts
            loaded.add(pid)
        for plan in interrupted:
            self._save(plan)
        if interrupted:
            self._append({p.id: p.expires_at for p in interrupted})
        return loaded

    # Tombstones ------------------------------------------------------------------------------

    @property
    def journal_path(self) -> Path:
        assert self.tombstone_path is not None
        return self.tombstone_path.with_name(self.tombstone_path.name + ".journal")

    def _lockfile(self) -> FileLock:
        assert self.tombstone_path is not None
        return FileLock(self.tombstone_path.with_name(self.tombstone_path.name + ".lock"))

    def _read(self) -> dict[str, datetime]:
        """The compacted file with the journal replayed on top (a removal is `until: null`)."""
        assert self.tombstone_path is not None
        known: dict[str, datetime] = {}
        try:
            raw = json.loads(self.tombstone_path.read_text())
            known = {str(k): from_rfc3339(v) for k, v in dict(raw.get("plans") or {}).items()}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            log.warning("plan tombstones %s unreadable, starting empty: %s", self.tombstone_path, exc)
        try:
            lines = self.journal_path.read_text().splitlines()
        except OSError:
            lines = []
        for line in lines:
            try:
                entry = json.loads(line)
                pid, until = str(entry["id"]), entry.get("until")
                if until is None:
                    known.pop(pid, None)
                else:
                    known[pid] = from_rfc3339(until)
            except (ValueError, TypeError, KeyError, AttributeError):
                continue  # a line cut by a crash
        return known

    def _load(self, loaded: set[str] | frozenset[str] = frozenset()) -> None:
        """Every id recorded by an earlier run and not loaded from its plan file is expired now: its
        plan was only in that run's memory."""
        now = utcnow()
        known = self._read()
        with self._lock:
            for pid, until in sorted(known.items(), key=lambda kv: kv[1]):
                if pid in loaded:
                    continue
                if now - until <= TOMBSTONE_TTL:
                    self._expired[pid] = min(until, now)
            while len(self._expired) > self.max_tombstones:
                self._expired.popitem(last=False)
        self.compact()

    def _append(self, entries: dict[str, datetime | None]) -> None:
        """One journal line per id, without fsync; compacts once the journal is large."""
        if self.tombstone_path is None:
            return
        body = "".join(
            json.dumps({"id": pid, "until": to_rfc3339(until) if until else None}) + "\n"
            for pid, until in entries.items()
        ).encode()
        try:
            with self._lockfile():
                self.tombstone_path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(self.journal_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    os.write(fd, body)
                    size = os.fstat(fd).st_size
                finally:
                    os.close(fd)
                if size > JOURNAL_MAX_BYTES:
                    self._compact_locked()
        except OSError as exc:
            # The plan itself is in memory and usable; only the 410 after a restart is lost.
            log.warning("plan tombstones %s not written: %s", self.journal_path, exc)

    def compact(self) -> None:
        """Fold the journal into the file (pruned and bounded), then empty the journal."""
        if self.tombstone_path is None:
            return
        try:
            with self._lockfile():
                self._compact_locked()
        except OSError as exc:
            log.warning("plan tombstones %s not compacted: %s", self.tombstone_path, exc)

    def _compact_locked(self) -> None:
        from pelagos.core.config_store import atomic_write

        assert self.tombstone_path is not None
        now = utcnow()
        kept = sorted(
            ((pid, until) for pid, until in self._read().items() if now - until <= TOMBSTONE_TTL),
            key=lambda kv: kv[1],
        )
        kept = kept[max(0, len(kept) - self.max_tombstones) :]
        body = {"plans": {pid: to_rfc3339(until) for pid, until in kept}}
        atomic_write(self.tombstone_path, json.dumps(body).encode(), mode=0o600)
        # Replaying a journal line the file already holds is harmless, so a crash here loses nothing.
        try:
            os.truncate(self.journal_path, 0)
        except FileNotFoundError:
            pass
