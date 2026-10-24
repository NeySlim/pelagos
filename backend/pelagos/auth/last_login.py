# SPDX-License-Identifier: Apache-2.0
"""Last successful login per user, kept on this node only.

A login must not write cluster.toml: that would bump the cluster version and
replicate the whole file on every login. The value shown is the newest of the
local record and any older replicated `users[].last_login`.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from pelagos.core.config_store import atomic_write
from pelagos.core.locks import FileLock
from pelagos.domain.common import from_rfc3339, to_rfc3339, utcnow

log = logging.getLogger(__name__)


class LastLoginStore:
    def __init__(self, path: Path, lock_path: Path) -> None:
        self.path = path
        self.lock = FileLock(lock_path)
        self._mutex = threading.Lock()

    def _read(self) -> dict[str, str]:
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log.warning("last login file %s unreadable: %s", self.path, exc)
            return {}
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}

    def record(self, user_id: str, when: datetime | None = None) -> datetime:
        when = when or utcnow()
        with self._mutex, self.lock:
            data = self._read()
            data[user_id] = to_rfc3339(when)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(self.path, json.dumps(data, sort_keys=True).encode(), mode=0o640)
        return when

    def get(self, user_id: str) -> datetime | None:
        return _parse(self._read().get(user_id))

    def forget(self, user_id: str) -> None:
        with self._mutex, self.lock:
            data = self._read()
            if data.pop(user_id, None) is not None:
                atomic_write(self.path, json.dumps(data, sort_keys=True).encode(), mode=0o640)

    def overlay(self, public: dict[str, Any]) -> dict[str, Any]:
        """A user's public dict with last_login set to the newest known value."""
        return self.overlay_all([public])[0]

    def overlay_all(self, publics: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """`overlay` for a list of users, reading the file once."""
        data = self._read()
        return [_newest(public, data.get(str(public.get("id", "")))) for public in publics]


def _parse(value: Any) -> datetime | None:
    try:
        return from_rfc3339(value) if value else None
    except (TypeError, ValueError):
        return None


def _newest(public: dict[str, Any], raw: str | None) -> dict[str, Any]:
    local = _parse(raw)
    if local is None:
        return public
    replicated = _parse(public.get("last_login"))
    if replicated is None or local > replicated:
        public = {**public, "last_login": to_rfc3339(local)}
    return public
