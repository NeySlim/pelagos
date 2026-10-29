# SPDX-License-Identifier: Apache-2.0
"""Server-side sessions in web process memory, with a per-session CSRF token (section 16)."""

from __future__ import annotations

import hmac
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from pelagos.domain.common import utcnow

COOKIE_NAME = "pelagos_session"
CSRF_HEADER = "X-CSRF-Token"


@dataclass(slots=True)
class Session:
    id: str
    user_id: str
    username: str
    permissions: set[str]
    csrf_token: str
    created_at: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)
    client_ip: str | None = None
    # "password_change" or "totp_enrollment": only /auth/* answers until the user complies.
    restriction: str | None = None
    # A Bearer call: {"id", "name"} of the API token. Never stored: built per request.
    token: dict[str, str] | None = None


class SessionStore:
    def __init__(self, ttl_seconds: int = 43200, idle_seconds: int = 1800) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self.idle = timedelta(seconds=idle_seconds)
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(
        self,
        user_id: str,
        username: str,
        permissions: set[str],
        client_ip: str | None = None,
        restriction: str | None = None,
    ) -> Session:
        session = Session(
            id=secrets.token_urlsafe(32),
            user_id=user_id,
            username=username,
            permissions=set(permissions),
            csrf_token=secrets.token_urlsafe(32),
            client_ip=client_ip,
            restriction=restriction,
        )
        with self._lock:
            self._sessions[session.id] = session
        return session

    def get(self, session_id: str | None) -> Session | None:
        """Returns the live session and refreshes its idle timer; expired sessions are dropped."""
        if not session_id:
            return None
        now = utcnow()
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if now - session.created_at > self.ttl or now - session.last_seen > self.idle:
                del self._sessions[session_id]
                return None
            session.last_seen = now
            return session

    def peek(self, session_id: str | None) -> Session | None:
        """Like get() but leaves the idle timer alone: a background check is not user activity."""
        if not session_id:
            return None
        now = utcnow()
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if now - session.created_at > self.ttl or now - session.last_seen > self.idle:
                del self._sessions[session_id]
                return None
            return session

    def revoke(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def adopt(self, session: Session) -> None:
        """Put a session back after revoke_user, so the caller survives its own password change."""
        with self._lock:
            self._sessions[session.id] = session

    def revoke_user(self, user_id: str) -> int:
        with self._lock:
            victims = [sid for sid, s in self._sessions.items() if s.user_id == user_id]
            for sid in victims:
                del self._sessions[sid]
        return len(victims)

    def sweep(self) -> int:
        now = utcnow()
        with self._lock:
            dead = [
                sid
                for sid, s in self._sessions.items()
                if now - s.created_at > self.ttl or now - s.last_seen > self.idle
            ]
            for sid in dead:
                del self._sessions[sid]
        return len(dead)

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)


def csrf_ok(session: Session, presented: str | None) -> bool:
    return bool(presented) and hmac.compare_digest(session.csrf_token, presented or "")
