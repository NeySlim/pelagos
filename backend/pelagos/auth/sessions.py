# SPDX-License-Identifier: Apache-2.0
"""Server-side sessions in web process memory behind a signed cookie that every node of the cluster
can verify and resume, with audit-driven revocations (section 16, "Sessions across nodes")."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import secrets
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from pelagos.domain.common import utcnow

COOKIE_NAME = "pelagos_session"
CSRF_HEADER = "X-CSRF-Token"
COOKIE_VERSION = "v1"
# Timestamps of a cookie may run ahead of this node's clock by at most this much.
CLOCK_SKEW_MS = 120_000
# A request re-signs the cookie when its `seen` is this old.
REFRESH_MS = 60_000
MAX_HANDLES = 100_000
RESTRICTIONS = frozenset({"password_change", "totp_enrollment", "webauthn_enrollment"})
_FIELD = re.compile(r"^[A-Za-z0-9_-]+$")
_DIGITS = re.compile(r"^[0-9]{1,15}$")

log = logging.getLogger(__name__)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def now_ms(now: datetime | None = None) -> int:
    return int((now or utcnow()).timestamp() * 1000)


@dataclass(frozen=True, slots=True)
class SessionKeys:
    cookie: bytes
    csrf: bytes


def derive_keys(secret: bytes) -> SessionKeys:
    return SessionKeys(
        cookie=hmac.new(secret, b"pelagos/cookie/v1", hashlib.sha256).digest(),
        csrf=hmac.new(secret, b"pelagos/csrf/v1", hashlib.sha256).digest(),
    )


def random_keys() -> SessionKeys:
    return derive_keys(secrets.token_bytes(32))


@dataclass(frozen=True, slots=True)
class CookieClaims:
    sid: str
    node_id: str
    user_id: str
    issued_ms: int
    seen_ms: int
    restriction: str | None

    def fields(self) -> list[str]:
        return [
            self.sid,
            self.node_id,
            self.user_id,
            str(self.issued_ms),
            str(self.seen_ms),
            self.restriction or "-",
        ]


def _mac(keys: SessionKeys, claims: CookieClaims) -> str:
    msg = "|".join([COOKIE_VERSION, *claims.fields()]).encode()
    return _b64(hmac.new(keys.cookie, msg, hashlib.sha256).digest())


def sign_cookie(keys: SessionKeys, claims: CookieClaims) -> str:
    return ".".join([COOKIE_VERSION, *claims.fields(), _mac(keys, claims)])


def parse_cookie(value: str | None) -> CookieClaims | None:
    """The claims of a v1 cookie, unverified; None for anything else (absent, malformed, 0.3.x id)."""
    if not value or len(value) > 512:
        return None
    parts = value.split(".")
    if len(parts) != 8 or parts[0] != COOKIE_VERSION:
        return None
    _, sid, node_id, user_id, issued, seen, restriction, mac = parts
    if not all(_FIELD.match(p) for p in (sid, node_id, user_id, restriction, mac)):
        return None
    if not (_DIGITS.match(issued) and _DIGITS.match(seen)):
        return None
    if restriction != "-" and restriction not in RESTRICTIONS:
        return None
    return CookieClaims(
        sid, node_id, user_id, int(issued), int(seen), None if restriction == "-" else restriction
    )


def verify_cookie(keys: SessionKeys, value: str | None) -> CookieClaims | None:
    claims = parse_cookie(value)
    if claims is None:
        return None
    presented = (value or "").rsplit(".", 1)[1]
    return claims if hmac.compare_digest(_mac(keys, claims), presented) else None


def csrf_token(keys: SessionKeys, sid: str) -> str:
    return _b64(hmac.new(keys.csrf, sid.encode(), hashlib.sha256).digest()[:16])


def session_handle(sid: str) -> bytes:
    """One-way name of a session for the audit log: never a credential."""
    return hashlib.sha256(b"pelagos/session/" + sid.encode()).digest()[:16]


@dataclass(slots=True)
class Session:
    id: str
    user_id: str
    username: str
    permissions: set[str]
    csrf_token: str
    created_at: datetime = field(default_factory=utcnow)  # the absolute TTL counts from here (issued_at)
    last_seen: datetime = field(default_factory=utcnow)
    client_ip: str | None = None
    # "password_change" or "totp_enrollment": only /auth/* answers until the user complies.
    restriction: str | None = None
    # A Bearer call: {"id", "name"} of the API token. Never stored: built per request.
    token: dict[str, str] | None = None
    keys: SessionKeys | None = field(default=None, repr=False)
    node_id: str = ""
    seen_ms: int = 0  # `seen` of the last cookie sent or received
    handle: bytes = b""

    @property
    def issued_at(self) -> datetime:
        return self.created_at

    @issued_at.setter
    def issued_at(self, value: datetime) -> None:
        self.created_at = value

    def claims(self, seen_ms: int) -> CookieClaims:
        return CookieClaims(
            self.id, self.node_id or "-", self.user_id, now_ms(self.created_at), seen_ms, self.restriction
        )


class SessionStore:
    def __init__(self, ttl_seconds: int = 43200, idle_seconds: int = 1800) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self.idle = timedelta(seconds=idle_seconds)
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self.revocations = Revocations()

    def create(
        self,
        user_id: str,
        username: str,
        permissions: set[str],
        client_ip: str | None = None,
        restriction: str | None = None,
        *,
        keys: SessionKeys | None = None,
        node_id: str = "",
    ) -> Session:
        """Always a fresh random sid: a presented one is never reused (session fixation)."""
        keys = keys or random_keys()
        sid = secrets.token_urlsafe(32)
        session = Session(
            id=sid,
            user_id=user_id,
            username=username,
            permissions=set(permissions),
            csrf_token=csrf_token(keys, sid),
            client_ip=client_ip,
            restriction=restriction,
            keys=keys,
            node_id=node_id,
            handle=session_handle(sid),
        )
        session.seen_ms = now_ms(session.last_seen)
        with self._lock:
            self._sessions[sid] = session
        return session

    def resume(
        self,
        claims: CookieClaims,
        username: str,
        permissions: set[str],
        restriction: str | None,
        client_ip: str | None,
        *,
        keys: SessionKeys,
    ) -> Session:
        """A local session for a verified cookie of another node (or of an earlier process)."""
        session = Session(
            id=claims.sid,
            user_id=claims.user_id,
            username=username,
            permissions=set(permissions),
            csrf_token=csrf_token(keys, claims.sid),
            created_at=datetime.fromtimestamp(claims.issued_ms / 1000, tz=utcnow().tzinfo),
            client_ip=client_ip,
            restriction=restriction,
            keys=keys,
            node_id=claims.node_id,
            seen_ms=claims.seen_ms,
            handle=session_handle(claims.sid),
        )
        with self._lock:
            self._sessions[session.id] = session
        return session

    def _dead(self, session: Session, now: datetime) -> bool:
        return now - session.created_at > self.ttl or now - session.last_seen > self.idle

    def _lookup(self, value: str | None, refresh: bool) -> Session | None:
        if not value:
            return None
        claims = None
        sid = value
        if "." in value:
            claims = parse_cookie(value)
            if claims is None:
                return None
            sid = claims.sid
        now = utcnow()
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return None
            if claims is not None:
                if session.keys is None or claims.user_id != session.user_id:
                    return None
                if verify_cookie(session.keys, value) is None:
                    return None
                # A copy older than the last re-issue (password change) is not this session any more.
                if claims.issued_ms < now_ms(session.created_at) - 1:
                    return None
                # Activity seen on another node counts for the idle timer here.
                session.seen_ms = max(session.seen_ms, claims.seen_ms)
                seen = datetime.fromtimestamp(claims.seen_ms / 1000, tz=now.tzinfo)
                session.last_seen = max(session.last_seen, min(seen, now))
            if self._dead(session, now):
                del self._sessions[sid]
                return None
            if refresh:
                session.last_seen = now
            return session

    def get(self, cookie: str | None) -> Session | None:
        """The live local session of a signed cookie, refreshing its idle timer; a bare id is none."""
        if not cookie or "." not in cookie:
            return None
        return self._lookup(cookie, refresh=True)

    def peek(self, cookie_or_sid: str | None) -> Session | None:
        """Like get() but leaves the idle timer alone: a background check is not user activity."""
        return self._lookup(cookie_or_sid, refresh=False)

    def cookie(self, session: Session, now: datetime | None = None) -> tuple[str, int]:
        """The session's cookie re-signed with `seen` = now, and the TTL left as max_age."""
        now = now or utcnow()
        seen = now_ms(now)
        keys = session.keys or random_keys()
        session.keys = keys
        session.seen_ms = seen
        left = int((session.created_at + self.ttl - now).total_seconds())
        return sign_cookie(keys, session.claims(seen)), max(0, left)

    def revoke(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def revoke_handle(self, handle: bytes) -> int:
        with self._lock:
            victims = [sid for sid, s in self._sessions.items() if s.handle == handle]
            for sid in victims:
                del self._sessions[sid]
        return len(victims)

    def adopt(self, session: Session) -> None:
        """Put a session back after revoke_user, so the caller survives its own password change."""
        with self._lock:
            self._sessions[session.id] = session

    def revoke_user(self, user_id: str, before: datetime | None = None) -> int:
        """Every session of the user, or only those issued before `before`."""
        with self._lock:
            victims = [
                sid
                for sid, s in self._sessions.items()
                if s.user_id == user_id and (before is None or s.created_at < before)
            ]
            for sid in victims:
                del self._sessions[sid]
        return len(victims)

    def revoke_username(self, username: str, before: datetime) -> int:
        with self._lock:
            victims = [
                sid for sid, s in self._sessions.items() if s.username == username and s.created_at < before
            ]
            for sid in victims:
                del self._sessions[sid]
        return len(victims)

    def sweep(self) -> int:
        now = utcnow()
        with self._lock:
            dead = [sid for sid, s in self._sessions.items() if self._dead(s, now)]
            for sid in dead:
                del self._sessions[sid]
        return len(dead)

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)


def csrf_ok(session: Session, presented: str | None) -> bool:
    return (
        bool(presented)
        and bool(session.csrf_token)
        and hmac.compare_digest(session.csrf_token.encode(), (presented or "").encode())
    )


# Revocations -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RevocationRule:
    """An audit entry shape that ends sessions: `kind` "handle" (one session) or "user" (sessions of
    the user named by the target issued before the entry) or "role" (same for every holder)."""

    action: str
    kind: str
    description: str

    def applies(self, entry: Any) -> bool:
        if entry.action != self.action:
            return False
        result = getattr(entry.result, "value", entry.result)
        request = entry.request or {}
        if self.action == "auth.logout":
            return isinstance(request.get("session"), str)
        if self.action == "auth.op":
            return request.get("op") == "password_change" and result == "ok"
        if self.action == "admin.user.replace":
            return (
                request.get("enabled") is False or "roles" in request or request.get("op") == "reset_password"
            )
        return True


# The only copy of the table of section 16; every SessionStore.revoke_user caller writes one of these.
REVOCATION_RULES: tuple[RevocationRule, ...] = (
    RevocationRule("auth.logout", "handle", "request.session"),
    RevocationRule("auth.op", "user", "op password_change, result ok"),
    RevocationRule("admin.user.replace", "user", "enabled false, roles, or op reset_password"),
    RevocationRule("admin.user.delete", "user", "the user is gone"),
    RevocationRule("admin.role.replace", "role", "every holder of the role"),
)
_WATCHED = tuple(sorted({r.action.split(".")[0] + "." for r in REVOCATION_RULES}))
# Entries are written with a fixed key order: this needle selects auth.*, admin.*, alert.*, archive.*.
SCAN_NEEDLE = b'"action":"a'


class Revocations:
    """Handles logged out and per-user "issued before" bounds, from the replicated audit log.

    The two kinds stay apart: a user bound never adds handles, so a cookie re-signed after a password
    change (same sid, new issued) is not refused. At MAX_HANDLES every resumption is refused."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.handles: dict[bytes, float] = {}  # handle -> expiry (epoch seconds)
        self.users: dict[str, tuple[float, float]] = {}  # username -> (latest entry ts, expiry)
        self._offset: int | None = None
        self._inode: int | None = None
        self._last = 0.0
        self._warned = False
        self.ttl = 43200.0

    @property
    def capped(self) -> bool:
        return len(self.handles) >= MAX_HANDLES

    def refresh(
        self, audit_log: Any, cluster: Any, sessions: SessionStore, now: datetime | None = None
    ) -> None:
        """Apply what the audit log gained since the last call (one stat when nothing did); at the
        first call, the entries of the last TTL through the (ts, id) index (merges append out of ts
        order)."""
        with self._lock:
            now = now or utcnow()
            self.ttl = sessions.ttl.total_seconds()
            if self._offset is None:
                try:
                    st = audit_log.path.stat()
                    self._offset, self._inode = st.st_size, st.st_ino
                except FileNotFoundError:
                    self._offset, self._inode = 0, None
                entries = list(self._recent(audit_log, now))
            else:
                try:
                    st = audit_log.path.stat()
                except FileNotFoundError:
                    return
                if st.st_size == self._offset and st.st_ino == self._inode and not self._due(now):
                    return
                entries, self._offset, self._inode = audit_log.scan(self._offset, self._inode, SCAN_NEEDLE)
            for entry in entries:
                self._apply(entry, cluster, sessions)
            self._expire(now.timestamp())
            if self.capped and not self._warned:
                self._warned = True
                log.warning(
                    "session revocations: %d handles kept, every resumption refused", len(self.handles)
                )
            elif not self.capped:
                self._warned = False

    def _due(self, now: datetime) -> bool:
        """Expiry runs at least once a minute even when the log does not move."""
        due = now.timestamp() - self._last >= 60
        if due:
            self._last = now.timestamp()
        return due

    def _recent(self, audit_log: Any, now: datetime) -> Iterable[Any]:
        since = now - timedelta(seconds=self.ttl)
        for prefix in _WATCHED:
            page = 1
            while True:
                items, total = audit_log.query(action=prefix, since=since, page=page, per_page=1000)
                yield from items
                if page * 1000 >= total or not items:
                    break
                page += 1

    def _apply(self, entry: Any, cluster: Any, sessions: SessionStore) -> None:
        rule = next((r for r in REVOCATION_RULES if r.applies(entry)), None)
        if rule is None:
            return
        ts = entry.ts.timestamp()
        expiry = ts + self.ttl
        if rule.kind == "handle":
            try:
                handle = bytes.fromhex(entry.request["session"])
            except ValueError:
                return
            if len(handle) != 16:
                return
            self.handles[handle] = max(expiry, self.handles.get(handle, 0.0))
            sessions.revoke_handle(handle)
            return
        if rule.kind == "role":
            role = entry.target.removeprefix("role:")
            names = [u.username for u in cluster.users if role in u.roles]
        else:
            names = [entry.target.removeprefix("user:")]
        for name in names:
            latest, _ = self.users.get(name, (0.0, 0.0))
            if ts > latest:
                self.users[name] = (ts, expiry)
            # By name: a deleted user is already gone from cluster.toml when its entry arrives.
            sessions.revoke_username(name, before=entry.ts)

    def _expire(self, now: float) -> None:
        self.handles = {h: e for h, e in self.handles.items() if e > now}
        self.users = {n: v for n, v in self.users.items() if v[1] > now}

    def refused(self, claims: CookieClaims, user: Any) -> bool:
        with self._lock:
            if self.capped:
                return True
            if session_handle(claims.sid) in self.handles:
                return True
            bound = self.users.get(user.username)
            return bound is not None and claims.issued_ms < bound[0] * 1000
