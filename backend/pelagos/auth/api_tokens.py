# SPDX-License-Identifier: Apache-2.0
"""API tokens (section 16): format, hashing, permission subsets, source networks, per-node last use.

A token is `pel_<id>_<secret>`: `id` is 16 hex characters that find the record, `secret` 32 random
bytes in base64url. Only `sha256:<hex>` of the whole string is stored. A 256-bit random secret
cannot be guessed or brute-forced offline, so a slow hash (argon2) would add a cost on every
request and no protection; the hash only keeps a copy of cluster.toml from being a usable token.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import threading
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from pelagos.auth.rbac import PERMISSIONS, has_permission
from pelagos.core.config_store import atomic_write
from pelagos.core.locks import FileLock
from pelagos.domain.common import from_rfc3339, to_rfc3339, utcnow

log = logging.getLogger(__name__)

PREFIX = "pel_"
SCHEME = "Bearer"
MAX_NAME = 64
MAX_CIDRS = 32
_TOKEN_RE = re.compile(r"^pel_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$")
# A token's last use is written to disk at most this often (seconds) per token and node.
USAGE_WRITE_SECONDS = 60.0


def new_token() -> tuple[str, str]:
    """(id, token string)."""
    token_id = secrets.token_hex(8)
    return token_id, f"{PREFIX}{token_id}_{secrets.token_urlsafe(32)}"


def parse(token: str) -> str | None:
    """The token id, or None when the string is not shaped like a Pelagos token."""
    m = _TOKEN_RE.match(token or "")
    return m.group(1) if m else None


def digest(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode()).hexdigest()


def matches(token: str, stored: str) -> bool:
    """Constant-time comparison of the presented token's digest with the stored one."""
    return hmac.compare_digest(digest(token).encode(), (stored or "").encode())


def bearer(header: str | None) -> str | None:
    """The credential of an `Authorization: Bearer <token>` header, None without one."""
    if not header:
        return None
    scheme, _, value = header.strip().partition(" ")
    return value.strip() if scheme.lower() == SCHEME.lower() and value.strip() else None


# Permissions ------------------------------------------------------------------------------------


def valid_permission(perm: str) -> bool:
    if perm == "*" or perm in PERMISSIONS:
        return True
    action, sep, rest = perm.partition(":")
    return bool(sep) and rest == "*" and any(p.startswith(action + ":") for p in PERMISSIONS)


def within(requested: Iterable[str], held: Iterable[str]) -> list[str]:
    """The requested permissions the holder does not have (empty: a subset)."""
    held = set(held)
    out = []
    for perm in requested:
        if perm == "*":
            ok = "*" in held
        elif perm.endswith(":*"):
            action = perm[:-2]
            ok = has_permission(held, perm) or all(
                has_permission(held, p) for p in PERMISSIONS if p.startswith(action + ":")
            )
        else:
            ok = has_permission(held, perm)
        if not ok:
            out.append(perm)
    return out


def intersect(token_perms: Iterable[str], user_perms: Iterable[str]) -> set[str]:
    """What a call made with the token may do: the token's permissions that the user still holds."""
    a, b = set(token_perms), set(user_perms)
    if "*" in a and "*" in b:
        return {"*"}
    return {p for p in PERMISSIONS if has_permission(a, p) and has_permission(b, p)}


# Source networks --------------------------------------------------------------------------------


def normalize_cidrs(values: Any) -> list[str]:
    """Canonical networks; ValueError names the first bad entry."""
    if values in (None, ""):
        return []
    if not isinstance(values, list) or len(values) > MAX_CIDRS:
        raise ValueError(f"a list of at most {MAX_CIDRS} networks")
    out: list[str] = []
    for raw in values:
        try:
            net = ipaddress.ip_network(str(raw).strip(), strict=False)
        except ValueError:
            raise ValueError(f"{raw!s} is not an address or network") from None
        if str(net) not in out:
            out.append(str(net))
    return out


def source_allowed(cidrs: list[str], address: str | None) -> bool:
    if not cidrs:
        return True
    try:
        ip = ipaddress.ip_address(address or "")
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    for raw in cidrs:
        try:
            if ip in ipaddress.ip_network(raw, strict=False):
                return True
        except (ValueError, TypeError):
            continue
    return False


# Per-node last use ------------------------------------------------------------------------------


class UsageStore:
    """{token id: {"at", "node", "ip"}} on this node only: a call never writes cluster.toml.

    Writes are throttled per token (USAGE_WRITE_SECONDS) so a script polling every second does not
    rewrite the file every second; the time shown is then at most that much behind.
    """

    def __init__(self, path: Path, lock_path: Path, node_id: str) -> None:
        self.path = path
        self.lock = FileLock(lock_path)
        self.node_id = node_id
        self._mutex = threading.Lock()
        self._written: dict[str, datetime] = {}

    def read(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log.warning("API token usage file %s unreadable: %s", self.path, exc)
            return {}
        return {str(k): v for k, v in data.items() if isinstance(v, dict)} if isinstance(data, dict) else {}

    def record(self, token_id: str, ip: str | None, when: datetime | None = None) -> bool:
        """True when the file was written."""
        when = when or utcnow()
        with self._mutex:
            last = self._written.get(token_id)
            if last is not None and (when - last).total_seconds() < USAGE_WRITE_SECONDS:
                return False
            self._written[token_id] = when
        try:
            with self.lock:
                data = self.read()
                data[token_id] = {"at": to_rfc3339(when), "node": self.node_id, "ip": ip}
                self.path.parent.mkdir(parents=True, exist_ok=True)
                atomic_write(self.path, json.dumps(data, sort_keys=True).encode(), mode=0o640)
        except OSError as exc:
            log.warning("API token usage not recorded: %s", exc)
            return False
        return True

    def forget(self, token_ids: Iterable[str]) -> None:
        ids = set(token_ids)
        with self._mutex:
            for tid in ids:
                self._written.pop(tid, None)
        with self.lock:
            data = self.read()
            if any(data.pop(tid, None) is not None for tid in ids):
                atomic_write(self.path, json.dumps(data, sort_keys=True).encode(), mode=0o640)


def newest(*usages: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per token, the most recent use among several nodes' usage maps."""
    out: dict[str, dict[str, Any]] = {}
    for usage in usages:
        for tid, entry in usage.items():
            try:
                at = from_rfc3339(entry.get("at"))
            except (TypeError, ValueError):
                continue
            current = out.get(tid)
            if current is None or at > from_rfc3339(current["at"]):
                out[tid] = {"at": to_rfc3339(at), "node": entry.get("node"), "ip": entry.get("ip")}
    return out
