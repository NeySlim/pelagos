# SPDX-License-Identifier: Apache-2.0
"""`archives.destinations` entries: validation, retention counts, secret names. No I/O here."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from pelagos.core import settings_registry as reg

PEER = "peer"
MOUNTED = "mounted"
SFTP = "sftp"
TYPES = (PEER, MOUNTED, SFTP)
LOCAL = "local"
KEEP_MAX = 1000

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.:_-]{1,253}$")
_USER_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._@-]{0,63}$")
_FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}=?$")
# Characters the sftp batch syntax would interpret (quotes, escapes, globs) or that end a command.
_SFTP_PATH_BAD = set("\"'\\*?[]\n\r\t")


class DestinationConfigError(ValueError):
    """An `archives.destinations` entry that cannot be used; the message names the field."""


@dataclass
class DestinationConfig:
    id: str
    type: str
    name: str = ""
    enabled: bool = True
    params: dict[str, Any] = field(default_factory=dict)
    keep: dict[str, int] | None = None

    @property
    def label(self) -> str:
        return self.name or self.id

    def to_dict(self) -> dict[str, Any]:
        """The stored entry; no `keep` key stands for null (TOML has no null)."""
        out: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "name": self.name,
            "enabled": self.enabled,
            "params": dict(self.params),
        }
        if self.keep is not None:
            out["keep"] = dict(self.keep)
        return out


def ssh_key_secret(destination_id: str) -> str:
    """Secret name of an SFTP destination's private key."""
    return f"archives/dest/{destination_id}/ssh_key"


def _int(value: Any, what: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise DestinationConfigError(f"{what} must be an integer from {low} to {high}")
    return value


def _keep(raw: Any) -> dict[str, int] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise DestinationConfigError("keep must be null or {daily, weekly, monthly}")
    return {k: _int(raw.get(k, 0), f"keep.{k}", 0, KEEP_MAX) for k in ("daily", "weekly", "monthly")}


def _params(kind: str, raw: Any) -> dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    if kind == PEER:
        ids = raw.get("node_ids", [])
        if not isinstance(ids, list) or not all(isinstance(i, str) and i for i in ids):
            raise DestinationConfigError("params.node_ids must be a list of node ids ([] = every other node)")
        return {"node_ids": list(dict.fromkeys(ids))}
    if kind == MOUNTED:
        path = raw.get("path")
        if not isinstance(path, str) or not os.path.isabs(path) or "\n" in path or "\0" in path:
            raise DestinationConfigError("params.path must be an absolute path")
        path = os.path.normpath(path)
        if path == "/":
            raise DestinationConfigError("params.path cannot be /")
        return {"path": path}
    host = raw.get("host")
    if not isinstance(host, str) or not _HOST_RE.match(host) or host.startswith("-"):
        raise DestinationConfigError("params.host must be a host name or an address")
    port = _int(raw.get("port", 22), "params.port", 1, 65535)
    user = raw.get("username")
    if not isinstance(user, str) or not _USER_RE.match(user):
        raise DestinationConfigError("params.username is required")
    path = raw.get("path", ".")
    if not isinstance(path, str) or not path or _SFTP_PATH_BAD & set(path):
        raise DestinationConfigError("params.path must be a folder name without quotes, globs or tabs")
    fp = raw.get("host_key_fingerprint")
    if not isinstance(fp, str) or not _FP_RE.match(fp.strip()):
        raise DestinationConfigError("params.host_key_fingerprint must be SHA256:... (ssh-keygen -lf)")
    return {
        "host": host,
        "port": port,
        "username": user,
        "path": path.rstrip("/") or "/",
        "host_key_fingerprint": fp.strip().rstrip("="),
    }


def parse(raw: Any) -> DestinationConfig:
    """A validated destination; raises DestinationConfigError."""
    if not isinstance(raw, dict):
        raise DestinationConfigError("a destination is an object")
    dest_id = raw.get("id")
    if not isinstance(dest_id, str) or not _ID_RE.match(dest_id) or dest_id == LOCAL:
        raise DestinationConfigError("id must be letters, digits, - or _ (and not 'local')")
    kind = raw.get("type")
    if kind not in TYPES:
        raise DestinationConfigError(f"type must be one of {', '.join(TYPES)}")
    name = raw.get("name", "")
    if not isinstance(name, str) or len(name) > 128:
        raise DestinationConfigError("name must be a string of at most 128 characters")
    return DestinationConfig(
        id=dest_id,
        type=kind,
        name=name,
        enabled=bool(raw.get("enabled", True)),
        params=_params(kind, raw.get("params")),
        keep=_keep(raw.get("keep")),
    )


def entries(settings: dict[str, Any]) -> list[Any]:
    raw = (settings.get("archives") or {}).get("destinations") or []
    return [d for d in raw if isinstance(d, dict) and d.get("type") != LOCAL]


def configured(settings: dict[str, Any]) -> tuple[list[DestinationConfig], dict[str, str]]:
    """Enabled destinations, and the errors of the enabled entries that do not validate (by id)."""
    good: list[DestinationConfig] = []
    bad: dict[str, str] = {}
    for raw in entries(settings):
        if not raw.get("enabled", True):
            continue
        try:
            good.append(parse(raw))
        except DestinationConfigError as exc:
            bad[str(raw.get("id") or "?")] = str(exc)
    return good, bad


def keep_counts(dest: DestinationConfig | None, settings: dict[str, Any]) -> tuple[int, int, int]:
    """(daily, weekly, monthly) of a destination: its own `keep`, else `archives.keep_*_count`."""
    if dest is not None and dest.keep is not None:
        return dest.keep["daily"], dest.keep["weekly"], dest.keep["monthly"]
    return (
        int(reg.get(settings, "archives.keep_daily_count")),
        int(reg.get(settings, "archives.keep_weekly_count")),
        int(reg.get(settings, "archives.keep_monthly_count")),
    )


def targets_node(dest: DestinationConfig, node_id: str, origin: str) -> bool:
    """Whether a peer destination written by `origin` sends to `node_id`."""
    if dest.type != PEER or node_id == origin:
        return False
    ids = dest.params.get("node_ids") or []
    return not ids or node_id in ids


def received_keep(settings: dict[str, Any], node_id: str, origin: str) -> tuple[int, int, int]:
    """Retention a node applies to the archives `origin` sent it: the largest of the peer
    destinations that target it, the defaults when none does (any longer)."""
    found = [d for d in configured(settings)[0] if targets_node(d, node_id, origin)]
    if not found:
        return keep_counts(None, settings)
    counts = [keep_counts(d, settings) for d in found]
    return max(c[0] for c in counts), max(c[1] for c in counts), max(c[2] for c in counts)
