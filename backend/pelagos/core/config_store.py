# SPDX-License-Identifier: Apache-2.0
"""node.toml and cluster.toml: load, atomic save, monotonic version, merge rule (section 10)."""

from __future__ import annotations

import glob
import os
import re
import tempfile
import time
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomli_w

from pelagos.core import cluster_merge as cm
from pelagos.core.locks import FileLock
from pelagos.domain.cluster import NodeModules, Peer, Role, User
from pelagos.domain.common import from_rfc3339, new_id, to_rfc3339, utcnow

SCHEMA_VERSION = 1
# All interfaces by default: the node serves the admin network, and TLS is mandatory.
DEFAULT_WEB_LISTEN = "0.0.0.0:8443"
DEFAULT_REPL_LISTEN = "0.0.0.0:8444"

DEFAULT_SETTINGS: dict[str, Any] = {
    "plan_ttl_seconds": 600,
    "session_ttl_seconds": 43200,
    "session_idle_seconds": 1800,
    "login_rate_limit_per_minute": 10,
    "require_totp": False,
    "alerts_pool_warning_percent": 80,
    "alerts_pool_critical_percent": 95,
    "alerts_serial_divergence_seconds": 900,
    "alerts_d2_error_rate": 0.05,
    "dns": {
        "read_key": "ddi-read",
        "admin_key": "ddi-admin",
        "update_types_admin": ["A", "AAAA", "PTR", "CNAME", "TXT", "SRV", "MX", "DHCID"],
        "update_types_kea": ["A", "AAAA", "PTR", "DHCID"],
        "default_ns": [],
    },
    "kea": {"ddns_key": "kea-ddns"},
    "collector": {
        "poll_seconds": 60,
        "pool_sample_seconds": 300,
        "peer_poll_seconds": 30,
        "consistency_seconds": 900,
    },
    "retention": {
        "pool_raw_days": 7,
        "pool_hourly_days": 365,
        "serial_days": 90,
        "ha_transition_days": 365,
        "alerts_resolved_days": 90,
        "backups_days": 90,
    },
}

DEFAULT_MODULES: dict[str, Any] = {"dhcpv6": False, "advanced_editor": True}


class ConfigError(Exception):
    pass


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


# A temp file of an atomic write older than this was left by a crash: removed on the next write.
STALE_TEMP_SECONDS = 600
TEMP_MARK = ".pelagos-tmp."


def fsync_dir(directory: Path) -> None:
    """Make a rename in `directory` durable: without it a power loss can bring the old file back."""
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass  # some filesystems refuse fsync on directories; the rename is still atomic
    finally:
        os.close(fd)


def temp_prefix(path: Path) -> str:
    """mkstemp prefix of atomic writes; distinctive so cleanup never matches an admin's own files."""
    return f".{path.name}{TEMP_MARK}"


def remove_stale_temps(path: Path, older_than: float = STALE_TEMP_SECONDS) -> int:
    """Temp files `.<name>.pelagos-tmp.<8 chars>` an interrupted atomic write left next to `path`."""
    removed = 0
    now = time.time()
    pattern = re.compile(re.escape(temp_prefix(path)) + r"[a-z0-9_]{8}")
    try:
        candidates = list(path.parent.glob(glob.escape(temp_prefix(path)) + "*"))
    except OSError:
        return 0
    for tmp in candidates:
        try:
            if pattern.fullmatch(tmp.name) and tmp.is_file() and now - tmp.stat().st_mtime > older_than:
                tmp.unlink()
                removed += 1
        except OSError:
            pass
    return removed


def atomic_write(path: Path, data: bytes, mode: int = 0o640) -> None:
    """Write via a temp file in the same directory, fsync, rename, fsync the directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    remove_stale_temps(path)
    fd, tmp = tempfile.mkstemp(prefix=temp_prefix(path), dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        fsync_dir(path.parent)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _dt(value: Any) -> Any:
    return to_rfc3339(value) if hasattr(value, "tzinfo") else value


@dataclass(slots=True)
class NodeConfig:
    id: str
    name: str
    web_listen: str = "0.0.0.0:8443"
    replication_listen: str = "0.0.0.0:8444"
    replication_url: str = ""
    web_url: str = ""
    engines: dict[str, Any] = field(default_factory=dict)
    paths: dict[str, str] = field(default_factory=dict)
    tls: dict[str, str] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    @property
    def modules(self) -> NodeModules:
        return NodeModules(
            bind=bool(self.engines.get("bind")),
            kea4=bool(self.engines.get("kea4")),
            kea6=bool(self.engines.get("kea6")),
            d2=bool(self.engines.get("d2")),
        )

    @classmethod
    def from_toml(cls, data: dict[str, Any]) -> NodeConfig:
        node = data.get("node") or {}
        if "id" not in node or "name" not in node:
            raise ConfigError("node.toml needs [node] id and name")
        return cls(
            id=node["id"],
            name=node["name"],
            web_listen=node.get("web_listen", "0.0.0.0:8443"),
            replication_listen=node.get("replication_listen", "0.0.0.0:8444"),
            replication_url=node.get("replication_url", ""),
            web_url=node.get("web_url", ""),
            engines=dict(data.get("engines") or {}),
            paths=dict(data.get("paths") or {}),
            tls=dict(data.get("tls") or {}),
            schema_version=int(data.get("schema_version", SCHEMA_VERSION)),
        )

    def to_toml(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schema_version": self.schema_version,
            "node": {
                "id": self.id,
                "name": self.name,
                "web_listen": self.web_listen,
                "replication_listen": self.replication_listen,
                "replication_url": self.replication_url,
                "web_url": self.web_url,
            },
        }
        if self.paths:
            out["paths"] = self.paths
        if self.tls:
            out["tls"] = self.tls
        if self.engines:
            out["engines"] = self.engines
        return out


@dataclass(slots=True)
class ClusterConfig:
    cluster_id: str
    version: int = 0
    updated_at: Any = field(default_factory=utcnow)
    updated_by: str = ""
    nodes: list[Peer] = field(default_factory=list)
    users: list[User] = field(default_factory=list)
    roles: list[Role] = field(default_factory=list)
    modules: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_MODULES))
    settings: dict[str, Any] = field(default_factory=lambda: deep_merge(DEFAULT_SETTINGS, {}))
    secrets: dict[str, str] = field(default_factory=dict)
    revoked: list[str] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION
    # Per-entry stamps and tombstones (core.cluster_merge); `stamped` is False for a pre-merge file.
    stamps: dict[str, cm.Stamp] = field(default_factory=dict)
    tombstones: dict[str, cm.Stamp] = field(default_factory=dict)
    stamped: bool = False

    @classmethod
    def new(cls, created_by: str) -> ClusterConfig:
        return cls(cluster_id=new_id(), version=0, updated_by=created_by)

    @classmethod
    def from_toml(cls, data: dict[str, Any]) -> ClusterConfig:
        schema = int(data.get("schema_version", SCHEMA_VERSION))
        if schema > SCHEMA_VERSION:
            raise ConfigError(
                f"cluster.toml schema_version {schema} is newer than supported {SCHEMA_VERSION}"
            )
        cfg = cls(
            cluster_id=data.get("cluster_id") or new_id(),
            version=int(data.get("version", 0)),
            updated_at=from_rfc3339(data["updated_at"]) if data.get("updated_at") else utcnow(),
            updated_by=str(data.get("updated_by", "")),
            nodes=[Peer.from_dict(_decode_dates(n)) for n in data.get("nodes", [])],
            users=[User.from_dict(_decode_dates(u)) for u in data.get("users", [])],
            roles=[Role.from_dict(r) for r in data.get("roles", [])],
            modules=deep_merge(DEFAULT_MODULES, data.get("modules") or {}),
            settings=deep_merge(DEFAULT_SETTINGS, data.get("settings") or {}),
            secrets=dict(data.get("secrets") or {}),
            revoked=list(data.get("revoked") or []),
            schema_version=schema,
        )
        repl = data.get("replication")
        if isinstance(repl, dict):
            cfg.stamped = True
            cfg.stamps = {str(k): cm.parse_stamp(v) for k, v in (repl.get("stamps") or {}).items()}
            cfg.tombstones = {str(k): cm.parse_stamp(v) for k, v in (repl.get("tombstones") or {}).items()}
        return cfg

    def to_toml(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "version": self.version,
            "updated_at": to_rfc3339(self.updated_at),
            "updated_by": self.updated_by,
            "cluster_id": self.cluster_id,
            "nodes": [_strip_none(n.to_dict()) for n in self.nodes],
            "users": [_strip_none(u.to_dict()) for u in self.users],
            "roles": [_strip_none(r.to_dict()) for r in self.roles],
            "modules": self.modules,
            "settings": self.settings,
            "secrets": self.secrets,
            "revoked": self.revoked,
            **self._replication_table(),
        }

    def _replication_table(self) -> dict[str, Any]:
        if not self.stamped:
            return {}
        stamps = {p: cm.stamp_text(s) for p, s in sorted(self.stamps.items()) if s != cm.ZERO}
        tombs = {p: cm.stamp_text(s) for p, s in sorted(self.tombstones.items())}
        return {"replication": {"stamps": stamps, "tombstones": tombs}}

    def document(self) -> dict[str, Any]:
        """The replicated entries' document: `to_toml()` without the header."""
        return {k: v for k, v in self.to_toml().items() if k not in cm.HEADER}

    def state(self) -> cm.State:
        # A pre-merge file: every entry carries the file's own (version, writer), the old rule.
        fallback = cm.ZERO if self.stamped else (self.version, cm.writer_node(self.updated_by))
        return cm.state_of(self.document(), self.stamps, self.tombstones, fallback)

    def digest(self) -> str:
        return self.state().digest()

    def dumps(self) -> str:
        return "# SPDX-License-Identifier: Apache-2.0\n" + tomli_w.dumps(self.to_toml())

    def peer(self, node_id: str) -> Peer | None:
        return next((n for n in self.nodes if n.id == node_id), None)

    def user(self, username: str) -> User | None:
        return next((u for u in self.users if u.username == username), None)

    def wins_over(self, other: ClusterConfig) -> bool:
        """Section 10 rule: higher version, then newer updated_at, then greater updated_by."""
        if self.version != other.version:
            return self.version > other.version
        if self.updated_at != other.updated_at:
            return self.updated_at > other.updated_at
        return self.updated_by > other.updated_by


def _decode_dates(d: dict[str, Any]) -> dict[str, Any]:
    # tomllib yields datetime objects for RFC 3339 values; Model.from_dict accepts both.
    return d


def _strip_none(d: dict[str, Any]) -> dict[str, Any]:
    # TOML has no null: absent key means None.
    return {k: (_strip_none(v) if isinstance(v, dict) else v) for k, v in d.items() if v is not None}


class ConfigStore:
    """Owner of node.toml and cluster.toml on disk."""

    def __init__(self, node_path: Path, cluster_path: Path, lock_path: Path | None = None) -> None:
        self.node_path = node_path
        self.cluster_path = cluster_path
        self.lock = FileLock(lock_path or cluster_path.with_suffix(".lock"))
        self._on_change: list[Callable[[ClusterConfig], None]] = []

    def on_change(self, callback: Callable[[ClusterConfig], None]) -> None:
        self._on_change.append(callback)

    def load_node(self) -> NodeConfig:
        with self.node_path.open("rb") as fh:
            return NodeConfig.from_toml(tomllib.load(fh))

    def save_node(self, cfg: NodeConfig) -> None:
        text = "# SPDX-License-Identifier: Apache-2.0\n" + tomli_w.dumps(cfg.to_toml())
        atomic_write(self.node_path, text.encode(), mode=0o640)

    def load_cluster(self) -> ClusterConfig:
        with self.cluster_path.open("rb") as fh:
            return ClusterConfig.from_toml(tomllib.load(fh))

    def cluster_exists(self) -> bool:
        return self.cluster_path.exists()

    def init_cluster(self, cfg: ClusterConfig) -> ClusterConfig:
        with self.lock:
            if self.cluster_path.exists():
                raise ConfigError("cluster.toml already exists")
            state, _ = cm.record_write(cm.State(), cm.flatten(cfg.document()), self._writer(cfg.updated_by))
            cfg.version = 1
            cfg.stamped = True
            cfg.stamps = {p: (1, s[1]) for p, s in state.stamps.items()}
            cfg.tombstones = {}
            cfg.updated_at = utcnow()
            atomic_write(self.cluster_path, cfg.dumps().encode())
        return cfg

    def _writer(self, updated_by: str) -> str:
        if "node:" in (updated_by or ""):
            return cm.writer_node(updated_by)
        try:
            return self.load_node().id
        except (OSError, ConfigError, ValueError):
            return updated_by

    def update_cluster(self, mutate: Callable[[ClusterConfig], None], updated_by: str) -> ClusterConfig:
        """Lock, load, mutate, stamp what changed, bump version, write atomically, notify."""
        with self.lock:
            cfg = self.load_cluster()
            before = cfg.state()
            mutate(cfg)
            state, counter = cm.record_write(
                before, cm.flatten(cfg.document()), self._writer(updated_by), floor=cfg.version
            )
            cfg.stamped = True
            cfg.stamps, cfg.tombstones = state.stamps, state.tombstones
            cfg.version = counter
            cfg.updated_at = utcnow()
            cfg.updated_by = updated_by
            atomic_write(self.cluster_path, cfg.dumps().encode())
        for cb in self._on_change:
            cb(cfg)
        return cfg

    def merge_remote(self, toml_text: str) -> bool:
        """Merge a peer's cluster.toml entry by entry (section 13); True when the local file changed."""
        remote = ClusterConfig.from_toml(tomllib.loads(toml_text))
        with self.lock:
            if self.cluster_path.exists():
                local = self.load_cluster()
                merged = merge_configs(local, remote)
                if merged.digest() == local.digest() and merged.version == local.version:
                    return False
            else:
                merged = remote
            atomic_write(self.cluster_path, merged.dumps().encode())
        for cb in self._on_change:
            cb(merged)
        return True

    def digest(self) -> str:
        """Digest of the replicated entries: two nodes agree exactly when their digests match."""
        return self.load_cluster().digest()

    def cluster_version(self) -> tuple[int, str, str]:
        cfg = self.load_cluster()
        return cfg.version, to_rfc3339(cfg.updated_at), cfg.updated_by


def merge_configs(local: ClusterConfig, remote: ClusterConfig) -> ClusterConfig:
    """The deterministic merge of two cluster files: the same result whichever side computes it."""
    lstate, rstate = local.state(), remote.state()
    merged = cm.merge_states(lstate, rstate)
    digest = merged.digest()
    version = max(local.version, remote.version, merged.clock())
    if digest not in (lstate.digest(), rstate.digest()):
        version += 1  # a state neither side had: a new version, computed alike on both
    head = max((local.updated_at, local.updated_by), (remote.updated_at, remote.updated_by))
    data = cm.unflatten(merged.values, merged.stamps)
    data.update(
        schema_version=max(local.schema_version, remote.schema_version),
        version=version,
        updated_at=to_rfc3339(head[0]),
        updated_by=head[1],
        cluster_id=local.cluster_id,
    )
    cfg = ClusterConfig.from_toml(data)
    cfg.stamped = True
    cfg.stamps, cfg.tombstones = merged.stamps, merged.tombstones
    return cfg
