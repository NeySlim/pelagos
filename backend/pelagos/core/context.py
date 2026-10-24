# SPDX-License-Identifier: Apache-2.0
"""NodeContext: everything a request handler or collector task needs from the node, built once at start."""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pelagos.auth.rate_limit import RateLimiter
from pelagos.auth.sessions import SessionStore
from pelagos.core.audit_log import AuditLog
from pelagos.core.config_store import ClusterConfig, ConfigStore, NodeConfig, atomic_write
from pelagos.core.paths import Paths
from pelagos.core.plans import PlanStore
from pelagos.core.secrets import SecretBox
from pelagos.core.signals import EVENT_AUDIT, EVENT_CONFIG, signal_collector
from pelagos.domain.cluster import Node, NodeStatus
from pelagos.domain.common import utcnow

REPL_READY = "ready"
REPL_SYNCING = "syncing"


# A `syncing` state older than this is stale (a collector killed mid-pull): the node is writable again.
SYNCING_STALE_SECONDS = 300
# A live writer refreshes the file this often while it stays `syncing`, so long pulls never look stale.
SYNCING_HEARTBEAT_SECONDS = 60


def read_replication_state(paths: Paths) -> str:
    """The collector writes the state file; without one (no collector, tests) the node is writable.

    `syncing` counts only while its writer process lives and for at most SYNCING_STALE_SECONDS.
    """
    path = paths.replication_state_file
    try:
        words = path.read_text().split()
        age = time.time() - path.stat().st_mtime
    except OSError:
        return REPL_READY
    if not words or words[0] != REPL_SYNCING or age > SYNCING_STALE_SECONDS:
        return REPL_READY
    # The pid means something only in the writer's own pid namespace (compose runs two containers).
    same_host = len(words) > 2 and words[2] == socket.gethostname()
    if same_host and words[1].isdigit() and not _alive(int(words[1])):
        return REPL_READY
    return REPL_SYNCING


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # another user's process (the collector runs as pelagos)
    return True


def write_replication_state(paths: Paths, state: str) -> None:
    paths.run.mkdir(parents=True, exist_ok=True, mode=0o750)
    atomic_write(
        paths.replication_state_file, f"{state} {os.getpid()} {socket.gethostname()}\n".encode(), mode=0o644
    )


@dataclass(slots=True)
class NodeContext:
    paths: Paths
    node: NodeConfig
    config_store: ConfigStore
    audit_log: AuditLog
    plan_store: PlanStore
    sessions: SessionStore
    login_limiter: RateLimiter
    secrets: SecretBox | None = None
    started_at: datetime = field(default_factory=utcnow)
    replication_state_override: str | None = None  # tests and single-process runs; None reads the file
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def replication_state(self) -> str:
        """`ready` or `syncing` (section 13), as published by the collector."""
        if self.replication_state_override is not None:
            return self.replication_state_override
        return read_replication_state(self.paths)

    @replication_state.setter
    def replication_state(self, value: str | None) -> None:
        # Kept assignable so callers written against the former plain field still work.
        self.replication_state_override = value

    @classmethod
    def build(cls, paths: Paths) -> NodeContext:
        store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")
        node = store.load_node()
        cluster = store.load_cluster()
        settings = cluster.settings
        secrets = SecretBox.from_file(paths.master_key) if paths.master_key.exists() else None
        audit_log = AuditLog(paths.audit_log, paths.locks_dir / "audit.lock")
        # Push on write: every local write pokes the collector, which replicates within seconds.
        store.on_change(lambda _cfg: signal_collector(paths.collector_sock, EVENT_CONFIG))
        audit_log.on_append(lambda _entry: signal_collector(paths.collector_sock, EVENT_AUDIT))
        return cls(
            paths=paths,
            node=node,
            config_store=store,
            audit_log=audit_log,
            plan_store=PlanStore(
                int(settings.get("plan_ttl_seconds", 600)), tombstone_path=paths.plan_tombstones
            ),
            sessions=SessionStore(
                int(settings.get("session_ttl_seconds", 43200)),
                int(settings.get("session_idle_seconds", 1800)),
            ),
            login_limiter=RateLimiter(int(settings.get("login_rate_limit_per_minute", 10))),
            secrets=secrets,
        )

    def cluster(self) -> ClusterConfig:
        return self.config_store.load_cluster()

    def settings(self) -> dict[str, Any]:
        return self.cluster().settings

    def get_secret(self, name: str) -> str | None:
        token = self.cluster().secrets.get(name)
        if token is None or self.secrets is None:
            return None
        return self.secrets.decrypt(name, token)

    def self_node(self) -> Node:
        peer = self.cluster().peer(self.node.id)
        if peer is None:
            from pelagos.domain.cluster import Peer

            peer = Peer(
                id=self.node.id,
                name=self.node.name,
                url=self.node.replication_url,
                web_url=self.node.web_url,
                cert_fingerprint="",
                modules=self.node.modules,
            )
        from pelagos import __version__

        cfg = self.cluster()
        count, _ = self.audit_log.head()
        return Node(
            peer=peer,
            is_self=True,
            status=NodeStatus.ONLINE,
            version=__version__,
            config_version=cfg.version,
            audit_count=count,
            last_seen=utcnow(),
        )
