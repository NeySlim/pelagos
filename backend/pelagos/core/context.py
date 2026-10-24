# SPDX-License-Identifier: Apache-2.0
"""NodeContext: everything a request handler or collector task needs from the node, built once at start."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pelagos.auth.rate_limit import RateLimiter
from pelagos.auth.sessions import SessionStore
from pelagos.core.audit_log import AuditLog
from pelagos.core.config_store import ClusterConfig, ConfigStore, NodeConfig
from pelagos.core.paths import Paths
from pelagos.core.plans import PlanStore
from pelagos.core.secrets import SecretBox
from pelagos.domain.cluster import Node, NodeStatus
from pelagos.domain.common import utcnow


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
    replication_state: str = "ready"  # "ready" | "syncing"
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def build(cls, paths: Paths) -> NodeContext:
        store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")
        node = store.load_node()
        cluster = store.load_cluster()
        settings = cluster.settings
        secrets = SecretBox.from_file(paths.master_key) if paths.master_key.exists() else None
        return cls(
            paths=paths,
            node=node,
            config_store=store,
            audit_log=AuditLog(paths.audit_log, paths.locks_dir / "audit.lock"),
            plan_store=PlanStore(int(settings.get("plan_ttl_seconds", 600))),
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
