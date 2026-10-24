# SPDX-License-Identifier: Apache-2.0
"""Node-to-node replication over mTLS (section 13). WP-CORE implements the bodies.

Client: push-on-write, pull-on-start, periodic anti-entropy. Server: the /repl/v1
endpoints served by the collector. Only cluster.toml and the audit log cross.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pelagos.core.audit_log import AuditLog
from pelagos.core.config_store import ConfigStore
from pelagos.domain.cluster import Peer
from pelagos.domain.plan import NodeApplyResult, Plan

REPL_PREFIX = "/repl/v1"


@dataclass(slots=True)
class PeerStatus:
    node_id: str
    reachable: bool
    config_version: int | None = None
    audit_count: int | None = None
    audit_head: str | None = None
    version: str | None = None
    error: str | None = None


class ReplicationError(Exception):
    pass


def client_ssl_context(ca_cert: Path, node_cert: Path, node_key: Path) -> ssl.SSLContext:
    """TLS 1.2+, verify the cluster CA, present the node certificate."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(node_cert), str(node_key))
    return ctx


def server_ssl_context(ca_cert: Path, node_cert: Path, node_key: Path) -> ssl.SSLContext:
    """Server side: client certificates required and chained to the cluster CA."""
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(ca_cert))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(str(node_cert), str(node_key))
    return ctx


class ReplicationClient:
    """Talks to one peer. All calls are blocking and raise ReplicationError."""

    def __init__(self, peer: Peer, ssl_context: ssl.SSLContext, timeout: float = 10.0) -> None:
        self.peer = peer
        self.ssl_context = ssl_context
        self.timeout = timeout

    def status(self) -> PeerStatus:
        raise NotImplementedError("WP-CORE")

    def fetch_config(self) -> dict[str, Any]:
        raise NotImplementedError("WP-CORE")

    def push_config(self, version: int, updated_at: str, updated_by: str, toml_text: str) -> bool:
        raise NotImplementedError("WP-CORE")

    def fetch_audit(self, after_id: str | None, limit: int = 1000) -> tuple[list[dict[str, Any]], str | None]:
        raise NotImplementedError("WP-CORE")

    def push_audit(self, entries: list[dict[str, Any]]) -> int:
        raise NotImplementedError("WP-CORE")

    def apply_plan(self, plan: Plan) -> NodeApplyResult:
        raise NotImplementedError("WP-CORE")

    def rollback_plan(self, plan: Plan) -> NodeApplyResult:
        raise NotImplementedError("WP-CORE")

    def engine_snapshot(self, engine: str) -> dict[str, Any]:
        raise NotImplementedError("WP-CORE")


class Replicator:
    """Drives all peers: pull on start, push on write, anti-entropy (collector side)."""

    def __init__(self, config_store: ConfigStore, audit_log: AuditLog, ssl_context: ssl.SSLContext) -> None:
        self.config_store = config_store
        self.audit_log = audit_log
        self.ssl_context = ssl_context

    def peers(self, self_id: str) -> list[Peer]:
        return [p for p in self.config_store.load_cluster().nodes if p.id != self_id]

    def pull_all(self, self_id: str) -> list[PeerStatus]:
        raise NotImplementedError("WP-CORE")

    def push_config(self, self_id: str) -> list[PeerStatus]:
        raise NotImplementedError("WP-CORE")

    def push_audit(self, self_id: str, after_id: str | None) -> list[PeerStatus]:
        raise NotImplementedError("WP-CORE")
