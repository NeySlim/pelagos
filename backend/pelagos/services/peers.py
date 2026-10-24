# SPDX-License-Identifier: Apache-2.0
"""Reads and plan calls on peer nodes over the replication channel (WP-CORE's client).

Every peer call is best effort: a peer that is down, or a client method WP-CORE
has not landed yet, yields None (reads) or a failed NodeApplyResult (writes).
Status answers are cached for `peer_poll_seconds` so list pages stay fast.
"""

from __future__ import annotations

import logging
import ssl
import threading
import time
from typing import Any

from pelagos.core.context import NodeContext
from pelagos.core.replication import (
    UNREACHABLE,
    PeerStatus,
    ReplicationClient,
    ReplicationError,
    Replicator,
    client_ssl_context,
    node_tls_files,
)
from pelagos.domain import Engine, Node, NodeApplyResult, NodeStatus, Peer, Plan, PlanScope, utcnow

log = logging.getLogger(__name__)

# A peer applies a plan synchronously: engine plans validate and reload (seconds to minutes),
# installer plans install packages and restart services (many minutes). Settings may override.
ENGINE_PLAN_TIMEOUT = 300.0
INSTALLER_PLAN_TIMEOUT = 1800.0
SYNC_TIMEOUT = 120.0
INSTALLER_SCOPES = (PlanScope.INSTALL, PlanScope.IMPORT, PlanScope.SECURITY)


def plan_timeout(plan: Plan, settings: dict[str, Any] | None = None) -> float:
    """How long a peer may take to answer a plan apply or rollback before the call fails."""
    settings = settings or {}
    if plan.scope in INSTALLER_SCOPES:
        return float(settings.get("installer_plan_timeout_seconds", INSTALLER_PLAN_TIMEOUT))
    return float(settings.get("peer_plan_timeout_seconds", ENGINE_PLAN_TIMEOUT))


class PeerGateway:
    def __init__(self, ctx: NodeContext, cache_seconds: float | None = None) -> None:
        self.ctx = ctx
        self.cache_seconds = (
            cache_seconds
            if cache_seconds is not None
            else float(ctx.settings().get("collector", {}).get("peer_poll_seconds", 30))
        )
        self._status: dict[str, tuple[float, PeerStatus]] = {}
        self._lock = threading.Lock()
        self._ssl: ssl.SSLContext | None = None

    # Wiring -------------------------------------------------------------

    def client_context(self) -> ssl.SSLContext | None:
        if self._ssl is None:
            ca, crt, key = node_tls_files(self.ctx.paths)
            if not (ca.exists() and crt.exists() and key.exists()):
                return None
            self._ssl = client_ssl_context(ca, crt, key)
        return self._ssl

    def client(self, peer: Peer) -> ReplicationClient | None:
        context = self.client_context()
        return ReplicationClient(peer, context) if context is not None else None

    def _client_with_timeout(self, peer: Peer, timeout: float) -> ReplicationClient | None:
        client = self.client(peer)
        if client is not None and hasattr(client, "timeout"):
            client.timeout = timeout
        return client

    def peers(self) -> list[Peer]:
        return [p for p in self.ctx.cluster().nodes if p.id != self.ctx.node.id]

    def peer(self, node_id: str) -> Peer | None:
        return next((p for p in self.peers() if p.id == node_id), None)

    def peers_running(self, engine: Engine) -> list[Peer]:
        return [p for p in self.peers() if getattr(p.modules, engine.value, False)]

    # Status -------------------------------------------------------------

    def status(self, peer: Peer) -> PeerStatus:
        now = time.monotonic()
        with self._lock:
            cached = self._status.get(peer.id)
            if cached and now - cached[0] < self.cache_seconds:
                return cached[1]
        status = self._fetch_status(peer)
        with self._lock:
            self._status[peer.id] = (now, status)
        return status

    def _fetch_status(self, peer: Peer) -> PeerStatus:
        client = self.client(peer)
        if client is None:
            return PeerStatus(peer.id, False, error="node certificate not available")
        try:
            return client.status()
        except NotImplementedError:
            return PeerStatus(peer.id, False, error="replication client not available")
        except (ReplicationError, OSError) as exc:
            return PeerStatus(peer.id, False, error=str(exc))

    def node(self, peer: Peer) -> Node:
        status = self.status(peer)
        return Node(
            peer=peer,
            is_self=False,
            status=NodeStatus.ONLINE if status.reachable else NodeStatus.OFFLINE,
            version=status.version,
            config_version=status.config_version,
            audit_count=status.audit_count,
            last_seen=utcnow() if status.reachable else None,
            error=status.error,
        )

    def forget(self, node_id: str | None = None) -> None:
        with self._lock:
            if node_id is None:
                self._status.clear()
            else:
                self._status.pop(node_id, None)

    # Engine reads -------------------------------------------------------

    def snapshot(
        self, peer: Peer, engine: Engine, kind: str = "summary", params: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        """None when the peer cannot answer; a dict with "error" when its read failed."""
        client = self.client(peer)
        if client is None:
            return None
        params = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            try:
                return client.engine_snapshot(engine.value, kind=kind, params=params)
            except TypeError:
                # Client without the kind/params extension (contracts-changes.md): summary only.
                return client.engine_snapshot(engine.value) if kind == "summary" else None
        except NotImplementedError:
            return None
        except (ReplicationError, OSError) as exc:
            log.warning("snapshot %s/%s from %s failed: %s", engine.value, kind, peer.name, exc)
            return None

    # Sync ---------------------------------------------------------------

    def replicator(self) -> Replicator | None:
        """The collector's Replicator on this node's certificate; None before enrollment. Its clients
        come from `client()` so every peer call of the web process goes through one place."""
        context = self.client_context()
        if context is None:
            return None
        c = self.ctx
        replicator = Replicator(c.config_store, c.audit_log, context, self_id=c.node.id, timeout=SYNC_TIMEOUT)
        replicator.client = lambda peer: self._client_with_timeout(peer, SYNC_TIMEOUT)  # type: ignore[method-assign,assignment,return-value]
        return replicator

    def sync(self, peer: Peer) -> PeerStatus:
        """Replicator.sync_peer: exchange cluster.toml and audit entries both ways with one peer."""
        replicator = self.replicator()
        if replicator is None:
            return PeerStatus(peer.id, False, error="node certificate not available")
        status = replicator.sync_peer(peer)
        with self._lock:
            self._status[peer.id] = (time.monotonic(), status)
        return status

    # Plans --------------------------------------------------------------

    def apply_plan(self, peer: Peer, plan: Plan) -> NodeApplyResult:
        return self._plan_call(peer, plan, "apply_plan")

    def rollback_plan(self, peer: Peer, plan: Plan) -> NodeApplyResult:
        return self._plan_call(peer, plan, "rollback_plan")

    def _plan_call(self, peer: Peer, plan: Plan, method: str) -> NodeApplyResult:
        try:
            settings = self.ctx.settings()
        except Exception:  # an unreadable cluster.toml must not block the call: defaults apply
            settings = {}
        client = self._client_with_timeout(peer, plan_timeout(plan, settings))
        if client is None:
            return NodeApplyResult(node_id=peer.id, ok=False, message="node certificate not available")
        try:
            return getattr(client, method)(plan)
        except NotImplementedError:
            return NodeApplyResult(
                node_id=peer.id, ok=False, message="remote plan apply is not available yet"
            )
        except ReplicationError as exc:
            # No answer (transport) or a server error: the peer may have applied the plan anyway.
            unknown = (exc.status is None and exc.code != UNREACHABLE) or (exc.status or 0) >= 500
            return NodeApplyResult(
                node_id=peer.id, ok=False, message=f"{peer.name}: {exc}", outcome_unknown=unknown
            )
        except OSError as exc:
            return NodeApplyResult(
                node_id=peer.id, ok=False, message=f"{peer.name}: {exc}", outcome_unknown=True
            )
