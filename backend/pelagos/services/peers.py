# SPDX-License-Identifier: Apache-2.0
"""Reads and plan calls on peer nodes over the replication channel (WP-CORE's client).

Every peer call is best effort: a peer that is down, or a client method WP-CORE
has not landed yet, yields None (reads) or a failed NodeApplyResult (writes).
Status answers are cached for `peer_poll_seconds` so list pages stay fast.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from pelagos.core.context import NodeContext
from pelagos.core.replication import PeerStatus, ReplicationClient, ReplicationError, client_ssl_context
from pelagos.domain import Engine, Node, NodeApplyResult, NodeStatus, Peer, Plan, utcnow

log = logging.getLogger(__name__)


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
        self._ssl = None

    # Wiring -------------------------------------------------------------

    def client(self, peer: Peer) -> ReplicationClient | None:
        pki = self.ctx.paths.pki_dir
        if self._ssl is None:
            ca, crt, key = pki / "ca.crt", pki / "node.crt", pki / "node.key"
            if not (ca.exists() and crt.exists() and key.exists()):
                return None
            self._ssl = client_ssl_context(ca, crt, key)
        return ReplicationClient(peer, self._ssl)

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

    def sync(self, peer: Peer) -> dict[str, Any]:
        """Pull now from one peer: adopt its cluster.toml if it wins, merge audit entries after our head."""
        from pelagos.domain import AuditEntry

        client = self.client(peer)
        if client is None:
            raise ReplicationError("node certificate not available")
        remote = client.fetch_config()
        adopted = self.ctx.config_store.merge_remote(remote["toml"])
        _count, head = self.ctx.audit_log.head()
        added = 0
        after = head
        while True:
            entries, after = client.fetch_audit(after)
            added += self.ctx.audit_log.merge([AuditEntry.from_dict(e) for e in entries])
            if not after or not entries:
                break
        self.forget(peer.id)
        return {"config_adopted": bool(adopted), "audit_added": added}

    # Plans --------------------------------------------------------------

    def apply_plan(self, peer: Peer, plan: Plan) -> NodeApplyResult:
        return self._plan_call(peer, plan, "apply_plan")

    def rollback_plan(self, peer: Peer, plan: Plan) -> NodeApplyResult:
        return self._plan_call(peer, plan, "rollback_plan")

    def _plan_call(self, peer: Peer, plan: Plan, method: str) -> NodeApplyResult:
        client = self.client(peer)
        if client is None:
            return NodeApplyResult(node_id=peer.id, ok=False, message="node certificate not available")
        try:
            return getattr(client, method)(plan)
        except NotImplementedError:
            return NodeApplyResult(
                node_id=peer.id, ok=False, message="remote plan apply is not available yet"
            )
        except (ReplicationError, OSError) as exc:
            return NodeApplyResult(node_id=peer.id, ok=False, message=f"{peer.name}: {exc}")
