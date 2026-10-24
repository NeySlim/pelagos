# SPDX-License-Identifier: Apache-2.0
"""Peers poller: liveness through GET /repl/v1/status, engine snapshots, serial and config divergence.

The poller talks to peers through a PeerClient (the mTLS ReplicationClient in production, a fake in
tests). A peer's engine snapshot is the payload SeriesStore.engine_snapshot() builds on that node:
{"node_id", "engine", "ts", "kinds": {kind: {"ts", "payload"}}}; the rows are copied locally under
the peer's node id so the UI on this node can show every node's last known state.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from pelagos.collector import rules
from pelagos.collector.pollers import PollOutcome
from pelagos.collector.series import SeriesStore
from pelagos.core.replication import PeerStatus, ReplicationClient, ReplicationError
from pelagos.domain import AlertKind, Engine, Node, NodeStatus, Peer

log = logging.getLogger(__name__)

KINDS = frozenset(
    {AlertKind.PEER_OFFLINE.value, AlertKind.SERIAL_DIVERGENCE.value, AlertKind.CONFIG_DIVERGENCE.value}
)
OFFLINE_AFTER = 3
# Zone kinds whose serial must follow the primary's (section 15, serial_divergence).
TRANSFERRED_KINDS = frozenset({"secondary", "mirror"})


class PeerClient(Protocol):
    def status(self, peer: Peer) -> PeerStatus: ...
    def engine_snapshot(self, peer: Peer, engine: str) -> dict[str, Any]: ...


class ReplicationPeerClient:
    """PeerClient over WP-CORE's ReplicationClient, one client per peer, built lazily."""

    def __init__(self, ssl_context: Any, timeout: float = 10.0) -> None:
        self.ssl_context = ssl_context
        self.timeout = timeout
        self._clients: dict[str, ReplicationClient] = {}

    def _client(self, peer: Peer) -> ReplicationClient:
        client = self._clients.get(peer.id)
        if client is None or client.peer.url != peer.url:
            client = ReplicationClient(peer, self.ssl_context, self.timeout)
            self._clients[peer.id] = client
        return client

    def status(self, peer: Peer) -> PeerStatus:
        return self._client(peer).status()

    def engine_snapshot(self, peer: Peer, engine: str) -> dict[str, Any]:
        return self._client(peer).engine_snapshot(engine)


def peer_engines(peer: Peer) -> list[str]:
    mods = peer.modules
    return [
        e.value
        for e, on in (
            (Engine.BIND, mods.bind),
            (Engine.KEA4, mods.kea4),
            (Engine.KEA6, mods.kea6),
            (Engine.D2, mods.d2),
        )
        if on
    ]


class PeersPoller:
    def __init__(
        self,
        client: PeerClient | None,
        self_id: str,
        peers: Callable[[], list[Peer]],
        store: SeriesStore,
        settings: dict[str, Any],
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.client = client
        self.self_id = self_id
        self.peers = peers
        self.store = store
        self.settings = settings
        self.clock = clock
        self.failures: dict[str, int] = {}
        self.divergent_since: dict[tuple[str, str, str], int] = {}
        self._unimplemented_logged = False

    def poll(self) -> PollOutcome:
        out = PollOutcome(kinds=KINDS)
        now = int(self.clock())
        peers = [p for p in self.peers() if p.id != self.self_id]
        known_nodes = {self.self_id, *(p.id for p in peers)}
        for snap_node in self.store.snapshot_nodes():
            if snap_node not in known_nodes:
                self.store.delete_snapshots(snap_node)
        for peer in peers:
            self._poll_peer(peer, now, out)
        self._serial_divergence(now, out)
        self._config_divergence(out)
        return out

    def _poll_peer(self, peer: Peer, now: int, out: PollOutcome) -> None:
        if self.client is None:
            return
        try:
            status = self.client.status(peer)
        except NotImplementedError:
            if not self._unimplemented_logged:
                log.info("replication client not available yet; peer liveness is not polled")
                self._unimplemented_logged = True
            return
        except (ReplicationError, OSError) as exc:
            status = PeerStatus(node_id=peer.id, reachable=False, error=str(exc))
        if not status.reachable:
            self.failures[peer.id] = self.failures.get(peer.id, 0) + 1
            failures = self.failures[peer.id]
            if failures >= OFFLINE_AFTER:
                out.alerts.append(rules.peer_offline(peer.id, peer.name, failures, status.error))
            node = Node(peer=peer, status=NodeStatus.OFFLINE, error=status.error)
            last = self.store.snapshot(peer.id, "node", "status")
            if last is not None:
                node.last_seen = datetime.fromtimestamp(last[0], tz=UTC)
                node.version = last[1].get("version")
                node.config_version = last[1].get("config_version")
                node.audit_count = last[1].get("audit_count")
            out.events.append(("nodes", "status", node))
            return
        self.failures[peer.id] = 0
        self.store.write_snapshot(
            peer.id,
            "node",
            "status",
            now,
            {
                "version": status.version,
                "config_version": status.config_version,
                "audit_count": status.audit_count,
                "audit_head": status.audit_head,
            },
        )
        out.events.append(
            (
                "nodes",
                "status",
                Node(
                    peer=peer,
                    status=NodeStatus.ONLINE,
                    version=status.version,
                    config_version=status.config_version,
                    audit_count=status.audit_count,
                    last_seen=datetime.fromtimestamp(now, tz=UTC),
                ),
            )
        )
        for engine in peer_engines(peer):
            try:
                snapshot = self.client.engine_snapshot(peer, engine)
            except NotImplementedError:
                return
            except (ReplicationError, OSError) as exc:
                log.debug("snapshot %s from %s failed: %s", engine, peer.name, exc)
                continue
            for kind, entry in (snapshot.get("kinds") or {}).items():
                if isinstance(entry, dict) and "payload" in entry:
                    self.store.write_snapshot(
                        peer.id, engine, kind, int(entry.get("ts") or now), entry["payload"]
                    )

    def _serial_divergence(self, now: int, out: PollOutcome) -> None:
        """Compare secondary and mirror copies of a zone with the primary; alert after the grace period."""
        threshold = int(self.settings.get("alerts_serial_divergence_seconds", 900))
        zones: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
        for snap in self.store.snapshots(engine=Engine.BIND.value):
            if snap["kind"] != "zones":
                continue
            for st in snap["payload"]:
                key = (st.get("zone"), st.get("view", "_default"))
                zones.setdefault(key, {})[snap["node_id"]] = st
        active: set[tuple[str, str, str]] = set()
        for (zone, view), by_node in zones.items():
            primary = next((n for n, st in by_node.items() if st.get("kind") == "primary"), None)
            reference = by_node[primary].get("serial") if primary else None
            for node_id, st in by_node.items():
                serial = st.get("serial")
                divergent = (
                    reference is not None
                    and st.get("kind") in TRANSFERRED_KINDS
                    and serial is not None
                    and serial != reference
                )
                if node_id != self.self_id:
                    self.store.write_serial_if_changed(now, zone, view, node_id, serial, divergent)
                if not divergent:
                    continue
                key = (zone, view, node_id)
                active.add(key)
                since = self.divergent_since.setdefault(key, now)
                if now - since >= threshold:
                    out.alerts.append(
                        rules.serial_divergence(node_id, zone, view, serial, reference, since, now)
                    )
        for key in list(self.divergent_since):
            if key not in active:
                del self.divergent_since[key]

    def _config_divergence(self, out: PollOutcome) -> None:
        """Compare the normalized config hashes (per-node keys removed) of every node running Kea.

        Raw config-hash-get values always differ between HA peers (this-server-name at least), so
        they are only compared when some node did not publish a normalized hash.
        """
        for engine in (Engine.KEA4.value, Engine.KEA6.value):
            payloads: dict[str, dict[str, Any]] = {}
            for snap in self.store.snapshots(engine=engine):
                if snap["kind"] == "config_hash":
                    payloads[snap["node_id"]] = snap["payload"] or {}
            field = "normalized" if all(p.get("normalized") for p in payloads.values()) else "hash"
            hashes: dict[str, str | None] = {n: p.get(field) for n, p in payloads.items()}
            distinct = {h for h in hashes.values() if h}
            if len(distinct) > 1:
                out.alerts.append(rules.config_divergence(engine, hashes))
