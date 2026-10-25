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

from pelagos.collector import kea_shared, rules
from pelagos.collector.pollers import PollOutcome
from pelagos.collector.series import SeriesStore
from pelagos.collector.snapshots import CACHE_KIND
from pelagos.core.replication import PeerStatus, ReplicationClient, ReplicationError
from pelagos.domain import Alert, AlertKind, Engine, Node, NodeStatus, Peer

log = logging.getLogger(__name__)

KINDS = frozenset(
    {
        AlertKind.PEER_OFFLINE.value,
        AlertKind.SERIAL_DIVERGENCE.value,
        AlertKind.CONFIG_DIVERGENCE.value,
        AlertKind.HA_BACKUP_OUT_OF_SYNC.value,
    }
)
OFFLINE_AFTER = 3
# A backup's lease count may trail its active server's while updates are in flight: this long first.
BACKUP_GRACE_SECONDS = 300
# Zone kinds whose serial must follow the primary's (section 15, serial_divergence).
TRANSFERRED_KINDS = frozenset({"secondary", "mirror"})


class PeerClient(Protocol):
    def status(self, peer: Peer) -> PeerStatus: ...
    def engine_snapshot(self, peer: Peer, engine: str) -> dict[str, Any]: ...


class Liveness(Protocol):
    """What the replicator knows from its own exchanges (core.replication.Replicator)."""

    failures: dict[str, int]

    def peer_statuses(self) -> list[PeerStatus]: ...


def owned(alert: Alert) -> bool:
    """Alerts this poller reconciles: Kea file divergence belongs to the local Kea pollers."""
    return not (alert.kind is AlertKind.CONFIG_DIVERGENCE and alert.subject.endswith(":config-file"))


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
        return self._client(peer).engine_snapshot(engine, kind=CACHE_KIND)


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
        liveness: Liveness | None = None,
    ) -> None:
        self.client = client
        # With a replicator, liveness and failure counts come from its exchanges (no extra status call).
        self.liveness = liveness
        self.self_id = self_id
        self.peers = peers
        self.store = store
        self.settings = settings
        self.clock = clock
        self.failures: dict[str, int] = {}
        self.divergent_since: dict[tuple[str, str, str], int] = {}
        self.backup_since: dict[tuple[str, str], int] = {}
        self._unimplemented_logged = False
        # Last node state sent per peer: (status, version, config_version, audit_count, error).
        self._node_seen: dict[str, tuple[Any, ...]] = {}

    def poll(self) -> PollOutcome:
        out = PollOutcome(kinds=KINDS, where=owned)
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
        self._backup_sync(now, out)
        return out

    def _status(self, peer: Peer) -> tuple[PeerStatus, int] | None:
        """(status, consecutive failed polls), or None when liveness is not known yet."""
        if self.liveness is not None:
            status = next((s for s in self.liveness.peer_statuses() if s.node_id == peer.id), None)
            if status is None:
                return None
            return status, self.liveness.failures.get(peer.id, 0)
        if self.client is None:
            return None
        try:
            status = self.client.status(peer)
        except NotImplementedError:
            if not self._unimplemented_logged:
                log.info("replication client not available yet; peer liveness is not polled")
                self._unimplemented_logged = True
            return None
        except (ReplicationError, OSError) as exc:
            status = PeerStatus(node_id=peer.id, reachable=False, error=str(exc))
        if status.reachable:
            self.failures[peer.id] = 0
        else:
            self.failures[peer.id] = self.failures.get(peer.id, 0) + 1
        return status, self.failures[peer.id]

    def _poll_peer(self, peer: Peer, now: int, out: PollOutcome) -> None:
        known = self._status(peer)
        if known is None:
            return
        status, failures = known
        if status.code == "schema_mismatch":
            out.alerts.append(rules.schema_mismatch(peer.id, peer.name, status.error))
        if not status.reachable:
            if failures >= OFFLINE_AFTER:
                out.alerts.append(rules.peer_offline(peer.id, peer.name, failures, status.error))
            node = Node(peer=peer, status=NodeStatus.OFFLINE, error=status.error)
            last = self.store.snapshot(peer.id, "node", "status")
            if last is not None:
                node.last_seen = datetime.fromtimestamp(last[0], tz=UTC)
                node.version = last[1].get("version")
                node.config_version = last[1].get("config_version")
                node.audit_count = last[1].get("audit_count")
            self._node_event(node, out)
            return
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
        self._node_event(
            Node(
                peer=peer,
                status=NodeStatus.ONLINE,
                version=status.version,
                config_version=status.config_version,
                audit_count=status.audit_count,
                last_seen=datetime.fromtimestamp(now, tz=UTC),
            ),
            out,
        )
        if self.client is None:
            return
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

    def _node_event(self, node: Node, out: PollOutcome) -> None:
        """`nodes`/`status` when a peer comes, goes or changes; `system`/`replication` when its
        configuration version or audit count moved (the change reached it). First sightings only
        record, a steady peer sends nothing."""
        seen = (node.status, node.version, node.config_version, node.audit_count, node.error)
        before = self._node_seen.get(node.peer.id)
        self._node_seen[node.peer.id] = seen
        if before == seen:
            return
        out.events.append(("nodes", "status", node, {"key": f"nodes:status:{node.peer.id}"}))
        if before is None or node.status is not NodeStatus.ONLINE:
            return
        if (node.config_version, node.audit_count) != (before[2], before[3]):
            data = {
                "node_id": node.peer.id,
                "config_version": node.config_version,
                "audit_count": node.audit_count,
                "config_changed": node.config_version != before[2],
            }
            out.events.append(("system", "replication", data, {"key": f"system:replication:{node.peer.id}"}))

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
        """Compare what the Kea servers of each HA relationship must share (collector.kea_shared):
        subnets, pools, reservations, options, classes and the peers list, never per-server keys.

        A node that publishes no relationship hashes (an older version) falls back to the normalized
        hash of the whole configuration, then to the raw config-hash-get, across every node."""
        for engine in (Engine.KEA4.value, Engine.KEA6.value):
            payloads: dict[str, dict[str, Any]] = {}
            for snap in self.store.snapshots(engine=engine):
                if snap["kind"] == "config_hash":
                    payloads[snap["node_id"]] = snap["payload"] or {}
            if payloads and all("relationships" in p for p in payloads.values()):
                hashes, groups = kea_shared.divergent(payloads)
                if hashes:
                    out.alerts.append(rules.config_divergence(engine, hashes, groups))
                continue
            field = "normalized" if all(p.get("normalized") for p in payloads.values()) else "hash"
            old: dict[str, str | None] = {n: p.get(field) for n, p in payloads.items()}
            if len({h for h in old.values() if h}) > 1:
                out.alerts.append(rules.config_divergence(engine, old))

    def _backup_sync(self, now: int, out: PollOutcome) -> None:
        """Compare each Kea HA backup's lease count with its primary's (an active server's otherwise):
        a backup takes every lease update, so a lasting gap means it stopped receiving them."""
        active: set[tuple[str, str]] = set()
        for engine in (Engine.KEA4, Engine.KEA6):
            ha: dict[str, dict[str, Any]] = {}
            leases: dict[str, int] = {}
            for snap in self.store.snapshots(engine=engine.value):
                payload = snap["payload"]
                if snap["kind"] == "ha" and isinstance(payload, dict) and payload.get("enabled", True):
                    ha[snap["node_id"]] = payload
                elif snap["kind"] == "utilization" and isinstance(payload, list):
                    leases[snap["node_id"]] = sum(int(r.get("assigned") or 0) for r in payload)
            # The primary is the reference; an active server in a normal state stands in for it.
            order = {"primary": 0, "secondary": 1, "standby": 1}
            candidates = sorted(
                (n for n, h in ha.items() if h.get("role") in order and n in leases),
                key=lambda n: (order[ha[n]["role"]], ha[n].get("state") not in rules.HA_NORMAL_STATES),
            )
            reference = (candidates[0], ha[candidates[0]]) if candidates else None
            if reference is None:
                continue
            ref_node, ref_ha = reference
            for node_id, st in ha.items():
                if st.get("role") != "backup" or node_id not in leases:
                    continue
                if not rules.backup_diverges(leases[node_id], leases[ref_node]):
                    continue
                key = (engine.value, node_id)
                active.add(key)
                since = self.backup_since.setdefault(key, now)
                if now - since >= BACKUP_GRACE_SECONDS:
                    out.alerts.append(
                        rules.ha_backup_out_of_sync(
                            node_id,
                            engine,
                            str(st.get("server_name") or node_id),
                            str(ref_ha.get("server_name") or ref_node),
                            leases[node_id],
                            leases[ref_node],
                            since,
                        )
                    )
        for key in list(self.backup_since):
            if key not in active:
                del self.backup_since[key]
