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

from pelagos.collector import kea_shared, rules, zone_config
from pelagos.collector.pollers import PollOutcome
from pelagos.collector.series import SeriesStore
from pelagos.collector.snapshots import CACHE_KIND
from pelagos.core import clock as clock_mod
from pelagos.core import settings_registry as reg
from pelagos.core.replication import PeerStatus, ReplicationClient, ReplicationError
from pelagos.domain import Alert, AlertKind, Engine, Node, NodeStatus, Peer

log = logging.getLogger(__name__)

KINDS = frozenset(
    {
        AlertKind.PEER_OFFLINE.value,
        AlertKind.SERIAL_DIVERGENCE.value,
        AlertKind.CONFIG_DIVERGENCE.value,
        AlertKind.HA_BACKUP_OUT_OF_SYNC.value,
        AlertKind.CLOCK_SKEW.value,
        AlertKind.CLOCK_UNSYNCHRONIZED.value,
    }
)
OFFLINE_AFTER = 3
# A backup's lease count may trail its active server's while updates are in flight: this long first.
BACKUP_GRACE_SECONDS = 300
# Each node snapshots its Kea config once per engine poll (60 s) and peers copy it once per peer poll:
# right after a plan, the nodes' hashes disagree for up to that long without any real divergence.
CONFIG_DIVERGENCE_GRACE_SECONDS = 120
# Zone kinds whose serial must follow the primary's (section 15, serial_divergence).
TRANSFERRED_KINDS = frozenset({"secondary", "mirror"})


def backup_reference(
    backup: dict[str, Any], ha: dict[str, dict[str, Any]], leases: dict[str, int]
) -> tuple[str, dict[str, Any]] | None:
    """The server a backup's lease count is compared with: the primary of its relationship (an
    active server in a normal state stands in for it). A hub, whose count covers several
    relationships, is never a reference."""
    order = {"primary": 0, "secondary": 1, "standby": 1}
    names = {p.get("name") for p in backup.get("peers") or [] if isinstance(p, dict)}
    candidates = sorted(
        (
            n
            for n, h in ha.items()
            if h.get("role") in order
            and n in leases
            and not h.get("other_relationships")
            and (not names or h.get("server_name") in names)
        ),
        key=lambda n: (order[ha[n]["role"]], ha[n].get("state") not in rules.HA_NORMAL_STATES),
    )
    return (candidates[0], ha[candidates[0]]) if candidates else None


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
        self.config_since: dict[str, int] = {}
        self.zone_config_since: dict[str, int] = {}
        self._unimplemented_logged = False
        # Last node state sent per peer: (status, version, config_version, audit_count, error).
        self._node_seen: dict[str, tuple[Any, ...]] = {}
        # This node's NTP state (core.clock); tests replace it.
        self.ntp: Callable[[], dict[str, Any]] = clock_mod.NTP.get
        self._self_ntp: dict[str, Any] | None = None
        self._self_name: str | None = None

    def poll(self) -> PollOutcome:
        out = PollOutcome(kinds=KINDS, where=owned)
        now = int(self.clock())
        everyone = self.peers()
        peers = [p for p in everyone if p.id != self.self_id]
        self._self_clock(next((p.name for p in everyone if p.id == self.self_id), self.self_id), now, out)
        known_nodes = {self.self_id, *(p.id for p in peers)}
        for snap_node in self.store.snapshot_nodes():
            if snap_node not in known_nodes:
                self.store.delete_snapshots(snap_node)
        for peer in peers:
            self._poll_peer(peer, now, out)
        self._serial_divergence(now, out)
        self._config_divergence(now, out)
        self._zone_config_divergence(now, out)
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
            # The skew that may have terminated HA stays raised while the node is out of reach.
            clock = self.store.snapshot(peer.id, "node", "clock")
            if clock is not None and isinstance(clock[1], dict) and clock[1].get("offset") is not None:
                payload = clock[1]
                self._skew_alert(
                    peer,
                    payload["offset"],
                    payload.get("uncertainty") or 0.0,
                    payload.get("ntp"),
                    out,
                    clock[0],
                )
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
        self._peer_clock(peer, status, now, out)
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

    def _self_clock(self, name: str, now: int, out: PollOutcome) -> None:
        """This node's NTP state as the "node"/"clock" snapshot (offset 0: the reference)."""
        try:
            ntp = self.ntp()
        except Exception as exc:  # a broken time tool must not stop the peers poll
            log.debug("ntp state failed: %s", exc)
            return
        self._self_ntp = ntp
        self._self_name = name
        payload = {"name": name, "offset": 0.0, "uncertainty": 0.0, "ntp": ntp, "reference": self.self_id}
        self.store.write_snapshot(self.self_id, "node", "clock", now, payload)
        if rules.ntp_unsynchronized(ntp):
            out.alerts.append(rules.clock_unsynchronized(self.self_id, name, ntp))

    def _peer_clock(self, peer: Peer, status: PeerStatus, now: int, out: PollOutcome) -> None:
        """clock_skew from the offset the status exchange measured, clock_unsynchronized from the
        NTP state the peer reports. Thresholds: checks.clock_skew_warning/critical_seconds."""
        if rules.ntp_unsynchronized(status.ntp):
            out.alerts.append(rules.clock_unsynchronized(peer.id, peer.name, status.ntp or {}))
        if status.clock_offset is None:
            return
        uncertainty = status.clock_uncertainty or 0.0
        payload = {
            "name": peer.name,
            "offset": round(status.clock_offset, 3),
            "uncertainty": round(uncertainty, 3),
            "ntp": status.ntp,
            "reference": self.self_id,
        }
        self.store.write_snapshot(peer.id, "node", "clock", now, payload)
        self._skew_alert(peer, status.clock_offset, uncertainty, status.ntp, out)

    def _skew_alert(
        self,
        peer: Peer,
        offset: float,
        uncertainty: float,
        ntp: dict[str, Any] | None,
        out: PollOutcome,
        measured_at: int | None = None,
    ) -> None:
        """clock_skew when the offset passes a threshold; `measured_at` marks a last known reading
        of a node out of reach."""
        severity = clock_mod.skew_severity(clock_mod.skew_floor(offset, uncertainty), self.settings)
        if severity is None:
            return
        mine = self._self_ntp
        suspect = None
        if rules.ntp_unsynchronized(ntp) and not rules.ntp_unsynchronized(mine):
            suspect = peer.id
        elif rules.ntp_unsynchronized(mine) and not rules.ntp_unsynchronized(ntp):
            suspect = self.self_id
        thresholds = {
            "warning_seconds": float(reg.get(self.settings, "checks.clock_skew_warning_seconds")),
            "critical_seconds": float(reg.get(self.settings, "checks.clock_skew_critical_seconds")),
        }
        alert = rules.clock_skew(
            peer.id,
            peer.name,
            self._self_name or self.self_id,
            offset,
            uncertainty,
            severity,
            thresholds,
            suspect,
        )
        if measured_at is not None:
            alert.details["measured_at"] = measured_at
        out.alerts.append(alert)

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
        threshold = int(reg.get(self.settings, "checks.serial_divergence_seconds"))
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

    def _config_divergence(self, now: int, out: PollOutcome) -> None:
        """Compare what the Kea servers of each HA relationship must share (collector.kea_shared):
        subnets, pools, reservations, options, classes and the peers list, never per-server keys.

        A node that publishes no relationship hashes (an older version) falls back to the normalized
        hash of the whole configuration, then to the raw config-hash-get, across every node.
        Raised once the divergence outlasts CONFIG_DIVERGENCE_GRACE_SECONDS."""
        for engine in (Engine.KEA4.value, Engine.KEA6.value):
            alert = self._config_divergence_of(engine)
            if alert is None:
                self.config_since.pop(engine, None)
                continue
            since = self.config_since.setdefault(engine, now)
            if now - since >= CONFIG_DIVERGENCE_GRACE_SECONDS:
                out.alerts.append(alert)

    def _config_divergence_of(self, engine: str) -> Alert | None:
        payloads: dict[str, dict[str, Any]] = {}
        for snap in self.store.snapshots(engine=engine):
            if snap["kind"] == "config_hash":
                payloads[snap["node_id"]] = snap["payload"] or {}
        if payloads and all("relationships" in p for p in payloads.values()):
            hashes, groups = kea_shared.divergent(payloads)
            return rules.config_divergence(engine, hashes, groups) if hashes else None
        field = "normalized" if all(p.get("normalized") for p in payloads.values()) else "hash"
        old: dict[str, str | None] = {n: p.get(field) for n, p in payloads.items()}
        return rules.config_divergence(engine, old) if len({h for h in old.values() if h}) > 1 else None

    def _zone_config_divergence(self, now: int, out: PollOutcome) -> None:
        """Forward zones: mode and forwarders; hint zones: digest of the hints file. Each node's own
        reads ("zone_list", "hints"), compared between the nodes that declare the zone."""
        forward: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
        hint: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
        for snap in self.store.snapshots(engine=Engine.BIND.value):
            payload = snap["payload"]
            if snap["kind"] == "zone_list" and isinstance(payload, list):
                for z in payload:
                    if isinstance(z, dict) and z.get("kind") == zone_config.FORWARD:
                        key = (str(z.get("name")), str(z.get("view") or "_default"))
                        forward.setdefault(key, {})[snap["node_id"]] = zone_config.forward_signature(z)
            elif snap["kind"] == "hints" and isinstance(payload, dict):
                for name, info in payload.items():
                    view, zone = name.split("/", 1)
                    hint.setdefault((zone, view), {})[snap["node_id"]] = info
        found: list[Alert] = []
        for (zone, view), by_node in forward.items():
            if zone_config.forwarders_divergent(by_node):
                found.append(rules.zone_config_divergence(zone, view, "forwarders", by_node))
        for (zone, view), by_node in hint.items():
            if zone_config.hints_divergent(by_node):
                nodes = {
                    n: {k: h.get(k) for k in ("file", "sha256", "related_version")}
                    for n, h in by_node.items()
                }
                found.append(rules.zone_config_divergence(zone, view, "hints", nodes))
        active = {a.subject for a in found}
        for alert in found:
            since = self.zone_config_since.setdefault(alert.subject, now)
            if now - since >= CONFIG_DIVERGENCE_GRACE_SECONDS:
                out.alerts.append(alert)
        for subject in list(self.zone_config_since):
            if subject not in active:
                del self.zone_config_since[subject]

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
            for node_id, st in ha.items():
                if st.get("role") != "backup" or node_id not in leases or st.get("other_relationships"):
                    continue
                reference = backup_reference(st, ha, leases)
                if reference is None:
                    continue
                ref_node, ref_ha = reference
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
