# SPDX-License-Identifier: Apache-2.0
"""Collector loop (section 15): tasks with periods from settings.collector, driven by one Collector object.

The Collector owns the pollers, reconciles their alerts against the store, fans events out to the web
process, replays alert acknowledgements from the audit log and runs retention. `run()` wires it to the
real node (connectors from node.toml, mTLS peer client) and loops; tests drive the same object with fakes.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pelagos.collector import series as series_mod
from pelagos.collector.alerts import ACK_ACTION, ACK_SKEW, AlertStore
from pelagos.collector.events import EventSink, SignalListener
from pelagos.collector.pollers import PollOutcome
from pelagos.collector.pollers.bind import BindPoller
from pelagos.collector.pollers.kea import D2Poller, KeaPoller
from pelagos.collector.pollers.peers import PeerClient, PeersPoller, ReplicationPeerClient
from pelagos.collector.snapshots import SnapshotProvider
from pelagos.connectors.base import ConnectorContext, ConnectorError, DdnsBackend, DhcpBackend, DnsBackend
from pelagos.core.context import NodeContext
from pelagos.core.paths import Paths
from pelagos.domain import (
    INCONSISTENCY_KINDS,
    Alert,
    AuditEntry,
    Family,
    Lease,
    Reservation,
    RRset,
    Severity,
    ZoneKind,
)
from pelagos.services import consistency

log = logging.getLogger(__name__)

LEASE_PAGE = 500
META_LAST_ACK = "last_ack_audit_id"


@dataclass(slots=True)
class Backends:
    """The local connectors this node drives; None when the engine is off or its connector failed to build."""

    dns: DnsBackend | None = None
    kea4: DhcpBackend | None = None
    kea6: DhcpBackend | None = None
    d2: DdnsBackend | None = None

    @property
    def dhcp(self) -> list[DhcpBackend]:
        return [b for b in (self.kea4, self.kea6) if b is not None]


def connector_context(ctx: NodeContext, engine: str) -> ConnectorContext:
    table = ctx.node.engines.get("bind" if engine == "bind" else "kea")
    # `[engines] bind = true` and an `[engines.bind]` table cannot coexist in TOML: accept either form.
    return ConnectorContext(
        node_id=ctx.node.id,
        engine_config=dict(table) if isinstance(table, dict) else {},
        backup_root=ctx.paths.backups_dir / engine,
        get_secret=ctx.get_secret,
        settings=ctx.settings(),
    )


def build_backends(ctx: NodeContext) -> Backends:
    """Instantiate the connectors enabled in node.toml [engines]; one that fails to build is skipped."""
    engines = ctx.node.engines
    backends = Backends()
    if engines.get("bind"):
        try:
            from pelagos.connectors.bind.backend import BindBackend

            backends.dns = BindBackend(connector_context(ctx, "bind"))
        except Exception:
            log.exception("bind connector could not be built")
    for engine, family in (("kea4", Family.V4), ("kea6", Family.V6)):
        if engines.get(engine):
            try:
                from pelagos.connectors.kea.backend import KeaBackend

                setattr(backends, engine, KeaBackend(connector_context(ctx, engine), family))
            except Exception:
                log.exception("%s connector could not be built", engine)
    if engines.get("d2"):
        try:
            from pelagos.connectors.kea.d2 import D2Backend

            backends.d2 = D2Backend(connector_context(ctx, "d2"))
        except Exception:
            log.exception("d2 connector could not be built")
    return backends


def build_peer_client(ctx: NodeContext) -> PeerClient | None:
    """mTLS client over the node PKI; None until the node has its certificate."""
    pki = ctx.paths.pki_dir
    ca, crt, key = pki / "ca.crt", pki / "node.crt", pki / "node.key"
    if not (ca.exists() and crt.exists() and key.exists()):
        return None
    from pelagos.core.replication import client_ssl_context

    return ReplicationPeerClient(client_ssl_context(ca, crt, key))


@dataclass(slots=True)
class Task:
    name: str
    period: float
    fn: Callable[[], Any]
    next_run: float = 0.0


@dataclass(slots=True)
class CycleReport:
    opened: list[Alert] = field(default_factory=list)
    updated: list[Alert] = field(default_factory=list)
    resolved: list[Alert] = field(default_factory=list)
    acked: list[Alert] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


class Collector:
    def __init__(
        self,
        ctx: NodeContext,
        store: series_mod.SeriesStore,
        backends: Backends,
        peer_client: PeerClient | None = None,
        events: EventSink | None = None,
        clock: Callable[[], float] = time.time,
        backend_lock: threading.RLock | None = None,
    ) -> None:
        self.ctx = ctx
        self.store = store
        # Every backend call runs under it, shared with the replication server (remote plans, live
        # snapshots) which drives the same backend objects from its own thread.
        self.backend_lock = backend_lock if backend_lock is not None else threading.RLock()
        self.alerts = AlertStore(store.conn)
        self.backends = backends
        self.events = events or EventSink(ctx.paths.events_sock, ctx.node.id)
        self.clock = clock
        self.node_id = ctx.node.id
        settings = ctx.settings()
        self.bind = BindPoller(backends.dns, self.node_id, store, clock) if backends.dns else None
        self.kea = [KeaPoller(b, self.node_id, store, settings, clock) for b in backends.dhcp]
        self.d2 = D2Poller(backends.d2, self.node_id, store, settings, clock) if backends.d2 else None
        self.peers = PeersPoller(
            peer_client, self.node_id, lambda: self.ctx.cluster().nodes, store, settings, clock
        )
        self.last_report = CycleReport()
        # Set by run(): the collector.sock listener other components register their handlers on.
        self.listener: SignalListener | None = None

    # Tasks -----------------------------------------------------------------

    def poll_bind(self) -> None:
        if self.bind is not None:
            with self.backend_lock:
                outcome = self.bind.poll()
            self._finish(outcome)

    def poll_kea(self) -> None:
        # Thresholds live in the replicated settings: re-read them every pass.
        settings = self.ctx.settings()
        for poller in self.kea:
            poller.settings = settings
            with self.backend_lock:
                outcome = poller.poll()
            self._finish(outcome)

    def poll_d2(self) -> None:
        if self.d2 is not None:
            self.d2.settings = self.ctx.settings()
            with self.backend_lock:
                outcome = self.d2.poll()
            self._finish(outcome)

    def poll_peers(self) -> None:
        self.peers.settings = self.ctx.settings()
        self._finish(self.peers.poll())

    def apply_acks(self) -> list[Alert]:
        """Replay alert.ack audit entries (local API acks and replicated ones) onto open alerts.

        Replicated entries can arrive with ids older than any cursor, so the scan is bounded by time
        instead: an ack older than the oldest open alert (minus the skew allowance) cannot apply. Each
        ack entry is consumed once (recorded in meta), which keeps it off a later re-opening.
        """
        oldest = self.alerts.oldest_open_first_seen()
        if oldest is None:
            return []
        entries, _ = self.ctx.audit_log.query(
            action=ACK_ACTION, since=oldest - ACK_SKEW, page=1, per_page=1_000_000
        )
        consumed = self.alerts.consumed_acks()
        fresh = sorted((e for e in entries if e.id not in consumed), key=lambda e: e.id)
        if not fresh:
            return []
        changed = self.alerts.apply_audit_acks(fresh)
        self.alerts.mark_acks_consumed([e.id for e in fresh])
        self.store.set_meta(META_LAST_ACK, fresh[-1].id)
        for alert in changed:
            self.events.emit("alerts", "acked", alert)
        self.last_report.acked.extend(changed)
        return changed

    def consistency(self) -> list[Alert]:
        """Read leases, reservations and primary zones live, run the pure checks, reconcile cross alerts.

        A partial read would turn into false alerts (every DHCID record without its lease, every PTR
        into an unread zone), so any read failure skips the reconcile and keeps the previous state.
        """
        leases, reservations, dhcp_errors = self._dhcp_data()
        forward, reverse, dns_errors = self._dns_data()
        failures = dhcp_errors + dns_errors
        if failures:
            log.warning("consistency pass skipped: %s", "; ".join(failures))
            self.last_report.errors["consistency"] = "; ".join(failures)
            return []
        observed = consistency.run_all(
            leases=leases, reservations=reservations, forward=forward, reverse=reverse
        )
        outcome = PollOutcome(alerts=observed, kinds=frozenset(k.value for k in INCONSISTENCY_KINDS))
        self._finish(outcome)
        self.store.set_meta("last_run_consistency", str(int(self.clock())))
        return observed

    def retention(self) -> dict[str, int]:
        now = int(self.clock())
        retention = self.ctx.settings().get("retention", {})
        counts = self.store.apply_retention(now, retention)
        counts["backups_deleted"] = series_mod.purge_backups(
            self.ctx.paths.backups_dir, int(retention.get("backups_days", 90)), now
        )
        return counts

    def cycle(self) -> CycleReport:
        """One pass over every task, in order; used by --once and by tests."""
        self.last_report = CycleReport()
        for name, fn in (
            ("poll_bind", self.poll_bind),
            ("poll_kea", self.poll_kea),
            ("poll_d2", self.poll_d2),
            ("poll_peers", self.poll_peers),
            ("apply_acks", self.apply_acks),
            ("consistency", self.consistency),
            ("retention", self.retention),
        ):
            try:
                fn()
            except Exception as exc:
                log.exception("task %s failed", name)
                self.last_report.errors[name] = str(exc)
        return self.last_report

    def tasks(self) -> list[Task]:
        settings = self.ctx.settings().get("collector", {})
        poll = float(settings.get("poll_seconds", 60))
        peer_poll = float(settings.get("peer_poll_seconds", 30))
        consistency_period = float(settings.get("consistency_seconds", 900))
        return [
            Task("poll_bind", poll, self.poll_bind),
            Task("poll_kea", poll, self.poll_kea),
            Task("poll_d2", poll, self.poll_d2),
            Task("poll_peers", peer_poll, self.poll_peers),
            Task("apply_acks", poll, self.apply_acks),
            Task("consistency", consistency_period, self.consistency),
            Task("retention", 3600.0, self.retention),
        ]

    def refresh_tasks(self, tasks: list[Task], now: float | None = None) -> list[str]:
        """Apply the periods of settings.collector as they are now; returns the tasks that changed.

        A shorter period takes effect at once (the next run moves closer), a longer one after the
        run already scheduled. Thresholds and retention are re-read by each task run anyway.
        """
        now = time.monotonic() if now is None else now
        fresh = {t.name: t.period for t in self.tasks()}
        changed: list[str] = []
        for task in tasks:
            period = fresh.get(task.name)
            if period is not None and period != task.period:
                task.period = period
                task.next_run = min(task.next_run, now + period)
                changed.append(task.name)
        settings = self.ctx.settings()
        for poller in self.kea:
            poller.settings = settings
        if self.d2 is not None:
            self.d2.settings = settings
        self.peers.settings = settings
        return changed

    # Internals -------------------------------------------------------------

    def _finish(self, outcome: PollOutcome) -> None:
        opened, updated, resolved = self.alerts.reconcile(outcome.alerts, set(outcome.kinds), outcome.where)
        for topic, event, data in outcome.events:
            self.events.emit(topic, event, data)
        for alert in opened:
            self.events.emit("alerts", "opened", alert)
            self._audit(alert, "alert.raise")
        for alert in updated:
            self.events.emit("alerts", "updated", alert)
        for alert in resolved:
            self.events.emit("alerts", "resolved", alert)
            self._audit(alert, "alert.resolve")
        self.last_report.opened.extend(opened)
        self.last_report.updated.extend(updated)
        self.last_report.resolved.extend(resolved)

    def _audit(self, alert: Alert, action: str) -> None:
        # Info alerts (HA transitions, inconsistencies that follow lease churn) flap by nature: the
        # replicated audit log keeps only warning and critical ones.
        if alert.severity is Severity.INFO:
            return
        entry = AuditEntry(
            node_id=self.node_id,
            action=action,
            target="alert:" + alert.id,
            user="system",
            engine=alert.engine,
            request={"kind": alert.kind.value, "subject": alert.subject, "node_id": alert.node_id},
            response={"severity": alert.severity.value, "details": alert.details},
            message=alert.title,
        )
        try:
            self.ctx.audit_log.append(entry)
        except OSError as exc:
            log.warning("audit append failed: %s", exc)

    def _dhcp_data(self) -> tuple[list[Lease], list[Reservation], list[str]]:
        """Leases and reservations of every local DHCP backend, plus one error string per failed read."""
        leases: list[Lease] = []
        reservations: list[Reservation] = []
        errors: list[str] = []
        for backend in self.backends.dhcp:
            try:
                with self.backend_lock:
                    reservations.extend(backend.list_reservations())
                    leases.extend(_all_leases(backend, self.node_id))
            except (ConnectorError, NotImplementedError) as exc:
                errors.append(f"{backend.engine_name}: {exc or type(exc).__name__}")
        return leases, reservations, errors

    def _dns_data(self) -> tuple[dict[str, list[RRset]], list[RRset], list[str]]:
        """Primary zone contents split forward/reverse, plus one error string per failed read."""
        forward: dict[str, list[RRset]] = {}
        reverse: list[RRset] = []
        if self.backends.dns is None:
            return forward, reverse, []
        try:
            with self.backend_lock:
                zones = self.backends.dns.list_zones()
        except (ConnectorError, NotImplementedError) as exc:
            return forward, reverse, [f"bind: {exc or type(exc).__name__}"]
        errors: list[str] = []
        for zone in zones:
            if zone.kind is not ZoneKind.PRIMARY:
                continue
            try:
                with self.backend_lock:
                    rrsets = self.backends.dns.read_zone(zone.name, zone.view)
            except (ConnectorError, NotImplementedError) as exc:
                errors.append(f"AXFR {zone.name}: {exc or type(exc).__name__}")
                continue
            if zone.name.endswith((".in-addr.arpa.", ".ip6.arpa.")):
                reverse.extend(rrsets)
            else:
                forward.setdefault(zone.name, []).extend(rrsets)
        return forward, reverse, errors


def _all_leases(backend: DhcpBackend, node_id: str) -> list[Lease]:
    """Walk lease4-get-page / lease6-get-page through the ABC's paging arguments."""
    out: list[Lease] = []
    start: str | None = None
    while True:
        page = backend.leases(limit=LEASE_PAGE, from_address=start)
        for lease in page:
            if lease.node_id is None:
                lease.node_id = node_id
        out.extend(page)
        if len(page) < LEASE_PAGE or not page:
            break
        start = page[-1].ip_address
    return out


# Process entry point -----------------------------------------------------------


def build_tasks(ctx: NodeContext, store: series_mod.SeriesStore) -> list[Task]:
    """Kept for callers of the skeleton API: the Collector decides the task list."""
    return Collector(ctx, store, build_backends(ctx), build_peer_client(ctx)).tasks()


def build_registries(
    ctx: NodeContext, backends: Backends, lock: threading.RLock | None = None
) -> tuple[Any, Any]:
    """The same backend objects behind both registries: core's (remote plan apply) and the services'
    one that `services.snapshot.engine_snapshot` reads (live snapshot kinds)."""
    from pelagos.services.registry import ConnectorRegistry as ServiceRegistry
    from pelagos.services.registry import replication_registry

    service = ServiceRegistry(dns=backends.dns, kea4=backends.kea4, kea6=backends.kea6, d2=backends.d2)
    # Core's entries are PlanRunners: peers' installer sub-plans run here, the rest reach the backend.
    core = replication_registry(ctx, service, lock=lock)
    return core, service


def start_replication(
    ctx: NodeContext,
    listener: SignalListener,
    store: series_mod.SeriesStore,
    backends: Backends | None = None,
    backend_lock: threading.RLock | None = None,
) -> Any:
    """Start ReplicationService on the collector's listener: /repl/v1 server, pushes, anti-entropy.

    Returns its handle (with `close()` and `replicator`), or None on a node without PKI files.
    """
    from pelagos.core.replication import EVENT_AUDIT_MERGED, start_collector_side
    from pelagos.core.signals import signal_collector

    backends = backends if backends is not None else Backends()
    core_registry, service_registry = build_registries(ctx, backends, backend_lock)
    provider = SnapshotProvider(ctx.node.id, ctx.paths.series_db, service_registry, core_registry.lock)
    sock = ctx.paths.collector_sock
    try:
        return start_collector_side(
            ctx,
            listener,
            store,
            registry=core_registry,
            snapshot=provider,
            # Runs on replication threads: the collector loop replays acks when the datagram arrives.
            on_audit_merged=lambda: signal_collector(sock, EVENT_AUDIT_MERGED),
        )
    except NotImplementedError as exc:
        log.info("replication not started by the collector: %s", exc)
        return None
    except Exception:
        log.exception("replication service failed to start")
        # Without replication the node still accepts writes: never leave it read-only.
        from pelagos.core.context import REPL_READY, write_replication_state

        write_replication_state(ctx.paths, REPL_READY)
        return None


# Exit status asking the service manager for a restart (Restart=on-failure): the engines changed.
EXIT_ENGINES_CHANGED = 75


class EnginesWatch:
    """Tells when node.toml [engines] differs from what the connectors were built with."""

    def __init__(self, ctx: NodeContext) -> None:
        self.ctx = ctx
        self.engines = dict(ctx.node.engines)
        self._mtime = self._stat()

    def _stat(self) -> int | None:
        try:
            return self.ctx.paths.node_toml.stat().st_mtime_ns
        except OSError:
            return None

    def changed(self) -> bool:
        mtime = self._stat()
        if mtime == self._mtime:
            return False
        self._mtime = mtime
        try:
            engines = self.ctx.config_store.load_node().engines
        except Exception:  # a half-written or broken file: keep running on the current connectors
            log.exception("node.toml not readable")
            return False
        return engines != self.engines


class SettingsWatch:
    """Tells when cluster.toml changed (a local write or a merge from a peer): settings to re-read."""

    def __init__(self, ctx: NodeContext) -> None:
        self.ctx = ctx
        self._mtime = self._stat()

    def _stat(self) -> int | None:
        try:
            return self.ctx.paths.cluster_toml.stat().st_mtime_ns
        except OSError:
            return None

    def changed(self) -> bool:
        mtime = self._stat()
        if mtime == self._mtime:
            return False
        self._mtime = mtime
        return True


def reload_settings(collector: Collector, tasks: list[Task], replication: Any = None) -> list[str]:
    """Live reload of settings.collector: task periods, poller thresholds, the anti-entropy period."""
    try:
        changed = collector.refresh_tasks(tasks)
        peer_poll = float(collector.ctx.settings().get("collector", {}).get("peer_poll_seconds", 30))
    except Exception:  # a half-written or broken file: keep the current periods
        log.exception("cluster.toml not readable")
        return []
    service = getattr(replication, "service", None)
    if service is not None and hasattr(service, "set_peer_poll_seconds"):
        service.set_peer_poll_seconds(peer_poll)
    if changed:
        log.info("collector periods reloaded: %s", ", ".join(f"{t.name}={t.period:g}s" for t in tasks))
    return changed


MODULES_CHECK_SECONDS = 30.0


def publish_own_modules(ctx: NodeContext) -> bool:
    """Each node owns its [[nodes]].modules entry: when cluster.toml says something else than
    node.toml [engines] (a peer wrote that entry later), publish it again."""
    try:
        own = ctx.config_store.load_cluster().peer(ctx.node.id)
    except Exception:
        log.exception("cluster.toml not readable")
        return False
    if own is None or own.modules == ctx.node.modules:
        return False

    def mutate(cfg: Any) -> None:
        peer = cfg.peer(ctx.node.id)
        if peer is not None:
            peer.modules = ctx.node.modules

    ctx.config_store.update_cluster(mutate, updated_by=f"node:{ctx.node.id}")
    log.info("published this node's modules in cluster.toml again")
    return True


def run(paths: Paths, once: bool = False, rebuild: bool = False) -> int:
    ctx = NodeContext.build(paths)
    if rebuild:
        log.info("rebuilding %s", paths.series_db)
        series_mod.rebuild(paths.series_db)
    conn = series_mod.connect(paths.series_db)
    store = series_mod.SeriesStore(conn)
    store.set_meta("last_start", datetime.now(UTC).isoformat())
    backends = build_backends(ctx)
    collector = Collector(ctx, store, backends, build_peer_client(ctx))
    log.info("collector started for node %s (%s)", ctx.node.name, ctx.node.id)
    if once:
        report = collector.cycle()
        log.info(
            "cycle done: %d opened, %d updated, %d resolved, %d acked, errors=%s",
            len(report.opened),
            len(report.updated),
            len(report.resolved),
            len(report.acked),
            report.errors or "none",
        )
        return 1 if report.errors else 0

    tasks = collector.tasks()
    listener = SignalListener(paths.collector_sock)
    listener.on("audit", lambda _msg: collector.apply_acks())
    listener.on("audit_merged", lambda _msg: collector.apply_acks())
    listener.on("consistency", lambda _msg: collector.consistency())
    collector.listener = listener
    try:
        listener.open()
    except OSError as exc:
        log.warning("signal socket %s unavailable: %s", paths.collector_sock, exc)
    replication = start_replication(ctx, listener, store, backends, collector.backend_lock)
    replicator = getattr(replication, "replicator", None)
    if replicator is not None:
        collector.peers.liveness = replicator
    watch = EnginesWatch(ctx)
    settings_watch = SettingsWatch(ctx)
    next_modules_check = 0.0
    try:
        while True:
            if watch.changed():
                log.info("node.toml engines changed: exiting so the service restarts with them")
                return EXIT_ENGINES_CHANGED
            if settings_watch.changed():
                reload_settings(collector, tasks, replication)
            if time.monotonic() >= next_modules_check:
                next_modules_check = time.monotonic() + MODULES_CHECK_SECONDS
                try:
                    publish_own_modules(ctx)
                except Exception:
                    log.exception("modules not published")
            now = time.monotonic()
            for task in tasks:
                if task.next_run <= now:
                    try:
                        task.fn()
                    except Exception:
                        log.exception("task %s failed", task.name)
                    task.next_run = now + task.period
            sleep_for = max(0.5, min(t.next_run for t in tasks) - time.monotonic())
            if listener.sock is not None:
                listener.wait(min(sleep_for, 5.0))
            else:
                time.sleep(min(sleep_for, 5.0))
    except KeyboardInterrupt:
        return 0
    finally:
        close = getattr(replication, "close", None)
        if callable(close):
            close()
        listener.close()
        conn.close()
