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
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pelagos.collector import series as series_mod
from pelagos.collector.alerts import ACK_ACTION, AlertStore
from pelagos.collector.checks.runner import HealthChecks
from pelagos.collector.events import EventSink, SignalListener
from pelagos.collector.pollers import PollOutcome
from pelagos.collector.pollers.bind import BindPoller
from pelagos.collector.pollers.kea import D2Poller, KeaPoller, engine_write_in_progress
from pelagos.collector.pollers.peers import PeerClient, PeersPoller, ReplicationPeerClient
from pelagos.collector.pollers.rpz import RpzPoller
from pelagos.collector.snapshots import SnapshotProvider
from pelagos.connectors.base import ConnectorContext, ConnectorError, DdnsBackend, DhcpBackend, DnsBackend
from pelagos.core import ha_maintenance
from pelagos.core import settings_registry as reg
from pelagos.core.context import NodeContext
from pelagos.core.paths import Paths
from pelagos.domain import (
    INCONSISTENCY_KINDS,
    Alert,
    AuditEntry,
    AuditResult,
    Engine,
    Family,
    Lease,
    Reservation,
    RRset,
    Severity,
    ZoneKind,
)
from pelagos.services import consistency
from pelagos.services.masking import masked_text

log = logging.getLogger(__name__)

LEASE_PAGE = 500
# Live task defaults (settings.collector): fast HA reads and the lease watch.
LIVE_SECONDS = 5.0
# A zone whose serial a peer announced is read again here after these delays, until it follows.
ZONE_RECHECK_DELAYS = (2.0, 5.0, 15.0, 30.0)
# Web certificate renewal and expiry checks (core.webcert): often enough for 24 h certificates.
CERT_SECONDS = 60.0
META_LAST_ACK = "last_ack_audit_id"
META_ACK_OFFSET = "ack_scan_offset"
META_ACK_INODE = "ack_scan_inode"
ACK_NEEDLE = b'"alert.ack"'


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


def _collect_findings(ctx: NodeContext) -> list[dict[str, Any]] | None:
    from pelagos.collector.security import collect_findings

    return collect_findings(ctx)


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
        if self.bind is not None:
            self.bind.external.locks_dir = ctx.paths.locks_dir
            self._watch_external(self.bind.external)
        locks = ctx.paths.locks_dir
        self.rpz = (
            RpzPoller(backends.dns, self.node_id, store, self.ctx.settings, clock) if backends.dns else None
        )
        self.kea = [KeaPoller(b, self.node_id, store, settings, clock, locks) for b in backends.dhcp]
        self.d2 = D2Poller(backends.d2, self.node_id, store, settings, clock, locks) if backends.d2 else None
        self.peers = PeersPoller(
            peer_client, self.node_id, lambda: self.ctx.cluster().nodes, store, settings, clock
        )
        for poller in self.kea:
            poller.maintenance = lambda engine: ha_maintenance.active(ctx.paths, engine)
            poller.maintenance_done = lambda engine: ha_maintenance.close(ctx.paths, engine)
            poller.reloading = self._reloading(poller)
            self._watch_external(poller.external)
        # (zone, view) -> (serial announced by a peer, attempt, monotonic time of the next read).
        self.zone_rechecks: dict[tuple[str, str], tuple[int, int, float]] = {}
        self._zone_lock = threading.Lock()  # recheck_zone runs on replication threads
        self._replication_seen: tuple[Any, ...] | None = None
        self._findings_seen: frozenset[str] | None = None
        self.checks = HealthChecks(
            ctx,
            store,
            backends,
            self.backend_lock,
            clock,
            lambda backend: _all_leases(backend, self.node_id, self.backend_lock),
        )
        self.last_report = CycleReport()
        # Where security findings come from (the helper or a local audit); tests replace it.
        self.findings_source: Callable[[NodeContext], list[dict[str, Any]] | None] = _collect_findings
        # Set by run(): the collector.sock listener other components register their handlers on.
        self.listener: SignalListener | None = None
        from pelagos.core.webcert.manager import CertManager

        # Web UI certificate of this node: renewal of an automatic source and expiry alerts.
        self.certs = CertManager(ctx)
        self.cert_background = True
        self._cert_thread: threading.Thread | None = None
        # run() turns this on: the slow checks probe the network, never inside the polling loop.
        self.slow_background = False
        self._slow_thread: threading.Thread | None = None
        self._slow_ready: list[PollOutcome] = []
        self._slow_lock = threading.Lock()

    def _reloading(self, poller: KeaPoller) -> Callable[[str], bool]:
        """True while Pelagos writes or reloads the engine and for the grace period after."""

        def reloading(engine: str) -> bool:
            if engine_write_in_progress(self.ctx.paths.locks_dir, engine):
                return True
            at = ha_maintenance.marked_at(self.ctx.paths, engine, "reload")
            return at is not None and self.clock() - at < poller.ha_grace

        return reloading

    def _watch_external(self, watcher: Any) -> None:
        watcher.last_write = lambda engine: ha_maintenance.marked_at(self.ctx.paths, engine, "write")
        watcher.emit = self._external_change

    def _external_change(self, engine: str, details: dict[str, Any]) -> None:
        """Audit entry for a configuration change nobody made through Pelagos."""
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.node_id,
                user="collector",
                action="external.change",
                target=f"{engine}:config",
                engine=Engine(engine),
                request={},
                response={"count": details["count"], "hash": details.get("hash")},
                diff="\n".join(details["differences"]),
                result=AuditResult.OK,
                message="external change detected",
            )
        )

    # Tasks -----------------------------------------------------------------

    def batch(self) -> Any:
        """The series writes of one task in one transaction (the store commits once at the end)."""
        batch = getattr(self.store, "batch", None)
        return batch() if callable(batch) else nullcontext()

    def poll_bind(self) -> None:
        if self.bind is not None:
            with self.backend_lock:
                outcome = self.bind.poll()
            self._finish(outcome)
            self._daemons_changed()

    def _daemons_changed(self) -> None:
        try:
            outcome = self.checks.daemons_changed()
        except Exception:
            log.exception("advisories after a daemon change failed")
            return
        if outcome is not None:
            self._finish(outcome)

    def poll_rpz(self) -> None:
        if self.rpz is not None:
            self._finish(self.rpz.poll())

    def poll_kea(self) -> None:
        # Thresholds live in the replicated settings: re-read them every pass.
        settings = self.ctx.settings()
        for poller in self.kea:
            poller.settings = settings
            with self.backend_lock:
                outcome = poller.poll()
            self._finish(outcome)
        self._daemons_changed()

    def poll_d2(self) -> None:
        if self.d2 is not None:
            self.d2.settings = self.ctx.settings()
            with self.backend_lock:
                outcome = self.d2.poll()
            self._finish(outcome)

    def poll_peers(self) -> None:
        self.peers.settings = self.ctx.settings()
        self._finish(self.peers.poll())

    def live(self) -> None:
        """Fast pass (settings.collector.live_seconds): HA heartbeats and the lease watch."""
        for poller in self.kea:
            with self.backend_lock:
                outcome = poller.heartbeat()
            self._finish(outcome)
        self.watch_leases()
        self.zone_checks()

    def watch_leases(self) -> None:
        """Walk the leases of a server that answered clients since the last walk; new and renewed
        ones go out as `leases` events and the latest ones to the "recent_leases" snapshot."""
        limit = int(reg.get(self.ctx.settings(), "collector.lease_watch_max_leases"))
        for poller in self.kea:
            with self.backend_lock:
                acks = poller.ack_counter()
            if not poller.lease_walk_due(acks, limit):
                continue
            try:
                leases = _all_leases(poller.backend, self.node_id, self.backend_lock)
            except (ConnectorError, NotImplementedError) as exc:
                log.debug("lease watch %s failed: %s", poller.engine.value, exc)
                continue
            self._finish(poller.lease_diff(leases, acks))

    def recheck_zone(self, zone: str, view: str, serial: int) -> None:
        """A peer announced a new serial for a zone this node may hold as a secondary: read it again
        shortly, so the transfer shows when it lands instead of at the next full poll."""
        if self.bind is None or not self.bind.holds_copy(zone, view):
            return
        with self._zone_lock:
            self.zone_rechecks[(zone, view)] = (serial, 0, time.monotonic() + ZONE_RECHECK_DELAYS[0])

    def zone_checks(self) -> None:
        if self.bind is None or not self.zone_rechecks:
            return
        now = time.monotonic()
        with self._zone_lock:
            due = [(k, v) for k, v in self.zone_rechecks.items() if v[2] <= now]
        for key, (serial, attempt, _due) in due:
            with self.backend_lock:
                outcome, current = self.bind.recheck(*key)
            self._finish(outcome)
            with self._zone_lock:
                if self.zone_rechecks.get(key, (None,))[0] != serial:
                    continue  # a newer serial was announced meanwhile: its own schedule stands
                if current is None or current >= serial or attempt + 1 >= len(ZONE_RECHECK_DELAYS):
                    del self.zone_rechecks[key]
                else:
                    self.zone_rechecks[key] = (serial, attempt + 1, now + ZONE_RECHECK_DELAYS[attempt + 1])

    def replication_events(self) -> None:
        """`system`/`replication` when this node's cluster.toml version or audit head moved."""
        try:
            version = self.ctx.config_store.load_cluster().version
            count, head = self.ctx.audit_log.head()
        except Exception:
            return
        seen = (version, count, head)
        if seen == self._replication_seen:
            return
        before = self._replication_seen
        self._replication_seen = seen
        if before is not None:
            data = {
                "node_id": self.node_id,
                "config_version": version,
                "audit_count": count,
                "config_changed": version != before[0],
            }
            self.events.emit("system", "replication", data, key="system:replication:self")

    def on_peer_events(self, caller: str, messages: list[dict[str, Any]]) -> None:
        """Events a peer relayed (POST /repl/v1/events): shown here as that node's, a zone serial
        announced by the primary starts a recheck of this node's copy."""
        for msg in messages:
            data = msg.get("data") or {}
            key = None
            if msg["topic"] == "ha" and msg["event"] in ("heartbeat", "unsent"):
                key = f"peer:{caller}:ha:{msg['event']}:{data.get('family')}"
            self.events.emit_message(msg, key=key)
            if msg["topic"] == "zones" and msg["event"] == "serial" and isinstance(data.get("serial"), int):
                self.recheck_zone(str(data.get("zone")), str(data.get("view") or "_default"), data["serial"])

    def on_peer_plan(self, plan: Any, origin: str, verb: str, phase: str, result: Any) -> None:
        """A plan this node runs for a peer: its steps on this node's `plans` topic, and the HA
        maintenance window it opens or closes here."""
        if phase != "running" and result is not None:
            ha_maintenance.record_plan(self.ctx.paths, plan, bool(result.ok), verb)
        self.events.emit("plans", "step", plan_step(plan, self.node_id, origin, verb, phase, result))

    def apply_acks(self) -> list[Alert]:
        """Replay alert.ack audit entries (local API acks and replicated ones) onto open alerts.

        The log is append-only (merged entries are appended too), so only the bytes past the last
        scanned offset are read, and only lines naming the ack action are decoded. Acks whose alert
        is not open here yet are kept (bounded) and retried on the next pass.
        """
        try:
            offset = int(self.store.get_meta(META_ACK_OFFSET) or 0)
            inode = int(self.store.get_meta(META_ACK_INODE) or 0) or None
        except ValueError:
            offset, inode = 0, None
        fresh, offset, inode = self.ctx.audit_log.scan(offset, inode, needle=ACK_NEEDLE)
        legacy = self.alerts.consumed_acks()  # markers of the time-window scan, dropped below
        fresh = [e for e in fresh if e.action == ACK_ACTION and e.id not in legacy]
        waiting = self.alerts.pending_acks()
        if not fresh and not waiting and not legacy:
            self._save_ack_cursor(offset, inode)
            return []
        held = frozenset(e.id for e in waiting)
        entries = sorted({e.id: e for e in [*waiting, *fresh]}.values(), key=lambda e: e.id)
        changed, still = self.alerts.replay_acks(entries, held)
        self.alerts.set_pending_acks(still)
        self._save_ack_cursor(offset, inode)
        if entries:
            self.store.set_meta(META_LAST_ACK, entries[-1].id)
        for alert in changed:
            self.events.emit("alerts", "acked", alert)
        self.last_report.acked.extend(changed)
        return changed

    def _save_ack_cursor(self, offset: int, inode: int | None) -> None:
        self.store.set_meta(META_ACK_OFFSET, str(offset))
        self.store.set_meta(META_ACK_INODE, str(inode or 0))

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
            leases=leases,
            reservations=reservations,
            forward=forward,
            reverse=reverse,
            excepted=consistency.excepted_for(self.ctx.cluster()),
        )
        outcome = PollOutcome(alerts=observed, kinds=frozenset(k.value for k in INCONSISTENCY_KINDS))
        self._finish(outcome)
        self.store.set_meta("last_run_consistency", str(int(self.clock())))
        return observed

    def apply_exceptions(self) -> list[Alert]:
        """Resolve at once the open alerts an admin exception now names, without waiting for their check."""
        excepted = consistency.excepted_for(self.ctx.cluster())
        gone = [a for a in self.alerts.open_alerts() if consistency.is_excepted(a, excepted)]
        if not gone:
            return []
        ids = {a.id for a in gone}
        kinds = {a.kind.value for a in gone}
        report = self.last_report.resolved
        before = len(report)
        self._finish(PollOutcome(alerts=[], kinds=frozenset(kinds), where=lambda a: a.id in ids))
        return report[before:]

    def security_audit(self) -> list[Alert]:
        """Weak keys and listeners off localhost from the security audit, as alerts (section 15)."""
        from pelagos.collector.security import security_outcome

        findings = self.findings_source(self.ctx)
        if findings is None:
            return []
        outcome = security_outcome(findings, self.node_id)
        self._finish(outcome)
        seen = frozenset(a.subject for a in outcome.alerts)
        if self._findings_seen is not None and seen != self._findings_seen:
            data = {"findings": len(seen), "opened": len(seen - self._findings_seen)}
            data["resolved"] = len(self._findings_seen - seen)
            self.events.emit("system", "security", data, key="system:security")
        self._findings_seen = seen
        return outcome.alerts

    def health(self) -> None:
        """Restart loops, resolver health, declined addresses, forecasts, versions, advisories."""
        for outcome in self.checks.fast():
            self._finish(outcome)

    def health_audit(self) -> None:
        """Disk and file growth, reservation risks, delegation and SOA, root reachability."""
        if not self.slow_background:
            for outcome in self.checks.slow():
                self._finish(outcome)
            return
        self.health_audit_ready()
        if self._slow_thread is None or not self._slow_thread.is_alive():
            self._slow_thread = threading.Thread(target=self._slow_checks, name="health-audit", daemon=True)
            self._slow_thread.start()

    def _slow_checks(self) -> None:
        try:
            outcomes = self.checks.slow()
        except Exception:
            log.exception("slow health checks failed")
            return
        with self._slow_lock:
            self._slow_ready.extend(outcomes)

    def health_audit_ready(self) -> None:
        """Reconcile what the slow checks finished since the last call (the loop thread owns the store)."""
        with self._slow_lock:
            ready, self._slow_ready = self._slow_ready, []
        for outcome in ready:
            self._finish(outcome)

    def certificates(self) -> list[Alert]:
        """Renew the web certificate when due (or install one another node sent), then the expiry
        alerts of the web, node and internal CA certificates and a failing renewal."""
        from pelagos.core.webcert.manager import ALERT_KINDS

        busy = self._cert_thread is not None and self._cert_thread.is_alive()
        if not busy:
            # An issuance waits on DNS propagation and the CA: never in the polling loop itself.
            self._cert_thread = threading.Thread(target=self._renew_certificate, name="webcert", daemon=True)
            self._cert_thread.start()
            if not self.cert_background:
                self._cert_thread.join()
        alerts = self.certs.alerts()
        node_id = self.node_id
        self._finish(PollOutcome(alerts=alerts, kinds=ALERT_KINDS, where=lambda a: a.node_id == node_id))
        return alerts

    def _renew_certificate(self) -> None:
        try:
            self.certs.run_due()
        except Exception:
            log.exception("web certificate renewal failed")

    def retention(self) -> dict[str, int]:
        now = int(self.clock())
        retention = self.ctx.settings().get("retention", {})
        counts = self.store.apply_retention(now, retention)
        counts["backups_deleted"] = series_mod.purge_backups(
            self.ctx.paths.backups_dir, int(reg.get(self.ctx.settings(), "retention.backups_days")), now
        )
        return counts

    def cycle(self) -> CycleReport:
        """One pass over every task, in order; used by --once and by tests."""
        self.last_report = CycleReport()
        for name, fn in (
            ("poll_bind", self.poll_bind),
            ("poll_kea", self.poll_kea),
            ("poll_d2", self.poll_d2),
            ("poll_rpz", self.poll_rpz),
            ("poll_peers", self.poll_peers),
            ("live", self.live),
            ("apply_acks", self.apply_acks),
            ("consistency", self.consistency),
            ("security_audit", self.security_audit),
            ("health", self.health),
            ("health_audit", self.health_audit),
            ("certificates", self.certificates),
            ("retention", self.retention),
        ):
            try:
                with self.batch():
                    fn()
            except Exception as exc:
                log.exception("task %s failed", name)
                self.last_report.errors[name] = str(exc)
        return self.last_report

    def tasks(self) -> list[Task]:
        settings = self.ctx.settings()
        poll = float(reg.get(settings, "collector.poll_seconds"))
        peer_poll = float(reg.get(settings, "collector.peer_poll_seconds"))
        consistency_period = float(reg.get(settings, "collector.consistency_seconds"))
        live = max(1.0, float(reg.get(settings, "collector.live_seconds")))
        rpz_period = max(30.0, float(reg.get(settings, "rpz.check_seconds")))
        return [
            Task("poll_bind", poll, self.poll_bind),
            Task("poll_kea", poll, self.poll_kea),
            Task("poll_d2", poll, self.poll_d2),
            Task("poll_rpz", rpz_period, self.poll_rpz),
            Task("poll_peers", peer_poll, self.poll_peers),
            Task("live", live, self.live),
            Task("apply_acks", poll, self.apply_acks),
            Task("consistency", consistency_period, self.consistency),
            Task("security_audit", consistency_period, self.security_audit),
            Task("health", poll, self.health),
            Task("health_audit", consistency_period, self.health_audit),
            Task("health_audit_ready", poll, self.health_audit_ready),
            Task("certificates", CERT_SECONDS, self.certificates),
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
        if outcome.kinds or outcome.alerts:
            observed = consistency.apply_exceptions(
                outcome.alerts, consistency.excepted_for(self.ctx.cluster())
            )
            opened, updated, resolved = self.alerts.reconcile(observed, set(outcome.kinds), outcome.where)
        else:
            opened, updated, resolved = [], [], []
        for item in outcome.events:
            topic, event, data = item[:3]
            opts = item[3] if len(item) > 3 else {}
            self.events.emit(topic, event, data, **opts)
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
            request={
                "kind": alert.kind.value,
                "subject": alert.subject,
                "node_id": alert.node_id,
                "title_message": alert.title_message,
            },
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
                # The lock is taken page by page: remote plans and snapshots get in between pages.
                leases.extend(_all_leases(backend, self.node_id, self.backend_lock))
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
            # RPZ policy zones hold block lists, not hosts: never read in full.
            if zone.kind is not ZoneKind.PRIMARY or zone.notes == "pelagos-rpz":
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


def plan_step(
    plan: Any, node_id: str, origin: str | None, verb: str, phase: str, result: Any = None
) -> dict[str, Any]:
    """Payload of `plans`/`step` (section 18): one node's part of an apply or rollback."""
    data: dict[str, Any] = {
        "plan_id": plan.id,
        "scope": plan.scope.value,
        "node_id": node_id,
        "origin_node_id": origin,
        "verb": verb,
        "state": "running"
        if phase == "running"
        else ("done" if result is not None and result.ok else "failed"),
    }
    if result is not None:
        data["ok"] = bool(result.ok)
        # Engine and peer messages can quote key material: masked as PlanService does.
        data["message"] = masked_text(result.message) if result.message else None
    return data


def _all_leases(backend: DhcpBackend, node_id: str, lock: Any = None) -> list[Lease]:
    """Walk lease4-get-page / lease6-get-page through the ABC's paging arguments.

    Leases are projected on what the consistency checks read: the raw Kea answer and the user
    context are dropped, which keeps a large lease table to a fraction of its memory.
    """
    out: list[Lease] = []
    start: str | None = None
    while True:
        if lock is not None:
            with lock:
                page = backend.leases(limit=LEASE_PAGE, from_address=start)
        else:
            page = backend.leases(limit=LEASE_PAGE, from_address=start)
        for lease in page:
            if lease.node_id is None:
                lease.node_id = node_id
            lease.raw = {}
            lease.user_context = {}
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
    from pelagos.services.peer_actions import PeerActions

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
            actions=PeerActions(ctx, service_registry, core_registry.lock),
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


def start_relay(ctx: NodeContext, collector: Collector, replication: Any) -> Any:
    """Peers' UIs get this node's live events (relay) and this node's UI gets theirs (hooks)."""
    from pelagos.collector.relay import PeerEventRelay

    service = getattr(replication, "service", None)
    replicator = getattr(replication, "replicator", None)
    app = getattr(service, "app", None)
    if app is not None:
        app.on_peer_events = collector.on_peer_events
        app.on_plan = collector.on_peer_plan
    if replicator is None:
        return None

    def send(peer: Any, batch: list[dict[str, Any]]) -> Any:
        client = replicator.client(peer)
        client.timeout = 3.0
        return client.push_events(batch)

    relay = PeerEventRelay(lambda: [p for p in ctx.cluster().nodes if p.id != ctx.node.id], send)
    collector.events.relay = relay.offer
    relay.start()
    return relay


# Exit status asking the service manager for a restart (Restart=on-failure): the engines changed.
EXIT_ENGINES_CHANGED = 75
# A peer's installer plan rewrites node.toml before its verify step: the exit waits for it to answer.
EXIT_WAIT_MAX = 600.0


def exit_due(changed_at: float | None, now: float, in_flight: int) -> bool:
    """True when the collector may exit for an engines change seen at `changed_at`."""
    if changed_at is None:
        return False
    return in_flight == 0 or now - changed_at >= EXIT_WAIT_MAX


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
        try:
            engines = self.ctx.config_store.load_node().engines
        except Exception:  # unreadable for now: keep the connectors, read it again next loop
            log.exception("node.toml not readable")
            return False
        self._mtime = mtime
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
        peer_poll = float(reg.get(collector.ctx.settings(), "collector.peer_poll_seconds"))
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
# How often the loop looks for a new cluster.toml version or audit head (`system`/`replication`).
REPLICATION_CHECK_SECONDS = 2.0


def publish_own_modules(ctx: NodeContext) -> bool:
    """Each node owns its [[nodes]].modules entry: when cluster.toml says something else than
    node.toml [engines] (a peer wrote that entry later), publish it again."""
    try:
        # node.toml as it is now: ctx.node predates an import until the collector restarts.
        modules = ctx.config_store.load_node().modules
        own = ctx.config_store.load_cluster().peer(ctx.node.id)
    except Exception:
        log.exception("node.toml or cluster.toml not readable")
        return False
    if own is None or own.modules == modules:
        return False

    def mutate(cfg: Any) -> None:
        peer = cfg.peer(ctx.node.id)
        if peer is not None:
            peer.modules = modules

    ctx.config_store.update_cluster(mutate, updated_by=f"node:{ctx.node.id}")
    log.info("published this node's modules in cluster.toml again")
    return True


def run(paths: Paths, once: bool = False, rebuild: bool = False) -> int:
    ctx = NodeContext.build(paths)
    from pelagos.core.write_pipeline import recover_in_place_writes

    try:
        recover_in_place_writes(paths.backups_dir)
    except Exception:  # never blocks the start
        log.exception("in-place write recovery failed")
    try:
        moved = ctx.migrate_settings()
        if moved:
            log.info("settings renamed in cluster.toml: %s", ", ".join(f"{a} -> {b}" for a, b in moved))
    except Exception:  # never blocks the start: every load migrates in memory anyway
        log.exception("settings migration failed")
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

    collector.slow_background = True
    tasks = collector.tasks()
    listener = SignalListener(paths.collector_sock)
    # One replay per batch of datagrams, run by the loop after listener.wait().
    acks_due = threading.Event()
    listener.on("audit", lambda _msg: acks_due.set())
    listener.on("audit_merged", lambda _msg: acks_due.set())
    listener.on("consistency", lambda _msg: (collector.consistency(), collector.apply_exceptions()))
    rpz_due = threading.Event()

    def rpz_request(msg: dict[str, Any]) -> None:
        if collector.rpz is not None:
            collector.rpz.request(msg.get("id"), bool(msg.get("accept_shrink")))
            rpz_due.set()

    listener.on("rpz", rpz_request)
    collector.listener = listener
    try:
        listener.open()
    except OSError as exc:
        log.warning("signal socket %s unavailable: %s", paths.collector_sock, exc)
    replication = start_replication(ctx, listener, store, backends, collector.backend_lock)
    replicator = getattr(replication, "replicator", None)
    relay = None
    if replicator is not None:
        collector.peers.liveness = replicator
        relay = start_relay(ctx, collector, replication)
    # A write from the web process: the zone serials it moved are read now, not at the next poll.
    bind_due = threading.Event()
    listener.on("audit", lambda _msg: bind_due.set())
    watch = EnginesWatch(ctx)
    settings_watch = SettingsWatch(ctx)
    next_modules_check = 0.0
    next_replication_check = 0.0
    changed_at: float | None = None
    from pelagos.services.registry import plans_in_flight

    try:
        while True:
            if changed_at is None and watch.changed():
                changed_at = time.monotonic()
            if exit_due(changed_at, time.monotonic(), plans_in_flight()):
                log.info("node.toml engines changed: exiting so the service restarts with them")
                return EXIT_ENGINES_CHANGED
            if settings_watch.changed():
                reload_settings(collector, tasks, replication)
            if time.monotonic() >= next_replication_check:
                next_replication_check = time.monotonic() + REPLICATION_CHECK_SECONDS
                collector.replication_events()
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
                        with collector.batch():
                            task.fn()
                    except Exception:
                        log.exception("task %s failed", task.name)
                    task.next_run = now + task.period
            collector.events.flush()
            sleep_for = max(0.5, min(t.next_run for t in tasks) - time.monotonic())
            if collector.events.held or collector.zone_rechecks:
                sleep_for = min(sleep_for, 1.0)
            if listener.sock is not None:
                listener.wait(min(sleep_for, 5.0))
            else:
                time.sleep(min(sleep_for, 5.0))
            if rpz_due.is_set():
                rpz_due.clear()
                for task in tasks:
                    if task.name == "poll_rpz":
                        task.next_run = min(task.next_run, time.monotonic() + 1.0)
            if bind_due.is_set():
                bind_due.clear()
                for task in tasks:
                    if task.name == "poll_bind":
                        task.next_run = min(task.next_run, time.monotonic() + 1.0)
            if collector.zone_rechecks:
                try:
                    with collector.batch():
                        collector.zone_checks()
                except Exception:
                    log.exception("zone recheck failed")
            if acks_due.is_set():
                acks_due.clear()
                try:
                    with collector.batch():
                        collector.apply_acks()
                except Exception:
                    log.exception("ack replay failed")
    except KeyboardInterrupt:
        return 0
    finally:
        if relay is not None:
            relay.close()
        close = getattr(replication, "close", None)
        if callable(close):
            close()
        listener.close()
        conn.close()
