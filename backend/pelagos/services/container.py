# SPDX-License-Identifier: Apache-2.0
"""Services container: built once per web process, stored in NodeContext.extra["services"]."""

from __future__ import annotations

import logging
import threading

from pelagos.auth.last_login import LastLoginStore
from pelagos.core.context import NodeContext
from pelagos.domain import Family, PlanScope
from pelagos.services.account_service import AccountService
from pelagos.services.admin_service import AdminService
from pelagos.services.advanced_service import AdvancedService
from pelagos.services.alerts_service import AlertsService, SeriesCache, SeriesService
from pelagos.services.archive_restore import ArchiveRestoreService, RestoreWriter
from pelagos.services.archive_service import ArchiveService
from pelagos.services.cert_service import CertService
from pelagos.services.dashboard_service import DashboardService
from pelagos.services.ddns_failover import DdnsFailoverService, RolesWriter
from pelagos.services.ddns_replay import DdnsReplayService
from pelagos.services.dhcp_service import DhcpService
from pelagos.services.dns_service import DnsService
from pelagos.services.events import EventHub, EventSocketListener
from pelagos.services.exceptions_service import ExceptionsService
from pelagos.services.group_watch import GroupWatch
from pelagos.services.hosts_service import HostsService
from pelagos.services.install_service import InstallService
from pelagos.services.ipv6_service import Ipv6Service
from pelagos.services.jobs import JobStore
from pelagos.services.notify_service import NotifyService
from pelagos.services.ops_service import OpsService
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService
from pelagos.services.ptr_service import PtrService
from pelagos.services.registry import ConnectorRegistry
from pelagos.services.rpz_service import RpzService
from pelagos.services.webauthn_service import WebAuthnService

log = logging.getLogger(__name__)

GROUPS_RECHECK_DELAY = 5.0


class Services:
    def __init__(
        self, ctx: NodeContext, registry: ConnectorRegistry | None = None, peers: PeerGateway | None = None
    ) -> None:
        self.ctx = ctx
        self._own_registry = registry is None
        self._node_mtime = self._node_stat()
        self._refresh_lock = threading.Lock()
        self.registry = registry if registry is not None else ConnectorRegistry.from_node(ctx)
        self.peers = peers if peers is not None else PeerGateway(ctx)
        self.events = EventHub(ctx.node.id)
        self.jobs = JobStore(self.events)
        self.cache = SeriesCache(ctx.paths.series_db)
        self.alerts = AlertsService(ctx, self.cache, self.events, self.peers)
        self.series = SeriesService(self.cache, self.peers, ctx.node.id)
        self.dns = DnsService(ctx, self.registry.dns, self.peers)
        self.rpz = RpzService(ctx, self.dns, self.peers)
        self.dhcp4 = DhcpService(
            ctx, Family.V4, self.registry.kea4, self.peers, self.registry.d2, self.alerts
        )
        self.dhcp6 = DhcpService(
            ctx, Family.V6, self.registry.kea6, self.peers, self.registry.d2, self.alerts
        )
        self.plans = PlanService(ctx, self.registry, self.peers, self.events)
        # Plans made of one part per node (HA setup, zone secondaries) register their parts there.
        self.dhcp4.plans = self.dhcp6.plans = self.dns.plans = self.plans
        self.hosts = HostsService(ctx, self.dns, self.dhcp4, self.dhcp6, self.alerts, self.plans)
        self.ptr = PtrService(ctx, self.dns, self.plans, self.hosts._dhcp_services)
        self.dns.ptr = self.ptr
        self.ddns_replay = DdnsReplayService(
            ctx, self.dns, self.hosts._dhcp_services, self.plans, lambda: self.cache.store
        )
        self.ddns_failover = DdnsFailoverService(
            ctx, self.dns, self.registry, self.peers, self.plans, self.ddns_replay
        )
        self.plans.cluster_parts[PlanScope.DNS_FAILOVER] = RolesWriter(ctx)
        restore_writer = RestoreWriter(ctx)
        self.plans.cluster_parts[PlanScope.RESTORE] = restore_writer
        self.archive_restore = ArchiveRestoreService(
            ctx, self.registry, self.peers, self.plans, restore_writer
        )
        self.archives = ArchiveService(ctx, self.peers, self.jobs, self.archive_restore)
        self.exceptions = ExceptionsService(ctx)
        self.dashboard = DashboardService(
            ctx, self.registry, self.peers, self.dns, self.dhcp4, self.dhcp6, self.alerts
        )
        self.admin = AdminService(ctx)
        self.account = AccountService(ctx)
        self.webauthn = WebAuthnService(ctx)
        self.advanced = AdvancedService(ctx, self.dns)
        self.ops = OpsService(ctx, self.registry, self.peers)
        self.install = InstallService(ctx, self.dns, self.dhcp4, self.peers)
        self.certs = CertService(ctx, self.peers, self.jobs, self.dns)
        self.notifications = NotifyService(ctx, self.peers)
        self.ipv6 = Ipv6Service(ctx, self.peers, self.hosts, self.cache)
        self.last_login = LastLoginStore(
            ctx.paths.var / "last_login.json", ctx.paths.locks_dir / "last_login.lock"
        )
        self.listener: EventSocketListener | None = None
        self.groups = GroupWatch(ctx.paths.run, busy=lambda: self.jobs.active() or self.plans.busy())
        # A restart deferred by a job runs once it is done, a moment later so the UI reads the outcome.
        self.jobs.on_finished = lambda job: self._recheck_groups()
        self._publish_audit()
        self._publish_plans()
        ctx.extra["services"] = self

    def _publish_plans(self) -> None:
        """Every plan this process builds goes to the `plans` topic as `validated` (or `failed` when a
        check refused it) once its checks ran (section 18)."""
        store = self.ctx.plan_store
        put = getattr(store.put, "__pelagos_inner__", store.put)
        plans = self.plans

        def publishing_put(plan):  # type: ignore[no-untyped-def]
            stored = put(plan)
            try:
                plans._phase(stored, "validated")
            except Exception:
                log.debug("plan event not published", exc_info=True)
            return stored

        publishing_put.__pelagos_inner__ = put  # type: ignore[attr-defined]
        store.put = publishing_put  # type: ignore[method-assign]

    def _recheck_groups(self) -> None:
        if not self.groups.deferred:
            return
        timer = threading.Timer(GROUPS_RECHECK_DELAY, self.groups.check, kwargs={"force": True})
        timer.daemon = True
        timer.start()

    def _publish_audit(self) -> None:
        """Every entry this process appends also goes to the `audit` WebSocket topic (section 18)."""
        log_ = self.ctx.audit_log
        append = getattr(log_.append, "__pelagos_inner__", log_.append)
        events = self.events

        def publishing_append(entry):  # type: ignore[no-untyped-def]
            append(entry)
            events.publish("audit", "entry", entry)

        publishing_append.__pelagos_inner__ = append  # type: ignore[attr-defined]
        log_.append = publishing_append  # type: ignore[method-assign]

    @classmethod
    def of(cls, ctx: NodeContext) -> Services:
        services = ctx.extra.get("services")
        return services if isinstance(services, Services) else cls(ctx)

    def _node_stat(self) -> int | None:
        try:
            return self.ctx.paths.node_toml.stat().st_mtime_ns
        except OSError:
            return None

    def refresh_engines(self) -> bool:
        """Rebuilds the connectors when node.toml [engines] changed (an import or install ran as
        root): the services keep their objects and get the new backends. True when it did; on a
        registry that cannot be built the previous connectors stay in place."""
        if not self._own_registry:
            return False
        self.groups.check()
        with self._refresh_lock:
            mtime = self._node_stat()
            if mtime == self._node_mtime:
                return False
            self._node_mtime = mtime
            try:
                engines = self.ctx.config_store.load_node().engines
            except Exception:
                log.exception("node.toml not readable; engines kept")
                return False
            if engines == self.ctx.node.engines:
                return False
            previous = self.ctx.node.engines
            self.ctx.node.engines = engines
            try:
                fresh = ConnectorRegistry.from_node(self.ctx)
            except Exception:
                self.ctx.node.engines = previous
                log.exception("engines in node.toml not usable; previous connectors kept")
                return False
            old = [getattr(self.registry, name) for name in ("dns", "kea4", "kea6", "d2")]
            for name in ("dns", "kea4", "kea6", "d2"):
                setattr(self.registry, name, getattr(fresh, name))
            self.dns.local = self.registry.dns
            for service, local in ((self.dhcp4, self.registry.kea4), (self.dhcp6, self.registry.kea6)):
                service.local = local
                service.d2 = self.registry.d2
            kept = (fresh.dns, fresh.kea4, fresh.kea6, fresh.d2)
            for connector in old:
                close = getattr(connector, "close", None)
                if callable(close) and not any(connector is k for k in kept):
                    try:
                        close()
                    except Exception:
                        log.warning("closing a replaced connector failed", exc_info=True)
            log.info("engines reloaded from node.toml")
            self.groups.check(force=True)
            return True

    def dhcp(self, family: Family) -> DhcpService:
        return self.dhcp4 if family is Family.V4 else self.dhcp6

    def start_event_listener(self) -> None:
        """Bind events.sock so collector events reach WebSocket clients; skipped when the dir is missing."""
        path = self.ctx.paths.events_sock
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.listener = EventSocketListener(path, self.events)
            self.listener.start()
        except OSError as exc:
            log.warning("events socket %s not started: %s", path, exc)
            self.listener = None

    def close(self) -> None:
        self.groups.stop()
        if self.listener is not None:
            self.listener.stop()
        self.cache.close()
