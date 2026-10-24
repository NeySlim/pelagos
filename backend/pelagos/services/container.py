# SPDX-License-Identifier: Apache-2.0
"""Services container: built once per web process, stored in NodeContext.extra["services"]."""

from __future__ import annotations

import logging

from pelagos.core.context import NodeContext
from pelagos.domain import Family
from pelagos.services.account_service import AccountService
from pelagos.services.admin_service import AdminService
from pelagos.services.advanced_service import AdvancedService
from pelagos.services.alerts_service import AlertsService, SeriesCache, SeriesService
from pelagos.services.dashboard_service import DashboardService
from pelagos.services.dhcp_service import DhcpService
from pelagos.services.dns_service import DnsService
from pelagos.services.events import EventHub, EventSocketListener
from pelagos.services.hosts_service import HostsService
from pelagos.services.install_service import InstallService
from pelagos.services.jobs import JobStore
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService
from pelagos.services.registry import ConnectorRegistry

log = logging.getLogger(__name__)


class Services:
    def __init__(
        self, ctx: NodeContext, registry: ConnectorRegistry | None = None, peers: PeerGateway | None = None
    ) -> None:
        self.ctx = ctx
        self.registry = registry if registry is not None else ConnectorRegistry.from_node(ctx)
        self.peers = peers if peers is not None else PeerGateway(ctx)
        self.events = EventHub(ctx.node.id)
        self.jobs = JobStore(self.events)
        self.cache = SeriesCache(ctx.paths.series_db)
        self.alerts = AlertsService(ctx, self.cache, self.events)
        self.series = SeriesService(self.cache)
        self.dns = DnsService(ctx, self.registry.dns, self.peers)
        self.dhcp4 = DhcpService(ctx, Family.V4, self.registry.kea4, self.peers, self.registry.d2)
        self.dhcp6 = DhcpService(ctx, Family.V6, self.registry.kea6, self.peers, self.registry.d2)
        self.plans = PlanService(ctx, self.registry, self.peers, self.events)
        self.hosts = HostsService(ctx, self.dns, self.dhcp4, self.dhcp6, self.alerts, self.plans)
        self.dashboard = DashboardService(
            ctx, self.registry, self.peers, self.dns, self.dhcp4, self.dhcp6, self.alerts
        )
        self.admin = AdminService(ctx)
        self.account = AccountService(ctx)
        self.advanced = AdvancedService(ctx, self.dns)
        self.install = InstallService(ctx, self.dns, self.dhcp4)
        self.listener: EventSocketListener | None = None
        self._publish_audit()
        ctx.extra["services"] = self

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
        if self.listener is not None:
            self.listener.stop()
        self.cache.close()
