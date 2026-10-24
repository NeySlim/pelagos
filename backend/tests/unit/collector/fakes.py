# SPDX-License-Identifier: Apache-2.0
"""Fake connectors implementing the section 5 ABCs with mutable state, so tests drive collector cycles."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pelagos.connectors.base import (
    ConnectorContext,
    ConnectorUnavailable,
    DdnsBackend,
    DhcpBackend,
    DnsBackend,
    NotSupported,
)
from pelagos.core.replication import PeerStatus, ReplicationError
from pelagos.domain import (
    BindConfigTree,
    BindInstanceStats,
    Change,
    ClientClass,
    D2Stats,
    DhcpCapabilities,
    DnsCapabilities,
    Family,
    HAPartner,
    HAState,
    Lease,
    NodeApplyResult,
    OptionData,
    Peer,
    Plan,
    Reservation,
    RRset,
    SharedNetwork,
    Subnet,
    Zone,
    ZoneKind,
    ZoneStatus,
)

NODE = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"
PEER = "01JB0ZK4Q9X3M5N7P8R2T4V6W9"


def fake_ctx(node_id: str = NODE) -> ConnectorContext:
    return ConnectorContext(
        node_id=node_id,
        engine_config={},
        backup_root=Path("/nonexistent"),
        get_secret=lambda _n: None,
        settings={},
    )


class FakeDnsBackend(DnsBackend):
    """Zones with serials, zone statuses and RRsets set by the test; `down` makes every call fail."""

    def __init__(self, node_id: str = NODE) -> None:
        super().__init__(fake_ctx(node_id))
        self.node_id = node_id
        self.down = False
        self.running = True
        self.zones: list[Zone] = [
            Zone(name="example.lan.", kind=ZoneKind.PRIMARY, dynamic=True),
            Zone(name="2.0.192.in-addr.arpa.", kind=ZoneKind.PRIMARY, dynamic=True),
        ]
        self.serials: dict[str, int | None] = {
            "example.lan.": 2026102401,
            "2.0.192.in-addr.arpa.": 2026102401,
        }
        self.errors: dict[str, str] = {}
        self.expires: dict[str, datetime] = {}
        self.rrsets: dict[str, list[RRset]] = {"example.lan.": [], "2.0.192.in-addr.arpa.": []}
        self.calls: list[str] = []
        self.read_errors: set[str] = set()

    def _check(self) -> None:
        if self.down:
            raise ConnectorUnavailable("rndc: connect failed: connection refused")

    def capabilities(self) -> DnsCapabilities:
        self._check()
        return DnsCapabilities(version="9.20.30", running=self.running, rndc=True, statistics_channel=True)

    def server_status(self) -> dict[str, str]:
        self._check()
        return {"version": "BIND 9.20.30", "server is up and running": ""}

    def read_config(self) -> BindConfigTree:
        self._check()
        return BindConfigTree(node_id=self.node_id, user_conf="/etc/bind/named.conf", zones=list(self.zones))

    def list_zones(self, view: str | None = None) -> list[Zone]:
        self._check()
        self.calls.append("list_zones")
        return [z for z in self.zones if view is None or z.view == view]

    def zone_status(self, zone: str, view: str | None = None) -> ZoneStatus:
        self._check()
        z = next(x for x in self.zones if x.name == zone)
        now = datetime.now(UTC)
        return ZoneStatus(
            zone=zone,
            view=view or z.view,
            node_id=self.node_id,
            kind=z.kind,
            serial=self.serials.get(zone),
            config_serial=self.serials.get(zone),
            dynamic=z.dynamic,
            signed=False,
            files=[f"{zone}db"],
            expires=self.expires.get(zone),
            last_loaded=None if zone in self.errors else now - timedelta(hours=1),
            error=self.errors.get(zone),
        )

    def soa_serial(self, zone: str, view: str | None = None) -> int | None:
        self._check()
        return self.serials.get(zone)

    def read_zone(self, zone: str, view: str | None = None) -> list[RRset]:
        self._check()
        self.calls.append(f"read_zone:{zone}")
        if zone in self.read_errors:
            raise ConnectorUnavailable(f"AXFR {zone}: transfer refused")
        return list(self.rrsets.get(zone, []))

    def instance_stats(self) -> BindInstanceStats:
        self._check()
        return BindInstanceStats(
            node_id=self.node_id, version="9.20.30", rcodes={"NOERROR": 10}, raw={"x": 1}
        )

    def dnssec_status(self, zone: str, view: str | None = None) -> dict[str, Any]:
        self._check()
        return {}

    def plan_rrset_changes(self, zone, changes, view=None, created_by=""):
        raise NotSupported("fake")

    def plan_zone_change(self, change: Change, created_by: str = "") -> Plan:
        raise NotSupported("fake")

    def plan_config_change(self, changes: list[Change], created_by: str = "") -> Plan:
        raise NotSupported("fake")

    def apply(self, plan: Plan) -> NodeApplyResult:
        raise NotSupported("fake")

    def rollback(self, plan: Plan) -> NodeApplyResult:
        raise NotSupported("fake")

    def reconfig(self) -> str:
        return "ok"

    def reload(self, zone=None, view=None) -> str:
        return "ok"

    def notify(self, zone, view=None) -> str:
        return "ok"

    def retransfer(self, zone, view=None) -> str:
        return "ok"

    def freeze(self, zone, view=None) -> str:
        return "ok"

    def thaw(self, zone, view=None) -> str:
        return "ok"

    def sync(self, zone=None, clean=False) -> str:
        return "ok"


class FakeDhcpBackend(DhcpBackend):
    def __init__(self, family: Family = Family.V4, node_id: str = NODE) -> None:
        super().__init__(fake_ctx(node_id), family)
        self.node_id = node_id
        self.down = False
        self.running = True
        self.hash = "abc123"
        self.subnets: list[Subnet] = [Subnet(id=1, subnet="192.0.2.0/24", family=family)]
        self.utilization: list[dict[str, Any]] = [
            {
                "subnet_id": 1,
                "subnet": "192.0.2.0/24",
                "pool": "192.0.2.100 - 192.0.2.199",
                "total": 100,
                "assigned": 10,
                "declined": 0,
            }
        ]
        self.ha = HAState(
            node_id=node_id,
            family=family,
            server_name="server1",
            mode=None,
            role="primary",
            state="hot-standby",
            scopes=["server1"],
            partner=HAPartner(role="standby", state="hot-standby", scopes=[], in_touch=True),
            enabled=True,
        )
        self.reservations: list[Reservation] = []
        self.lease_list: list[Lease] = []
        self.stats: dict[str, Any] = {"reclaimed-leases": [[0, "2026-10-24 10:00:00.000000"]]}

    def _check(self) -> None:
        if self.down:
            raise ConnectorUnavailable(f"{self.engine_name}: control socket unreachable")

    def capabilities(self) -> DhcpCapabilities:
        self._check()
        return DhcpCapabilities(
            engine=self.family.kea_engine,
            version="3.2.1",
            running=self.running,
            control_socket="/run/kea/kea4-ctrl-socket",
            hooks=["lease_cmds", "ha", "stat_cmds"],
            lease_cmds=True,
            stat_cmds=True,
            ha=True,
            degraded=False,
        )

    def status(self) -> dict[str, Any]:
        self._check()
        return {"pid": 1234, "uptime": 10, "reload": 10}

    def command(self, command: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        self._check()
        return {"result": 0}

    def config_get(self) -> dict[str, Any]:
        self._check()
        return {"Dhcp4": {}}

    def config_hash(self) -> str:
        self._check()
        return self.hash

    def list_subnets(self) -> list[Subnet]:
        self._check()
        return list(self.subnets)

    def get_subnet(self, subnet_id: int) -> Subnet:
        self._check()
        return next(s for s in self.subnets if s.id == subnet_id)

    def list_shared_networks(self) -> list[SharedNetwork]:
        return []

    def list_client_classes(self) -> list[ClientClass]:
        return []

    def global_options(self) -> list[OptionData]:
        return []

    def option_defs(self) -> list[dict[str, Any]]:
        return []

    def list_reservations(self, subnet_id: int | None = None) -> list[Reservation]:
        self._check()
        return [r for r in self.reservations if subnet_id is None or r.subnet_id == subnet_id]

    def leases(
        self, subnet_id: int | None = None, limit: int = 500, from_address: str | None = None
    ) -> list[Lease]:
        self._check()
        rows = sorted(self.lease_list, key=lambda lease: lease.ip_address)
        if from_address is not None:
            rows = [x for x in rows if x.ip_address > from_address]
        return rows[:limit]

    def lease(self, ip_address: str) -> Lease | None:
        return next((x for x in self.lease_list if x.ip_address == ip_address), None)

    def leases_by_hw(self, hw_address: str) -> list[Lease]:
        return [x for x in self.lease_list if x.hw_address == hw_address]

    def leases_by_hostname(self, hostname: str) -> list[Lease]:
        return [x for x in self.lease_list if x.hostname == hostname]

    def statistics(self) -> dict[str, Any]:
        self._check()
        return dict(self.stats)

    def pool_utilization(self) -> list[dict[str, Any]]:
        self._check()
        return [dict(r) for r in self.utilization]

    def ha_state(self) -> HAState:
        self._check()
        return self.ha

    def plan_subnet_change(self, change, created_by=""):
        raise NotSupported("fake")

    def plan_shared_network_change(self, change, created_by=""):
        raise NotSupported("fake")

    def plan_reservation_change(self, change, created_by=""):
        raise NotSupported("fake")

    def plan_class_change(self, change, created_by=""):
        raise NotSupported("fake")

    def plan_global_change(self, changes, created_by=""):
        raise NotSupported("fake")

    def plan_config_replace(self, config, created_by=""):
        raise NotSupported("fake")

    def plan_lease_delete(self, ip_address, created_by=""):
        raise NotSupported("fake")

    def plan_ha_maintenance(self, action, created_by=""):
        raise NotSupported("fake")

    def plan_service_toggle(self, enable, created_by=""):
        raise NotSupported("fake")

    def apply(self, plan):
        raise NotSupported("fake")

    def rollback(self, plan):
        raise NotSupported("fake")


class FakeDdnsBackend(DdnsBackend):
    def __init__(self, node_id: str = NODE) -> None:
        super().__init__(fake_ctx(node_id))
        self.node_id = node_id
        self.down = False
        self.totals: dict[str, int] = {
            "update-sent": 0,
            "update-error": 0,
            "update-timeout": 0,
            "update-success": 0,
        }

    def _check(self) -> None:
        if self.down:
            raise ConnectorUnavailable("d2: control socket unreachable")

    def capabilities(self) -> dict[str, Any]:
        self._check()
        return {"running": True, "version": "3.2.1", "control_socket": "/run/kea/kea-ddns-ctrl-socket"}

    def status(self) -> dict[str, Any]:
        self._check()
        return {"pid": 42}

    def config_get(self) -> dict[str, Any]:
        return {"DhcpDdns": {}}

    def stats(self) -> D2Stats:
        self._check()
        return D2Stats(node_id=self.node_id, totals=dict(self.totals), per_key={}, raw={"big": True})

    def plan_config_replace(self, config, created_by=""):
        raise NotSupported("fake")

    def apply(self, plan):
        raise NotSupported("fake")

    def rollback(self, plan):
        raise NotSupported("fake")


class FakePeerClient:
    """PeerClient whose answers the test sets per peer id."""

    def __init__(self) -> None:
        self.reachable: dict[str, bool] = {}
        self.snapshots: dict[tuple[str, str], dict[str, Any]] = {}
        self.calls: list[tuple[str, str]] = []

    def status(self, peer: Peer) -> PeerStatus:
        self.calls.append(("status", peer.id))
        if not self.reachable.get(peer.id, True):
            raise ReplicationError("connection refused")
        return PeerStatus(node_id=peer.id, reachable=True, config_version=3, audit_count=7, version="0.1.0")

    def engine_snapshot(self, peer: Peer, engine: str) -> dict[str, Any]:
        self.calls.append((f"snapshot:{engine}", peer.id))
        return self.snapshots.get(
            (peer.id, engine), {"node_id": peer.id, "engine": engine, "ts": 0, "kinds": {}}
        )


def snapshot_payload(node_id: str, engine: str, kinds: dict[str, Any], ts: int = 1000) -> dict[str, Any]:
    return {
        "node_id": node_id,
        "engine": engine,
        "ts": ts,
        "kinds": {k: {"ts": ts, "payload": v} for k, v in kinds.items()},
    }
