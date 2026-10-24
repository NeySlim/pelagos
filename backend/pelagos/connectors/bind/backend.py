# SPDX-License-Identifier: Apache-2.0
"""BindBackend: DnsBackend over rndc, statistics-channel, AXFR and signed UPDATE. WP-BIND fills the bodies."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorContext, DnsBackend
from pelagos.connectors.bind.dns_client import DnsClient, TsigKey
from pelagos.connectors.bind.rndc import RndcClient
from pelagos.connectors.bind.stats import StatsClient
from pelagos.domain import (
    BindConfigTree,
    BindInstanceStats,
    Change,
    DnsCapabilities,
    NodeApplyResult,
    Plan,
    RRset,
    Zone,
    ZoneStatus,
)


class BindBackend(DnsBackend):
    """Wiring of the three local channels; every method body is WP-BIND work."""

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        cfg = ctx.engine_config
        self.named_conf = Path(cfg.get("named_conf", "/etc/bind/named.conf"))
        self.include_dir = Path(cfg.get("include_dir", "/etc/bind/pelagos"))
        self.rndc = RndcClient(
            Path(cfg.get("rndc_conf", "/etc/bind/rndc.conf")),
            server=cfg.get("rndc_address", "127.0.0.1"),
            port=int(cfg.get("rndc_port", 953)),
        )
        self.stats = StatsClient(cfg.get("statistics_url", "http://127.0.0.1:8053/json/v1"))
        self.dns = DnsClient(cfg.get("query_address", "127.0.0.1"), int(cfg.get("query_port", 53)))

    def _key(self, role: str) -> TsigKey | None:
        name = self.ctx.settings.get("dns", {}).get(f"{role}_key")
        secret = self.ctx.get_secret(f"tsig/{name}") if name else None
        return TsigKey(name, secret) if name and secret else None

    def capabilities(self) -> DnsCapabilities:
        raise NotImplementedError("WP-BIND")

    def server_status(self) -> dict[str, str]:
        return self.rndc.status()

    def read_config(self) -> BindConfigTree:
        raise NotImplementedError("WP-BIND")

    def list_zones(self, view: str | None = None) -> list[Zone]:
        raise NotImplementedError("WP-BIND")

    def zone_status(self, zone: str, view: str | None = None) -> ZoneStatus:
        raise NotImplementedError("WP-BIND")

    def soa_serial(self, zone: str, view: str | None = None) -> int | None:
        return self.dns.soa_serial(zone)

    def read_zone(self, zone: str, view: str | None = None) -> list[RRset]:
        return self.dns.axfr(zone, self._key("read"))

    def instance_stats(self) -> BindInstanceStats:
        return self.stats.instance_stats(self.ctx.node_id)

    def dnssec_status(self, zone: str, view: str | None = None) -> dict[str, Any]:
        raise NotImplementedError("WP-BIND")

    def plan_rrset_changes(
        self, zone: str, changes: list[Change], view: str | None = None, created_by: str = ""
    ) -> Plan:
        raise NotImplementedError("WP-BIND")

    def plan_zone_change(self, change: Change, created_by: str = "") -> Plan:
        raise NotImplementedError("WP-BIND")

    def plan_config_change(self, changes: list[Change], created_by: str = "") -> Plan:
        raise NotImplementedError("WP-BIND")

    def apply(self, plan: Plan) -> NodeApplyResult:
        raise NotImplementedError("WP-BIND")

    def rollback(self, plan: Plan) -> NodeApplyResult:
        raise NotImplementedError("WP-BIND")

    def reconfig(self) -> str:
        return self.rndc.run("reconfig")

    def reload(self, zone: str | None = None, view: str | None = None) -> str:
        args = ["reload"] + ([zone] if zone else []) + ([view] if zone and view else [])
        return self.rndc.run(*args)

    def notify(self, zone: str, view: str | None = None) -> str:
        return self.rndc.run("notify", zone, *([view] if view else []))

    def retransfer(self, zone: str, view: str | None = None) -> str:
        return self.rndc.run("retransfer", zone, *([view] if view else []))

    def freeze(self, zone: str, view: str | None = None) -> str:
        return self.rndc.run("freeze", zone, *([view] if view else []))

    def thaw(self, zone: str, view: str | None = None) -> str:
        return self.rndc.run("thaw", zone, *([view] if view else []))

    def sync(self, zone: str | None = None, clean: bool = False) -> str:
        args = ["sync"] + (["-clean"] if clean else []) + ([zone] if zone else [])
        return self.rndc.run(*args)
