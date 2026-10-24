# SPDX-License-Identifier: Apache-2.0
"""KeaBackend: DhcpBackend over the kea-dhcp4 / kea-dhcp6 control socket. WP-KEA fills the bodies."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorContext, DhcpBackend
from pelagos.connectors.kea.control_socket import KeaControlSocket
from pelagos.domain import (
    Change,
    ClientClass,
    DhcpCapabilities,
    Family,
    HAState,
    Lease,
    NodeApplyResult,
    OptionData,
    Plan,
    Reservation,
    SharedNetwork,
    Subnet,
)

HOOK_PREFIX = "libdhcp_"
WRITE_COMMANDS = frozenset({"config-set", "config-write", "config-reload", "shutdown"})


def hook_name(library: str) -> str:
    base = Path(library).name
    if base.startswith(HOOK_PREFIX):
        base = base[len(HOOK_PREFIX) :]
    return base.removesuffix(".so")


class KeaBackend(DhcpBackend):
    def __init__(self, ctx: ConnectorContext, family: Family) -> None:
        super().__init__(ctx, family)
        cfg = ctx.engine_config
        socket_dir = Path(cfg.get("socket_dir", "/run/kea"))
        name = cfg.get(
            "dhcp4_socket" if family is Family.V4 else "dhcp6_socket",
            f"kea{4 if family is Family.V4 else 6}-ctrl-socket",
        )
        self.socket = KeaControlSocket(socket_dir / name)
        self.conf_path = Path(
            cfg.get(
                "dhcp4_conf" if family is Family.V4 else "dhcp6_conf",
                f"/etc/kea/kea-dhcp{4 if family is Family.V4 else 6}.conf",
            )
        )

    @property
    def root_key(self) -> str:
        return "Dhcp4" if self.family is Family.V4 else "Dhcp6"

    def capabilities(self) -> DhcpCapabilities:
        """Real enough for the skeleton: hooks from config-get, flags derived from them."""
        try:
            config = self.config_get()
            running = True
        except Exception:
            return DhcpCapabilities(
                engine=self.family.kea_engine, running=False, control_socket=str(self.socket.path)
            )
        hooks = [hook_name(h.get("library", "")) for h in config.get("hooks-libraries", [])]
        has = {h: (h in hooks) for h in ("lease_cmds", "host_cmds", "subnet_cmds", "stat_cmds", "ha")}
        return DhcpCapabilities(
            engine=self.family.kea_engine,
            version=self.socket.version() or None,
            running=running,
            control_socket=str(self.socket.path),
            hooks=hooks,
            lease_cmds=has["lease_cmds"],
            host_cmds=has["host_cmds"],
            subnet_cmds=has["subnet_cmds"],
            stat_cmds=has["stat_cmds"],
            ha=has["ha"],
            degraded=not (has["host_cmds"] and has["subnet_cmds"]),
            config_write=True,
            lease_backend=(config.get("lease-database") or {}).get("type"),
            multi_threading=(config.get("multi-threading") or {}).get("enable-multi-threading"),
        )

    def status(self) -> dict[str, Any]:
        return self.socket.status()

    def command(self, command: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        if command in WRITE_COMMANDS:
            raise PermissionError(f"{command} must go through a plan")
        return self.socket.call(command, arguments, allow_empty=True)

    def config_get(self) -> dict[str, Any]:
        return self.socket.config_get()[self.root_key]

    def config_hash(self) -> str:
        return self.socket.config_hash()

    def list_subnets(self) -> list[Subnet]:
        raise NotImplementedError("WP-KEA")

    def get_subnet(self, subnet_id: int) -> Subnet:
        raise NotImplementedError("WP-KEA")

    def list_shared_networks(self) -> list[SharedNetwork]:
        raise NotImplementedError("WP-KEA")

    def list_client_classes(self) -> list[ClientClass]:
        raise NotImplementedError("WP-KEA")

    def global_options(self) -> list[OptionData]:
        raise NotImplementedError("WP-KEA")

    def option_defs(self) -> list[dict[str, Any]]:
        return list(self.config_get().get("option-def", []))

    def list_reservations(self, subnet_id: int | None = None) -> list[Reservation]:
        raise NotImplementedError("WP-KEA")

    def leases(
        self, subnet_id: int | None = None, limit: int = 500, from_address: str | None = None
    ) -> list[Lease]:
        raise NotImplementedError("WP-KEA")

    def lease(self, ip_address: str) -> Lease | None:
        raise NotImplementedError("WP-KEA")

    def leases_by_hw(self, hw_address: str) -> list[Lease]:
        raise NotImplementedError("WP-KEA")

    def leases_by_hostname(self, hostname: str) -> list[Lease]:
        raise NotImplementedError("WP-KEA")

    def statistics(self) -> dict[str, Any]:
        return self.socket.statistic_get_all()

    def pool_utilization(self) -> list[dict[str, Any]]:
        raise NotImplementedError("WP-KEA")

    def ha_state(self) -> HAState:
        raise NotImplementedError("WP-KEA")

    def plan_subnet_change(self, change: Change, created_by: str = "") -> Plan:
        raise NotImplementedError("WP-KEA")

    def plan_shared_network_change(self, change: Change, created_by: str = "") -> Plan:
        raise NotImplementedError("WP-KEA")

    def plan_reservation_change(self, change: Change, created_by: str = "") -> Plan:
        raise NotImplementedError("WP-KEA")

    def plan_class_change(self, change: Change, created_by: str = "") -> Plan:
        raise NotImplementedError("WP-KEA")

    def plan_global_change(self, changes: list[Change], created_by: str = "") -> Plan:
        raise NotImplementedError("WP-KEA")

    def plan_config_replace(self, config: dict[str, Any], created_by: str = "") -> Plan:
        raise NotImplementedError("WP-KEA")

    def plan_lease_delete(self, ip_address: str, created_by: str = "") -> Plan:
        raise NotImplementedError("WP-KEA")

    def plan_ha_maintenance(self, action: str, created_by: str = "") -> Plan:
        raise NotImplementedError("WP-KEA")

    def plan_service_toggle(self, enable: bool, created_by: str = "") -> Plan:
        raise NotImplementedError("WP-KEA")

    def apply(self, plan: Plan) -> NodeApplyResult:
        raise NotImplementedError("WP-KEA")

    def rollback(self, plan: Plan) -> NodeApplyResult:
        raise NotImplementedError("WP-KEA")
