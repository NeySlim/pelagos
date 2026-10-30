# SPDX-License-Identifier: Apache-2.0
"""Connector interfaces: the only code that knows BIND and Kea protocols (section 5).

Services and the collector program against these ABCs. WP-BIND implements
DnsBackend, WP-KEA implements DhcpBackend and DdnsBackend. Every method is
synchronous and blocking; failures raise a ConnectorError subclass.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pelagos.core.write_pipeline import WritePipeline
from pelagos.domain import (
    BindConfigTree,
    BindInstanceStats,
    Change,
    ClientClass,
    D2Stats,
    DhcpCapabilities,
    DnsCapabilities,
    Family,
    HAState,
    Lease,
    NodeApplyResult,
    OptionData,
    Plan,
    Precondition,
    Reservation,
    RRset,
    SharedNetwork,
    Subnet,
    ValidationResult,
    Zone,
    ZoneStatus,
)


class ConnectorError(Exception):
    """Base of every connector failure; message is safe to show to the user."""


class ConnectorUnavailable(ConnectorError):
    """The daemon or its control channel is not reachable."""


class ConnectorDenied(ConnectorError):
    """The daemon refused us (bad key, permission)."""


class ZoneWithoutRecords(ConnectorError):
    """The zone's kind (forward, hint, stub, static-stub) has no records named could transfer."""

    def __init__(self, zone: str, view: str, kind: str) -> None:
        super().__init__(f"{zone} is a {kind} zone: named holds no records for it")
        self.zone = zone
        self.view = view
        self.kind = kind


class ZoneTooLarge(ConnectorError):
    """The zone holds more owner names than a bounded read may take (`dns.zone_read_max_names`)."""

    def __init__(self, zone: str, view: str, size: int, limit: int) -> None:
        super().__init__(f"{zone} holds {size} names or more, above the read limit of {limit}")
        self.zone = zone
        self.view = view
        self.size = size
        self.limit = limit


class ConnectorTimeout(ConnectorError):
    pass


class NotSupported(ConnectorError):
    """The engine lacks the feature (for instance host_cmds on Kea 2.6)."""


class ValidationFailed(ConnectorError):
    def __init__(self, result: ValidationResult) -> None:
        super().__init__(f"{result.tool}: {result.output.strip()}")
        self.result = result


class PreconditionFailed(ConnectorError):
    def __init__(self, precondition: Precondition, observed: str) -> None:
        super().__init__(
            f"{precondition.kind.value} on {precondition.subject}: "
            f"expected {precondition.value}, observed {observed}"
        )
        self.precondition = precondition
        self.observed = observed


@dataclass(slots=True)
class ConnectorContext:
    """What a connector needs from the node: identity, paths, secrets and the pipeline factory."""

    node_id: str
    engine_config: dict[str, Any]  # the [engines.bind] or [engines.kea] table of node.toml
    backup_root: Path
    get_secret: Callable[[str], str | None]  # name -> decrypted secret, None when absent
    settings: dict[str, Any]  # cluster.toml [settings] when the connector was built
    pipeline_factory: Callable[..., WritePipeline] = WritePipeline
    # The current [settings]: a setting changed after start (dns.default_ns) applies at once.
    live_settings: Callable[[], dict[str, Any]] | None = None

    def current_settings(self) -> dict[str, Any]:
        return self.live_settings() if self.live_settings is not None else self.settings


class DnsBackend(ABC):
    engine_name = "bind"

    def __init__(self, ctx: ConnectorContext) -> None:
        self.ctx = ctx

    # Observation
    @abstractmethod
    def capabilities(self) -> DnsCapabilities: ...
    @abstractmethod
    def server_status(self) -> dict[str, str]: ...
    @abstractmethod
    def read_config(self) -> BindConfigTree: ...
    @abstractmethod
    def list_zones(self, view: str | None = None) -> list[Zone]: ...
    @abstractmethod
    def zone_status(self, zone: str, view: str | None = None) -> ZoneStatus: ...
    @abstractmethod
    def soa_serial(self, zone: str, view: str | None = None) -> int | None: ...
    @abstractmethod
    def read_zone(self, zone: str, view: str | None = None) -> list[RRset]: ...
    @abstractmethod
    def instance_stats(self) -> BindInstanceStats: ...
    @abstractmethod
    def dnssec_status(self, zone: str, view: str | None = None) -> dict[str, Any]: ...

    # Plans
    @abstractmethod
    def plan_rrset_changes(
        self, zone: str, changes: list[Change], view: str | None = None, created_by: str = ""
    ) -> Plan: ...
    @abstractmethod
    def plan_zone_change(self, change: Change, created_by: str = "") -> Plan: ...
    @abstractmethod
    def plan_config_change(self, changes: list[Change], created_by: str = "") -> Plan: ...
    @abstractmethod
    def apply(self, plan: Plan) -> NodeApplyResult: ...
    @abstractmethod
    def rollback(self, plan: Plan) -> NodeApplyResult: ...

    # Operations
    @abstractmethod
    def reconfig(self) -> str: ...
    @abstractmethod
    def reload(self, zone: str | None = None, view: str | None = None) -> str: ...
    @abstractmethod
    def notify(self, zone: str, view: str | None = None) -> str: ...
    @abstractmethod
    def retransfer(self, zone: str, view: str | None = None) -> str: ...
    @abstractmethod
    def freeze(self, zone: str, view: str | None = None) -> str: ...
    @abstractmethod
    def thaw(self, zone: str, view: str | None = None) -> str: ...
    @abstractmethod
    def sync(self, zone: str | None = None, clean: bool = False) -> str: ...


class DhcpBackend(ABC):
    def __init__(self, ctx: ConnectorContext, family: Family) -> None:
        self.ctx = ctx
        self.family = family

    @property
    def engine_name(self) -> str:
        return self.family.kea_engine.value

    @abstractmethod
    def capabilities(self) -> DhcpCapabilities: ...
    @abstractmethod
    def status(self) -> dict[str, Any]: ...
    @abstractmethod
    def command(self, command: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]: ...
    @abstractmethod
    def config_get(self) -> dict[str, Any]: ...
    @abstractmethod
    def config_hash(self) -> str: ...
    @abstractmethod
    def list_subnets(self) -> list[Subnet]: ...
    @abstractmethod
    def get_subnet(self, subnet_id: int) -> Subnet: ...
    @abstractmethod
    def list_shared_networks(self) -> list[SharedNetwork]: ...
    @abstractmethod
    def list_client_classes(self) -> list[ClientClass]: ...
    @abstractmethod
    def global_options(self) -> list[OptionData]: ...
    @abstractmethod
    def option_defs(self) -> list[dict[str, Any]]: ...
    @abstractmethod
    def list_reservations(self, subnet_id: int | None = None) -> list[Reservation]: ...
    @abstractmethod
    def leases(
        self, subnet_id: int | None = None, limit: int = 500, from_address: str | None = None
    ) -> list[Lease]: ...
    @abstractmethod
    def lease(self, ip_address: str) -> Lease | None: ...
    @abstractmethod
    def leases_by_hw(self, hw_address: str) -> list[Lease]: ...
    @abstractmethod
    def leases_by_hostname(self, hostname: str) -> list[Lease]: ...
    @abstractmethod
    def statistics(self) -> dict[str, Any]: ...
    @abstractmethod
    def pool_utilization(self) -> list[dict[str, Any]]: ...
    @abstractmethod
    def ha_state(self) -> HAState: ...

    @abstractmethod
    def plan_subnet_change(self, change: Change, created_by: str = "") -> Plan: ...
    @abstractmethod
    def plan_shared_network_change(self, change: Change, created_by: str = "") -> Plan: ...
    @abstractmethod
    def plan_reservation_change(self, change: Change, created_by: str = "") -> Plan: ...
    @abstractmethod
    def plan_class_change(self, change: Change, created_by: str = "") -> Plan: ...
    @abstractmethod
    def plan_global_change(self, changes: list[Change], created_by: str = "") -> Plan: ...
    @abstractmethod
    def plan_config_replace(self, config: dict[str, Any], created_by: str = "") -> Plan: ...
    @abstractmethod
    def plan_lease_delete(self, ip_address: str, created_by: str = "") -> Plan: ...
    @abstractmethod
    def plan_ha_maintenance(self, action: str, created_by: str = "") -> Plan: ...
    @abstractmethod
    def plan_service_toggle(self, enable: bool, created_by: str = "") -> Plan: ...
    def plan_adopt(self, source: str, created_by: str = "") -> Plan:
        """Section 9: "file" makes the daemon run its file, "running" makes the file say what runs."""
        raise NotSupported("this backend cannot adopt its configuration file")

    @abstractmethod
    def apply(self, plan: Plan) -> NodeApplyResult: ...
    @abstractmethod
    def rollback(self, plan: Plan) -> NodeApplyResult: ...


class DdnsBackend(ABC):
    engine_name = "d2"

    def __init__(self, ctx: ConnectorContext) -> None:
        self.ctx = ctx

    @abstractmethod
    def capabilities(self) -> dict[str, Any]: ...
    @abstractmethod
    def status(self) -> dict[str, Any]: ...
    @abstractmethod
    def config_get(self) -> dict[str, Any]: ...
    @abstractmethod
    def stats(self) -> D2Stats: ...
    @abstractmethod
    def plan_config_replace(self, config: dict[str, Any], created_by: str = "") -> Plan: ...
    def plan_adopt(self, source: str, created_by: str = "") -> Plan:
        raise NotSupported("this backend cannot adopt its configuration file")

    @abstractmethod
    def apply(self, plan: Plan) -> NodeApplyResult: ...
    @abstractmethod
    def rollback(self, plan: Plan) -> NodeApplyResult: ...
