# SPDX-License-Identifier: Apache-2.0
"""KeaBackend: DhcpBackend over the kea-dhcp4 / kea-dhcp6 control socket.

Reads project config-get and the lease, statistic and status commands into
domain objects. Writes are plans: every plan computes the edited Dhcp4/Dhcp6
object in memory (diff, config-test), and `apply` picks the path at run time
from the loaded hooks: object commands plus config-write on Kea 3.x, or
config-test, config-set and config-write everywhere else. The CONFIG_HASH
precondition is checked just before writing.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

from pelagos.connectors.base import (
    ConnectorContext,
    ConnectorDenied,
    ConnectorError,
    DhcpBackend,
    NotSupported,
    PreconditionFailed,
    ValidationFailed,
)
from pelagos.connectors.kea import config as kcfg
from pelagos.connectors.kea.commands import (
    command_path_available,
    lease_from_kea,
    lease_to_kea_add,
    normalize_version,
    object_commands,
    pool_utilization_from_stats,
)
from pelagos.connectors.kea.control_socket import EMPTY, KeaCommandError, KeaControlSocket
from pelagos.connectors.kea.ha import MAINTENANCE_COMMANDS, ha_state_from_status
from pelagos.connectors.kea.schema import config_schema
from pelagos.domain import (
    Change,
    ChangeOp,
    ClientClass,
    DhcpCapabilities,
    Family,
    HAState,
    Lease,
    NodeApplyResult,
    OptionData,
    Plan,
    PlanScope,
    PlanState,
    Precondition,
    PreconditionKind,
    Reservation,
    SharedNetwork,
    Subnet,
    ValidationResult,
    utcnow,
)

HOOK_PREFIX = "libdhcp_"
WRITE_COMMANDS = frozenset({"config-set", "config-write", "config-reload", "shutdown"})
KNOWN_HOOKS = ("lease_cmds", "host_cmds", "subnet_cmds", "stat_cmds", "ha", "class_cmds")
LEASE_PAGE = 1000
# Target kinds (config.parse_target) each configuration plan scope may touch.
SCOPE_TARGETS = {
    PlanScope.DHCP_SUBNET: {"subnet"},
    PlanScope.DHCP_SHARED_NETWORK: {"shared_network"},
    PlanScope.DHCP_RESERVATION: {"reservation"},
    PlanScope.DHCP_CLASS: {"client_class"},
    PlanScope.DHCP_OPTIONS: {"option", "key"},
    PlanScope.DHCP_DDNS: {"key"},
    PlanScope.DHCP_CONFIG: {"option", "key", "config"},
}
# Top-level keys holding objects that have their own plans (and permissions).
OBJECT_KEYS = frozenset({"subnet4", "subnet6", "shared-networks", "reservations", "client-classes"})


def hook_name(library: str) -> str:
    base = Path(library).name
    if base.startswith(HOOK_PREFIX):
        base = base[len(HOOK_PREFIX) :]
    return base.removesuffix(".so")


class KeaBackend(DhcpBackend):
    def __init__(self, ctx: ConnectorContext, family: Family) -> None:
        super().__init__(ctx, family)
        cfg = ctx.engine_config
        n = 4 if family is Family.V4 else 6
        socket_dir = Path(cfg.get("socket_dir", "/run/kea"))
        name = cfg.get(f"dhcp{n}_socket", f"kea{n}-ctrl-socket")
        self.socket = KeaControlSocket(socket_dir / name)
        self.conf_path = Path(cfg.get(f"dhcp{n}_conf", f"/etc/kea/kea-dhcp{n}.conf"))
        self.backup_root = Path(ctx.backup_root) / self.engine_name
        self.plan_ttl = int((ctx.settings or {}).get("plan_ttl_seconds", 600))
        self._version: str | None = None

    # Helpers ----------------------------------------------------------------------

    @property
    def root_key(self) -> str:
        return kcfg.root_key(self.family)

    @property
    def n(self) -> str:
        return "4" if self.family is Family.V4 else "6"

    def version(self) -> str | None:
        if self._version is None:
            self._version = normalize_version(self.socket.version())
        return self._version

    def _wrap(self, cfg: dict[str, Any]) -> dict[str, Any]:
        return {self.root_key: cfg}

    def _subnets_of(self, cfg: dict[str, Any]) -> list[Subnet]:
        version = self.version()
        return [
            kcfg.subnet_from_kea(obj, self.family, net, version)
            for obj, net in kcfg.iter_subnets(cfg, self.family)
        ]

    # Observation ----------------------------------------------------------------------

    def capabilities(self) -> DhcpCapabilities:
        try:
            config = self.config_get()
        except ConnectorError:
            return DhcpCapabilities(
                engine=self.family.kea_engine, running=False, control_socket=str(self.socket.path)
            )
        hooks = [hook_name(h.get("library", "")) for h in config.get("hooks-libraries", [])]
        has = {h: (h in hooks) for h in KNOWN_HOOKS}
        return DhcpCapabilities(
            engine=self.family.kea_engine,
            version=self.version(),
            running=True,
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

    def config_schema(self) -> dict[str, Any]:
        """Advanced editor description for this server's Kea series (GET /advanced/kea/{family}/schema)."""
        return config_schema(self.family.value, self.version())

    def command(self, command: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        if command in WRITE_COMMANDS:
            raise ConnectorDenied(f"{command} must go through a plan")
        return self.socket.call(command, arguments, allow_empty=True)

    def config_get(self) -> dict[str, Any]:
        return self.socket.config_get()[self.root_key]

    def config_hash(self) -> str:
        return self.socket.config_hash()

    def list_subnets(self) -> list[Subnet]:
        return self._subnets_of(self.config_get())

    def get_subnet(self, subnet_id: int) -> Subnet:
        cfg = self.config_get()
        found = kcfg.find_subnet(cfg, self.family, subnet_id)
        if found is None:
            raise ConnectorError(f"subnet {subnet_id} not found")
        container, idx, net = found
        return kcfg.subnet_from_kea(container[idx], self.family, net, self.version())

    def list_shared_networks(self) -> list[SharedNetwork]:
        version = self.version()
        return [
            kcfg.shared_network_from_kea(obj, self.family, version)
            for obj in self.config_get().get("shared-networks") or []
        ]

    def list_client_classes(self) -> list[ClientClass]:
        version = self.version()
        return [
            kcfg.client_class_from_kea(obj, version) for obj in self.config_get().get("client-classes") or []
        ]

    def global_options(self) -> list[OptionData]:
        return kcfg.options_from_kea(self.config_get().get("option-data"), self.family)

    def option_defs(self) -> list[dict[str, Any]]:
        return [dict(d) for d in self.config_get().get("option-def") or []]

    def list_reservations(self, subnet_id: int | None = None) -> list[Reservation]:
        """reservation-get-page through host_cmds (config and database hosts), else the config."""
        cfg = self.config_get()
        hooks = [hook_name(h.get("library", "")) for h in cfg.get("hooks-libraries", [])]
        if "host_cmds" in hooks:
            return self._reservations_paged(cfg, subnet_id)
        out: list[Reservation] = []
        if subnet_id is None or subnet_id == 0:
            out.extend(kcfg.reservation_from_kea(r, None) for r in cfg.get("reservations") or [])
        for obj, _net in kcfg.iter_subnets(cfg, self.family):
            sid = int(obj.get("id", 0))
            if subnet_id is None or sid == subnet_id:
                out.extend(kcfg.reservation_from_kea(r, sid) for r in obj.get("reservations") or [])
        return out

    def _reservations_paged(self, cfg: dict[str, Any], subnet_id: int | None) -> list[Reservation]:
        subnet_ids = (
            [subnet_id]
            if subnet_id is not None
            else [0, *(int(o.get("id", 0)) for o, _ in kcfg.iter_subnets(cfg, self.family))]
        )
        out: list[Reservation] = []
        for sid in subnet_ids:
            args: dict[str, Any] = {"subnet-id": sid, "limit": LEASE_PAGE}
            while True:
                resp = self.socket.send("reservation-get-page", args)
                result = int(resp.get("result", 1))
                if result == EMPTY:
                    break
                if result != 0:
                    raise KeaCommandError("reservation-get-page", result, str(resp.get("text", "")))
                arguments = resp.get("arguments") or {}
                hosts = arguments.get("hosts") or []
                out.extend(kcfg.reservation_from_kea(h, sid or None) for h in hosts)
                nxt = arguments.get("next") or {}
                if not hosts or len(hosts) < LEASE_PAGE or not nxt:
                    break
                args = {
                    "subnet-id": sid,
                    "limit": LEASE_PAGE,
                    "from": nxt.get("from"),
                    "source-index": nxt.get("source-index", 0),
                }
        return out

    # Leases ---------------------------------------------------------------------------------

    def _leases(self, command: str, arguments: dict[str, Any]) -> list[Lease]:
        resp = self.socket.send(command, arguments)
        result = int(resp.get("result", 1))
        if result == EMPTY:
            return []
        if result != 0:
            raise KeaCommandError(command, result, str(resp.get("text", "")))
        leases = (resp.get("arguments") or {}).get("leases") or []
        return [lease_from_kea(lease, self.family, self.ctx.node_id) for lease in leases]

    def leases(
        self, subnet_id: int | None = None, limit: int = 500, from_address: str | None = None
    ) -> list[Lease]:
        """lease4-get-page / lease6-get-page; a subnet filter walks pages until `limit` leases match."""
        out: list[Lease] = []
        cursor = from_address or "start"
        while len(out) < limit:
            page = self._leases(f"lease{self.n}-get-page", {"from": cursor, "limit": LEASE_PAGE})
            if not page:
                break
            for lease in page:
                if subnet_id is None or lease.subnet_id == subnet_id:
                    out.append(lease)
                    if len(out) >= limit:
                        break
            if len(page) < LEASE_PAGE:
                break
            cursor = page[-1].ip_address
        return out

    def lease(self, ip_address: str) -> Lease | None:
        # lease6-get looks up IA_NA unless told otherwise; a delegated prefix needs type IA_PD.
        lookups = [{}] if self.family is Family.V4 else [{"type": "IA_NA"}, {"type": "IA_PD"}]
        for extra in lookups:
            resp = self.socket.send(f"lease{self.n}-get", {"ip-address": ip_address, **extra})
            result = int(resp.get("result", 1))
            if result == EMPTY:
                continue
            if result != 0:
                raise KeaCommandError(f"lease{self.n}-get", result, str(resp.get("text", "")))
            return lease_from_kea(resp.get("arguments") or {}, self.family, self.ctx.node_id)
        return None

    def leases_by_hw(self, hw_address: str) -> list[Lease]:
        return self._leases(f"lease{self.n}-get-by-hw-address", {"hw-address": hw_address})

    def leases_by_hostname(self, hostname: str) -> list[Lease]:
        return self._leases(f"lease{self.n}-get-by-hostname", {"hostname": hostname})

    def leases_by_duid(self, duid: str) -> list[Lease]:
        if self.family is not Family.V6:
            raise NotSupported("DUID lookups exist for DHCPv6 only")
        return self._leases("lease6-get-by-duid", {"duid": duid})

    # Statistics and HA -----------------------------------------------------------------------

    def statistics(self) -> dict[str, Any]:
        return self.socket.statistic_get_all()

    def pool_utilization(self) -> list[dict[str, Any]]:
        return pool_utilization_from_stats(self.statistics(), self.list_subnets(), self.ctx.node_id)

    def ha_state(self) -> HAState:
        return ha_state_from_status(self.ctx.node_id, self.family, self.status())

    # Plans ------------------------------------------------------------------------------------

    def _new_plan(
        self,
        scope: PlanScope,
        summary: str,
        changes: list[Change],
        created_by: str,
        *,
        diff: str = "",
        preconditions: list[Precondition] | None = None,
        validations: list[ValidationResult] | None = None,
        requires_confirmation: bool = False,
    ) -> Plan:
        validations = validations or []
        failed = [v for v in validations if not v.ok]
        return Plan(
            scope=scope,
            node_id=self.ctx.node_id,
            summary=summary,
            created_by=created_by,
            engine=self.family.kea_engine,
            changes=changes,
            diff=diff,
            preconditions=preconditions or [],
            validations=validations,
            target_node_ids=[self.ctx.node_id],
            requires_confirmation=requires_confirmation,
            state=PlanState.FAILED if failed else PlanState.VALIDATED,
            expires_at=utcnow() + timedelta(seconds=self.plan_ttl),
            error=failed[0].output if failed else None,
        )

    def _hash_precondition(self, value: str) -> Precondition:
        return Precondition(
            kind=PreconditionKind.CONFIG_HASH,
            subject=f"{self.engine_name}:config",
            value=value,
            node_id=self.ctx.node_id,
        )

    def config_test(self, cfg: dict[str, Any]) -> ValidationResult:
        resp = self.socket.send("config-test", self._wrap(cfg))
        ok = int(resp.get("result", 1)) == 0
        return ValidationResult(
            ok=ok, tool="config-test", output=str(resp.get("text", "")), node_id=self.ctx.node_id
        )

    def _before_of(self, cfg: dict[str, Any], change: Change) -> Any:
        """Current state of the change target as a domain dict (or raw value), None when absent."""
        t = kcfg.parse_target(change.target)
        version = self.version()
        if t.kind == "config":
            return cfg
        if t.kind == "subnet":
            if t.subnet_id is None:
                return None
            found = kcfg.find_subnet(cfg, self.family, t.subnet_id)
            if found is None:
                return None
            return kcfg.subnet_from_kea(found[0][found[1]], self.family, found[2], version).to_dict()
        if t.kind == "shared_network":
            items = cfg.get("shared-networks") or []
            idx = kcfg.find_by_name(items, t.name or "")
            return (
                None
                if idx is None
                else kcfg.shared_network_from_kea(items[idx], self.family, version).to_dict()
            )
        if t.kind == "client_class":
            items = cfg.get("client-classes") or []
            idx = kcfg.find_by_name(items, t.name or "")
            return None if idx is None else kcfg.client_class_from_kea(items[idx], version).to_dict()
        if t.kind == "reservation":
            try:
                items = kcfg.reservation_list(json.loads(json.dumps(cfg)), t, self.family)
            except ConnectorError:
                return None
            idx = kcfg.find_reservation(items, t.reservation_key or "")
            return None if idx is None else kcfg.reservation_from_kea(items[idx], t.subnet_id).to_dict()
        if t.kind == "option":
            for obj in cfg.get("option-data") or []:
                if kcfg.option_matches(obj, t.space or "", t.name or "", self.family):
                    return kcfg.option_from_kea(obj, "dhcp" + self.n).to_dict()
            return None
        if t.kind == "key":
            return cfg.get(t.name or "")
        return None

    def _plan_config(self, scope: PlanScope, changes: list[Change], created_by: str, summary: str) -> Plan:
        # The scope decides the permission checked at apply, so every target must belong to it.
        allowed = SCOPE_TARGETS[scope]
        for change in changes:
            t = kcfg.parse_target(change.target)
            if t.kind not in allowed:
                raise ConnectorError(f"{change.target} cannot be changed by a {scope.value} plan")
            if t.kind in ("subnet", "reservation") and change.target.startswith("subnet"):
                if not change.target.startswith(f"subnet{self.n}/"):
                    raise ConnectorError(f"{change.target} is not a {self.engine_name} subnet")
            if t.kind == "key" and t.name in OBJECT_KEYS:
                raise ConnectorError(f"{t.name} changes go through their own plans or the config replace")
        cfg = self.config_get()
        current_hash = self.config_hash()
        version = self.version()
        prepared: list[Change] = []
        for change in changes:
            change = Change.from_dict(change.to_dict())  # private copy
            t = kcfg.parse_target(change.target)
            if t.kind == "subnet" and change.op is ChangeOp.ADD:
                after = dict(change.after or {})
                sid = int(after.get("id") or 0) or t.subnet_id or kcfg.next_subnet_id(cfg, self.family)
                if kcfg.find_subnet(cfg, self.family, sid) is not None:
                    raise ConnectorError(f"subnet {sid} already exists")
                after["id"] = sid
                change.after = after
                change.target = f"subnet{self.n}/{sid}"
            change.before = self._before_of(cfg, change)
            if change.op is ChangeOp.DELETE and change.before is None and t.kind != "key":
                raise ConnectorError(f"{change.target} not found")
            prepared.append(change)
        new_cfg = kcfg.apply_changes(cfg, prepared, self.family, version)
        diff = kcfg.config_diff(cfg, new_cfg, str(self.conf_path))
        validation = self.config_test(new_cfg)
        return self._new_plan(
            scope,
            summary,
            prepared,
            created_by,
            diff=diff,
            preconditions=[self._hash_precondition(current_hash)],
            validations=[validation],
        )

    def plan_subnet_change(self, change: Change, created_by: str = "") -> Plan:
        name = (
            (change.after or change.before or {}).get("subnet")
            if isinstance(change.after or change.before, dict)
            else None
        )
        return self._plan_config(
            PlanScope.DHCP_SUBNET, [change], created_by, f"{change.op.value} subnet {name or change.target}"
        )

    def plan_shared_network_change(self, change: Change, created_by: str = "") -> Plan:
        return self._plan_config(
            PlanScope.DHCP_SHARED_NETWORK, [change], created_by, f"{change.op.value} {change.target}"
        )

    def plan_reservation_change(self, change: Change, created_by: str = "") -> Plan:
        return self._plan_config(
            PlanScope.DHCP_RESERVATION, [change], created_by, f"{change.op.value} reservation {change.target}"
        )

    def plan_class_change(self, change: Change, created_by: str = "") -> Plan:
        return self._plan_config(
            PlanScope.DHCP_CLASS, [change], created_by, f"{change.op.value} {change.target}"
        )

    def plan_global_change(self, changes: list[Change], created_by: str = "") -> Plan:
        """Top-level keys and global option-data; scope follows the keys touched."""
        if not changes:
            raise ConnectorError("no changes")
        targets = [c.target for c in changes]
        if all(t.startswith("ddns-") or t == "dhcp-ddns" for t in targets):
            scope = PlanScope.DHCP_DDNS
        elif any(t in kcfg.CONFIG_SCOPE_KEYS for t in targets):
            scope = PlanScope.DHCP_CONFIG
        else:
            scope = PlanScope.DHCP_OPTIONS
        summary = f"{self.engine_name}: {', '.join(targets[:4])}" + (" ..." if len(targets) > 4 else "")
        return self._plan_config(scope, changes, created_by, summary)

    def plan_config_replace(self, config: dict[str, Any], created_by: str = "") -> Plan:
        """Advanced editor: the whole Dhcp4/Dhcp6 object; the root wrapper is accepted too."""
        if self.root_key in config and len(config) <= 2:
            config = config[self.root_key]
        change = Change(ChangeOp.REPLACE, "config", after=config)
        return self._plan_config(
            PlanScope.DHCP_CONFIG, [change], created_by, f"{self.engine_name}: replace configuration"
        )

    def plan_lease_delete(self, ip_address: str, created_by: str = "") -> Plan:
        lease = self.lease(ip_address)
        if lease is None:
            raise ConnectorError(f"lease {ip_address} not found")
        change = Change(ChangeOp.DELETE, f"lease{self.n}/{ip_address}", before=lease.to_dict())
        who = lease.hw_address or lease.duid or lease.client_id or "?"
        diff = f"-{ip_address} {who} {lease.hostname or ''} subnet {lease.subnet_id}\n"
        return self._new_plan(
            PlanScope.DHCP_LEASE,
            f"delete lease {ip_address}",
            [change],
            created_by,
            diff=diff,
            requires_confirmation=True,
        )

    def plan_ha_maintenance(self, action: str, created_by: str = "") -> Plan:
        """Kea semantics: this server goes partner-in-maintenance and its partner in-maintenance,
        after which the partner can be shut down; "cancel" goes to the same server."""
        if action not in MAINTENANCE_COMMANDS:
            raise ConnectorError("action must be 'start' or 'cancel'")
        state = self.ha_state()
        if not state.enabled:
            raise NotSupported("the ha hook is not loaded on this server")
        remote = ((state.raw.get("ha-servers") or {}).get("remote") or {}).get("server-name") or "the partner"
        if action == "start" and state.state in ("in-maintenance", "partner-in-maintenance"):
            raise ConnectorError(f"HA maintenance already active (state {state.state})")
        if action == "cancel" and state.state != "partner-in-maintenance":
            raise ConnectorError(
                f"cancel goes to the server that started the maintenance (this one is {state.state})"
            )
        effect = (
            f"{remote} goes in-maintenance and can be shut down"
            if action == "start"
            else "both servers return to normal operation"
        )
        change = Change(ChangeOp.REPLACE, "ha/maintenance", before=state.state, after=action)
        precondition = Precondition(
            kind=PreconditionKind.HA_STATE,
            subject=f"{self.engine_name}:ha",
            value=state.state or "",
            node_id=self.ctx.node_id,
        )
        return self._new_plan(
            PlanScope.DHCP_HA,
            f"HA maintenance {action} on {state.server_name or self.engine_name}: {effect}",
            [change],
            created_by,
            diff=f"-state: {state.state}\n+maintenance: {action}\n",
            preconditions=[precondition],
            requires_confirmation=True,
        )

    def plan_service_toggle(self, enable: bool, created_by: str = "") -> Plan:
        status = self.status()
        dhcp_state = status.get("dhcp-state") or {}
        currently = not bool(dhcp_state.get("disabled-by-user", False))
        change = Change(ChangeOp.REPLACE, "service", before={"enabled": currently}, after={"enable": enable})
        verb = "enable" if enable else "disable"
        return self._new_plan(
            PlanScope.DHCP_HA,
            f"{verb} DHCP service ({self.engine_name})",
            [change],
            created_by,
            diff=f"-enabled: {str(currently).lower()}\n+enabled: {str(enable).lower()}\n",
            requires_confirmation=True,
        )

    # Apply and rollback --------------------------------------------------------------------------

    def _check_preconditions(self, plan: Plan) -> None:
        for p in plan.preconditions:
            if p.node_id not in (None, self.ctx.node_id):
                continue
            if p.kind is PreconditionKind.CONFIG_HASH:
                observed = self.config_hash()
            elif p.kind is PreconditionKind.HA_STATE:
                observed = self.ha_state().state or ""
            else:
                continue
            if observed != p.value:
                raise PreconditionFailed(p, observed)

    def apply(self, plan: Plan) -> NodeApplyResult:
        self._check_preconditions(plan)
        return self._run(plan.changes, plan.id, plan.scope)

    def rollback(self, plan: Plan) -> NodeApplyResult:
        """Apply the inverse changes through the same path; a config replace restores the exact JSON."""
        inverse = [c.inverse() for c in reversed(plan.changes)]
        return self._run(inverse, f"{plan.id}-rollback", plan.scope)

    def _run(self, changes: list[Change], label: str, scope: PlanScope) -> NodeApplyResult:
        try:
            if scope is PlanScope.DHCP_LEASE:
                return self._run_lease(changes)
            if scope is PlanScope.DHCP_HA:
                return self._run_ha(changes)
            return self._run_config(changes, label)
        except PreconditionFailed:
            raise
        except ConnectorError as exc:
            return NodeApplyResult(node_id=self.ctx.node_id, ok=False, message=str(exc))

    def _run_lease(self, changes: list[Change]) -> NodeApplyResult:
        messages = []
        for change in changes:
            t = kcfg.parse_target(change.target)
            if t.kind != "lease":
                raise ConnectorError(f"{change.target} is not a lease change")
            if change.op is ChangeOp.DELETE:
                args: dict[str, Any] = {"ip-address": t.name}
                if self.family is Family.V6 and isinstance(change.before, dict):
                    args["type"] = change.before.get("lease_type") or "IA_NA"
                resp = self.socket.send(f"lease{self.n}-del", args)
                if int(resp.get("result", 1)) not in (0, EMPTY):
                    raise KeaCommandError(
                        f"lease{self.n}-del", int(resp["result"]), str(resp.get("text", ""))
                    )
                messages.append(str(resp.get("text", "")))
            elif change.op is ChangeOp.ADD and isinstance(change.after, dict):
                lease = Lease.from_dict(change.after)
                self.socket.call(f"lease{self.n}-add", lease_to_kea_add(lease))
                messages.append(f"lease {lease.ip_address} recreated")
            else:
                raise ConnectorError(f"unsupported lease change {change.op.value}")
        return NodeApplyResult(node_id=self.ctx.node_id, ok=True, message="; ".join(messages))

    def _run_ha(self, changes: list[Change]) -> NodeApplyResult:
        messages = []
        for change in changes:
            t = kcfg.parse_target(change.target)
            if t.kind == "ha":
                action = str(change.after)
                if action not in MAINTENANCE_COMMANDS:
                    # Rolling back "start" means "cancel" and the other way round.
                    action = "cancel" if change.before == "start" else "start"
                command = MAINTENANCE_COMMANDS[action]
                resp = self.socket.send(command)
                if int(resp.get("result", 1)) != 0:
                    raise KeaCommandError(command, int(resp.get("result", 1)), str(resp.get("text", "")))
                messages.append(str(resp.get("text", "")))
            elif t.kind == "service":
                after = change.after if isinstance(change.after, dict) else {}
                enable = bool(after.get("enable", after.get("enabled", True)))
                resp = self.socket.call("dhcp-enable" if enable else "dhcp-disable", None)
                messages.append(json.dumps(resp) if resp else ("enabled" if enable else "disabled"))
            else:
                raise ConnectorError(f"{change.target} is not an HA or service change")
        return NodeApplyResult(node_id=self.ctx.node_id, ok=True, message="; ".join(m for m in messages if m))

    def _backup(self, label: str) -> Path | None:
        if not self.conf_path.exists():
            return None
        pipeline = self.ctx.pipeline_factory(
            self.backup_root,
            validate=lambda: ValidationResult(ok=True, tool="none"),
            reload=lambda: "",
            label=label,
        )
        return pipeline.backup([self.conf_path])

    def _run_config(self, changes: list[Change], label: str) -> NodeApplyResult:
        caps = self.capabilities()
        if not caps.running:
            raise ConnectorError(f"{self.engine_name} is not running")
        version = self.version()
        before = self.config_get()
        before_hash = self.config_hash()
        new_cfg = kcfg.apply_changes(before, changes, self.family, version)
        use_commands = command_path_available(changes, caps)
        hosts_db = bool(before.get("hosts-database") or before.get("hosts-databases"))
        backup_dir = self._backup(label)
        steps: list[str] = []
        mutated = False
        try:
            if use_commands:
                current = before
                for change in changes:
                    for command, args in object_commands(change, self.family, current, version, hosts_db):
                        self.socket.call(command, args)
                        mutated = True
                        steps.append(command)
                    current = kcfg.apply_change(current, change, self.family, version)
            else:
                validation = self.config_test(new_cfg)
                if not validation.ok:
                    raise ValidationFailed(validation)
                steps.append("config-test")
                self.socket.call("config-set", self._wrap(new_cfg))
                mutated = True
                steps.append("config-set")
            problems = self._verify(changes, self.config_get())
            if problems:
                raise ConnectorError("verification failed: " + "; ".join(problems))
            steps.append("verify")
            self.socket.call("config-write")
            steps.append("config-write")
        except ConnectorError as exc:
            rolled_back = False
            if mutated:
                rolled_back = self._restore(before, before_hash, backup_dir)
            path = "commands" if use_commands else "config-set"
            return NodeApplyResult(
                node_id=self.ctx.node_id,
                ok=False,
                message=f"{exc} (path {path}, steps {', '.join(steps) or 'none'})",
                rolled_back=rolled_back,
            )
        path = "commands" if use_commands else "config-set"
        after_hash = self.config_hash()
        hashes = f"config-hash {before_hash[:12]} -> {after_hash[:12]}"
        message = f"applied through {path}: {', '.join(steps)}; {hashes}"
        return NodeApplyResult(node_id=self.ctx.node_id, ok=True, message=message)

    def _restore(self, before: dict[str, Any], before_hash: str, backup_dir: Path | None) -> bool:
        """Put the running config back and keep the file consistent; True when the hash is back."""
        try:
            self.socket.call("config-set", self._wrap(before))
            if self.config_hash() != before_hash:
                return False
            try:
                self.socket.call("config-write")
            except ConnectorError:
                if backup_dir is not None:
                    self.ctx.pipeline_factory(
                        self.backup_root,
                        validate=lambda: ValidationResult(ok=True, tool="none"),
                        reload=lambda: "",
                    ).restore(backup_dir)
            return True
        except ConnectorError:
            return False

    def _verify(self, changes: list[Change], cfg: dict[str, Any]) -> list[str]:
        """Each target must now be present (add, replace) or absent (delete) in the running config."""
        problems = []
        for change in changes:
            t = kcfg.parse_target(change.target)
            if t.kind in ("config", "key", "option"):
                continue
            present = self._before_of(cfg, change) is not None
            if change.op is ChangeOp.DELETE and present:
                problems.append(f"{change.target} still present")
            if change.op is not ChangeOp.DELETE and not present:
                problems.append(f"{change.target} missing")
        return problems
