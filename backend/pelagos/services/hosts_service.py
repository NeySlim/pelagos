# SPDX-License-Identifier: Apache-2.0
"""Hosts service: the join of lease, reservation and A/AAAA/PTR by MAC, then IP, then name.

Nothing is persisted: every call re-reads leases and reservations from Kea and
records from BIND, and attaches the open inconsistency alerts about the host.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Any

from pelagos.connectors.kea.configfile import FileDiverged
from pelagos.core.context import NodeContext
from pelagos.domain import (
    Alert,
    Change,
    ChangeOp,
    Host,
    Lease,
    LeaseState,
    Plan,
    PlanScope,
    PlanState,
    Reservation,
    ReservationIdType,
    RRset,
    ZoneKind,
    host_key,
    messages,
    normalize_name,
)
from pelagos.services import kea_files, remote_rrset
from pelagos.services.alerts_service import AlertsService
from pelagos.services.dhcp_service import DhcpService
from pelagos.services.dns_service import DnsService
from pelagos.services.errors import (
    ConnectorError,
    EngineUnavailable,
    NotFound,
    ServiceError,
    ValidationError,
    field_error,
)
from pelagos.services.plan_service import PlanService

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
VIEW_RE = re.compile(r"^(?!-)[A-Za-z0-9_.-]{1,64}$")
DEFAULT_VIEW = "_default"
HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class _Join:
    """Mutable host table with three indexes; hosts merge when a MAC, an IP or a name is shared."""

    def __init__(self) -> None:
        self.hosts: dict[str, Host] = {}
        self.by_mac: dict[str, str] = {}
        self.by_ip: dict[str, str] = {}
        self.by_name: dict[str, str] = {}

    def find(self, mac: str | None, ips: Iterable[str], name: str | None) -> Host | None:
        if mac and mac in self.by_mac:
            return self.hosts[self.by_mac[mac]]
        for ip in ips:
            if ip in self.by_ip:
                return self.hosts[self.by_ip[ip]]
        if name and name in self.by_name:
            return self.hosts[self.by_name[name]]
        return None

    def attach(self, mac: str | None, ips: Iterable[str], name: str | None) -> Host:
        ips = [canonical(ip) for ip in ips if ip]
        name = normalize_name(name) if name else None
        host = self.find(mac, ips, name)
        if host is None:
            key = host_key(mac, ips[0] if ips else None, name)
            host = self.hosts.setdefault(key, Host(key=key))
        if mac and not host.mac:
            host.mac = mac
        for ip in ips:
            if ip not in host.ips:
                host.ips.append(ip)
        if name and not host.hostname:
            host.hostname = name
        self.index(host)
        return host

    def index(self, host: Host) -> None:
        if host.mac:
            self.by_mac[host.mac] = host.key
        for ip in host.ips:
            self.by_ip[ip] = host.key
        if host.hostname:
            self.by_name[host.hostname] = host.key


def _join(dhcp_rows: Iterable[Lease | Reservation], records: Iterable[list[RRset]]) -> _Join:
    join = _Join()
    for row in dhcp_rows:
        if isinstance(row, Lease):
            _attach_lease(join, row)
        else:
            _attach_reservation(join, row)
    for rrsets in records:
        for rr in rrsets:
            _attach_rrset(join, rr)
    return join


def _sorted_hosts(join: _Join) -> list[Host]:
    return sorted(join.hosts.values(), key=lambda h: (_ip_sort(h.ips[0]) if h.ips else (9, 0), h.key))


class HostsService:
    def __init__(
        self,
        ctx: NodeContext,
        dns: DnsService | None,
        dhcp4: DhcpService | None,
        dhcp6: DhcpService | None,
        alerts: AlertsService | None = None,
        plans: PlanService | None = None,
    ) -> None:
        self.ctx = ctx
        self.dns = dns
        self.dhcp4 = dhcp4
        self.dhcp6 = dhcp6
        self.alerts = alerts
        self.plans = plans

    # Join ---------------------------------------------------------------

    def _dhcp_services(self) -> list[DhcpService]:
        out = [s for s in (self.dhcp4,) if s is not None]
        if self.dhcp6 is not None and self.ctx.cluster().modules.get("dhcpv6"):
            out.append(self.dhcp6)
        return out

    def collect(self) -> tuple[list[Host], dict[str, str]]:
        """All hosts plus the per-source errors (an engine down removes its data, not the page)."""
        hosts, _judged, errors = self.collect_judged(None)
        return hosts, errors

    def collect_judged(self, judged: Iterable[str] | None) -> tuple[list[Host], list[Host], dict[str, str]]:
        """`collect()` plus the hosts joined from the records of the `judged` zones only (the
        zones a check reads), from the same reads; the second list is empty when `judged` is None."""
        dhcp_rows: list[Lease | Reservation] = []
        errors: dict[str, str] = {}
        for dhcp in self._dhcp_services():
            try:
                leases, _node, partial = dhcp.all_leases()
                if partial:
                    errors[f"{dhcp.engine.value}.leases"] = (
                        f"partial: only the first {len(leases)} leases read"
                    )
            except ServiceError as exc:
                errors[f"{dhcp.engine.value}.leases"] = exc.detail
                leases = []
            dhcp_rows += leases
            try:
                dhcp_rows += dhcp.reservations(None, None)
            except ServiceError as exc:
                errors[f"{dhcp.engine.value}.reservations"] = exc.detail
        records: dict[str, list[RRset]] = {}
        if self.dns is not None:
            try:
                records = self._zone_records(errors)
            except ServiceError as exc:
                errors["dns"] = exc.detail
            except ConnectorError as exc:
                errors["dns"] = str(exc)
        join = _join(dhcp_rows, records.values())
        if self.alerts is not None:
            for alert in self.alerts.open_inconsistencies():
                for host in self._hosts_for_alert(join, alert):
                    if alert not in host.alerts:
                        host.alerts.append(alert)
        subset: list[Host] = []
        if judged is not None:
            names = {normalize_name(z) for z in judged}
            subset = _sorted_hosts(_join(dhcp_rows, (r for z, r in records.items() if z in names)))
        return _sorted_hosts(join), subset, errors

    def _zone_records(self, errors: dict[str, str]) -> dict[str, list[RRset]]:
        """Records of every served zone by zone name; a zone that cannot be read (a refused AXFR)
        is named in `errors["dns.zones"]` and the others are still returned."""
        assert self.dns is not None
        zones = [
            z["zone"]
            for z in self.dns.zones()
            if z["zone"]["kind"] in (ZoneKind.PRIMARY.value, ZoneKind.SECONDARY.value, ZoneKind.MIRROR.value)
        ]
        out: dict[str, list[RRset]] = {}
        unread: list[str] = []
        for zone in zones:
            try:
                rrsets, _node = self.dns.records(zone["name"])
            except NotFound:
                continue  # removed since the zone list was read
            except ServiceError as exc:
                unread.append(f"{zone['name']}: {exc.detail}")
                continue
            except ConnectorError as exc:
                unread.append(f"{zone['name']}: {exc}")
                continue
            out.setdefault(normalize_name(zone["name"]), []).extend(rrsets)
        if unread:
            errors["dns.zones"] = "; ".join(unread)
        return out

    def _hosts_for_alert(self, join: _Join, alert: Alert) -> list[Host]:
        keys: set[str] = set()
        kind, _, value = alert.subject.partition(":")
        if kind == "ip" and value in join.by_ip:
            keys.add(join.by_ip[value])
        if kind == "mac" and value.lower() in join.by_mac:
            keys.add(join.by_mac[value.lower()])
        if kind in ("name", "host"):
            name = normalize_name(value)
            if name in join.by_name:
                keys.add(join.by_name[name])
        details = alert.details or {}
        for field, index in (
            ("ip", join.by_ip),
            ("ip_address", join.by_ip),
            ("mac", join.by_mac),
            ("hw_address", join.by_mac),
        ):
            value = details.get(field)
            if isinstance(value, str) and value.lower() in index:
                keys.add(index[value.lower()])
        for field in ("hostname", "name", "fqdn"):
            value = details.get(field)
            if isinstance(value, str) and normalize_name(value) in join.by_name:
                keys.add(join.by_name[normalize_name(value)])
        return [join.hosts[k] for k in keys]

    # Reads --------------------------------------------------------------

    def list(
        self,
        q: str | None = None,
        subnet_id: int | None = None,
        zone: str | None = None,
        only_inconsistent: bool = False,
    ) -> tuple[list[Host], dict[str, str]]:
        hosts, errors = self.collect()
        if q:
            needle = q.lower().strip()
            hosts = [
                h
                for h in hosts
                if needle in (h.mac or "")
                or any(needle in ip for ip in h.ips)
                or needle in (h.hostname or "")
                or needle in (h.reservation.identifier if h.reservation else "")
            ]
        if subnet_id is not None:
            hosts = [
                h
                for h in hosts
                if (h.lease and h.lease.subnet_id == subnet_id)
                or (h.reservation and h.reservation.subnet_id == subnet_id)
            ]
        if zone:
            suffix = normalize_name(zone)
            hosts = [
                h
                for h in hosts
                if any(normalize_name(r.name).endswith(suffix) for r in h.records)
                or (h.hostname or "").endswith(suffix)
            ]
        if only_inconsistent:
            hosts = [h for h in hosts if h.alerts]
        return hosts, errors

    def get(self, key: str) -> Host:
        key = normalize_key(key)
        hosts, _errors = self.collect()
        for host in hosts:
            if host.key == key:
                return host
        kind, _, value = key.partition(":")
        for host in hosts:
            if (
                (kind == "mac" and host.mac == value)
                or (kind == "ip" and value in host.ips)
                or (kind == "name" and host.hostname == value)
            ):
                return host
        raise NotFound(f"host {key}")

    # Consistency --------------------------------------------------------

    def consistency_pass(self) -> dict[str, Any]:
        """One read-only pass of services.consistency on fresh reads; the collector owns the alert table."""
        from pelagos.collector.events import send_signal
        from pelagos.services import consistency

        leases, reservations = [], []
        errors: dict[str, str] = {}
        for dhcp in self._dhcp_services():
            try:
                rows, _node, partial = dhcp.all_leases()
                leases += rows
                reservations += dhcp.reservations(None, None)
                if partial:
                    # Missing leases would read as DHCID/PTR records without a lease.
                    errors[dhcp.engine.value] = f"partial: only the first {len(rows)} leases read"

            except ServiceError as exc:
                errors[dhcp.engine.value] = exc.detail
        forward: dict[str, list[RRset]] = {}
        reverse: list[RRset] = []
        if self.dns is not None:
            try:
                self._consistency_records(forward, reverse, errors)
            except ServiceError as exc:
                errors["dns"] = exc.detail
            except ConnectorError as exc:
                errors["dns"] = str(exc)
        # A partial read turns into false alerts (PTR into an unread zone): no pass, as the collector.
        alerts = (
            []
            if errors
            else consistency.run_all(
                leases=leases,
                reservations=reservations,
                forward=forward,
                reverse=reverse,
                excepted=consistency.excepted_for(self.ctx.cluster()),
            )
        )
        by_kind: dict[str, int] = {}
        for alert in alerts:
            by_kind[alert.kind.value] = by_kind.get(alert.kind.value, 0) + 1
        # Ask the collector to run its own pass now, which is the one that updates the alert table.
        signalled = send_signal(self.ctx.paths.collector_sock, "consistency")
        return {
            "found": len(alerts),
            "by_kind": by_kind,
            "alerts": [a.to_dict() for a in alerts],
            "errors": errors,
            "collector_signalled": signalled,
        }

    def _consistency_records(
        self, forward: dict[str, list[RRset]], reverse: list[RRset], errors: dict[str, str]
    ) -> None:
        """Records of the primary and secondary zones; an unread zone is named in `errors["dns.zones"]`."""
        assert self.dns is not None
        unread: list[str] = []
        for item in self.dns.zones():
            zone = item["zone"]
            if zone["kind"] not in (ZoneKind.PRIMARY.value, ZoneKind.SECONDARY.value):
                continue
            try:
                rrsets, _node = self.dns.records(zone["name"])
            except NotFound:
                continue  # removed since the zone list was read
            except ServiceError as exc:
                unread.append(f"{zone['name']}: {exc.detail}")
                continue
            except ConnectorError as exc:
                unread.append(f"{zone['name']}: {exc}")
                continue
            if zone["name"].endswith(("in-addr.arpa.", "ip6.arpa.")):
                reverse += rrsets
            else:
                forward[zone["name"]] = rrsets
        if unread:
            errors["dns.zones"] = "; ".join(unread)

    # Plan ---------------------------------------------------------------

    def plan(self, request: dict[str, Any], created_by: str) -> Plan:
        """Expands into dns.rrset (A or AAAA, PTR) and dhcp.reservation changes under scope `host`."""
        if self.plans is None:
            raise EngineUnavailable("plan service not available")
        errors: list[dict[str, str]] = []
        hostname = str(request.get("hostname") or "").strip().lower().rstrip(".")
        zone = normalize_name(str(request.get("zone") or ""))
        ip_text = str(request.get("ip") or "").strip()
        mac = _mac(request.get("mac"))
        ttl = request.get("ttl", 300)
        want_reservation = bool(request.get("reservation", False))
        view = _view(request.get("view"), "view", errors)
        # An absent reverse_view follows `view`; an explicit "_default" puts the PTR in the default view.
        raw_reverse = request.get("reverse_view")
        reverse_view = view if raw_reverse in (None, "") else _view(raw_reverse, "reverse_view", errors)
        if not hostname:
            errors.append(field_error("hostname", "required"))
        elif hostname.endswith(zone.rstrip(".")) and "." in hostname:
            hostname = hostname[: -len(zone.rstrip(".")) - 1]
        if hostname and not HOSTNAME_RE.match(hostname):
            errors.append(field_error("hostname", "must be a single label (letters, digits, hyphen)"))
        if zone == ".":
            errors.append(field_error("zone", "required"))
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            ip = None
            errors.append(field_error("ip", "a valid IPv4 or IPv6 address is required"))
        if request.get("mac") and mac is None:
            errors.append(field_error("mac", "must be aa:bb:cc:dd:ee:ff"))
        if not isinstance(ttl, int) or ttl < 0:
            errors.append(field_error("ttl", "must be a non-negative integer"))
        subnet_raw = request.get("subnet_id")
        if subnet_raw is not None and (not isinstance(subnet_raw, int) or isinstance(subnet_raw, bool)):
            errors.append(field_error("subnet_id", "must be an integer"))
        if want_reservation and mac is None:
            errors.append(field_error("mac", "required for a reservation"))
        if errors:
            raise ValidationError("invalid host request", errors)
        assert ip is not None
        fqdn = f"{hostname}.{zone}"
        if self.dns is None:
            raise EngineUnavailable("DNS is not available on this node")
        parts: list[Plan] = []
        rtype = "A" if ip.version == 4 else "AAAA"
        rr_changes = [Change(ChangeOp.ADD, f"{zone}/{fqdn}/{rtype}", after={"ttl": ttl, "rdata": [str(ip)]})]
        parts.append(self._dns_part(zone, rr_changes, created_by, view))
        reverse_zone = request.get("reverse_zone")
        ptr_name = ip.reverse_pointer + "."
        if reverse_zone:
            reverse_zone = normalize_name(str(reverse_zone))
        else:
            reverse_zone = self._find_reverse_zone(ptr_name, reverse_view)
        if reverse_zone:
            ptr = [
                Change(ChangeOp.ADD, f"{reverse_zone}/{ptr_name}/PTR", after={"ttl": ttl, "rdata": [fqdn]})
            ]
            parts.append(self._dns_part(reverse_zone, ptr, created_by, reverse_view))
        if want_reservation:
            dhcp = self.dhcp4 if ip.version == 4 else self.dhcp6
            if dhcp is None or dhcp.local is None:
                raise EngineUnavailable(f"this node does not run Kea for {rtype} reservations")
            subnet_id = request.get("subnet_id")
            if subnet_id is None:
                subnet_id = self._find_subnet(dhcp, ip)
            if subnet_id is None:
                raise ValidationError(
                    "no subnet contains this address; pass subnet_id", [field_error("subnet_id", "required")]
                )
            # `after` is a Reservation dict (section 5); the connector maps it to Kea keys.
            reservation = Reservation(
                subnet_id=int(subnet_id),
                id_type=ReservationIdType.HW_ADDRESS,
                identifier=mac,
                ip_address=str(ip) if ip.version == 4 else None,
                ip_addresses=[str(ip)] if ip.version == 6 else [],
                hostname=hostname,
            )
            if request.get("notes"):
                reservation.user_context = {
                    "pelagos": {"notes": str(request["notes"]), "updated_by": created_by}
                }
            after = {k: v for k, v in reservation.to_dict().items() if v not in (None, [], {})}
            target = f"{dhcp.subnet_key}/{int(subnet_id)}/reservations/hw-address={mac}"
            targets = dhcp._all_nodes()
            kea_files.check(
                dhcp.alerts,
                dhcp.engine,
                targets,
                self.ctx.node.id,
                dhcp.local,
                dhcp._node_names(),
                dhcp.peers,
            )
            try:
                part = dhcp.local.plan_reservation_change(
                    Change(ChangeOp.ADD, target, after=after), created_by
                )
            except FileDiverged as exc:
                raise kea_files.from_connector(dhcp.engine, exc, self.ctx.node.id) from None
            # Every Kea of the HA pair carries the reservation, as reservation plans do.
            part.target_node_ids = targets
            parts.append(part)
        plan = Plan(
            scope=PlanScope.HOST,
            node_id=self.ctx.node.id,
            **_host_summary(fqdn, ip, mac if want_reservation else None),
            created_by=created_by,
            engine=None,
        )
        targets: list[str] = []
        for part in parts:
            plan.changes.extend(part.changes)
            plan.diff += part.diff if not plan.diff or plan.diff.endswith("\n") else "\n" + part.diff
            plan.preconditions.extend(part.preconditions)
            plan.validations.extend(part.validations)
            plan.requires_confirmation = plan.requires_confirmation or part.requires_confirmation
            for node_id in part.target_node_ids:
                if node_id not in targets:
                    targets.append(node_id)
        plan.target_node_ids = targets
        failed = [p for p in parts if p.state is PlanState.FAILED]
        plan.state = PlanState.FAILED if failed else PlanState.VALIDATED
        plan.error = "; ".join(p.error or "validation failed" for p in failed) or None
        self.plans.register_composite(plan, parts)
        return self.ctx.plan_store.put(plan)

    def _dns_part(self, zone: str, changes: list[Change], created_by: str, view: str | None = None) -> Plan:
        """An RRset plan applied where the zone is primary (this node, or the peer holding it), in
        `view` with that view's key. Without BIND here, the plan is built from the primary's records
        and applied there."""
        assert self.dns is not None
        if self.dns.local is None:
            return remote_rrset.plan_on_primary(self.dns, self.ctx, zone, changes, created_by, view)
        part = self.dns.local.plan_rrset_changes(zone, changes, view, created_by)
        primary = self.dns._primary_node(normalize_name(zone), view)
        if primary is not None:
            part.target_node_ids = [primary]
        return part

    def _find_reverse_zone(self, ptr_name: str, view: str | None = None) -> str | None:
        assert self.dns is not None
        try:
            zones = [
                z["zone"]["name"]
                for z in self.dns.zones(view)
                if z["zone"]["kind"] == ZoneKind.PRIMARY.value
                and z["zone"].get("view", DEFAULT_VIEW) == (view or DEFAULT_VIEW)
            ]
        except ServiceError:
            return None
        candidates = [
            z for z in zones if ptr_name.endswith("." + z) and z.endswith(("in-addr.arpa.", "ip6.arpa."))
        ]
        return max(candidates, key=len) if candidates else None

    @staticmethod
    def _find_subnet(dhcp: DhcpService, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> int | None:
        try:
            subnets, _util, _node = dhcp.subnets()
        except ServiceError:
            return None
        for subnet in subnets:
            try:
                if ip in ipaddress.ip_network(subnet.subnet, strict=False):
                    return subnet.id
            except ValueError:
                continue
        return None


def touches(plan: Plan) -> tuple[bool, bool]:
    """(dns, dhcp) engines a host plan writes to, from its change targets."""
    dns = any("/reservations/" not in c.target for c in plan.changes)
    dhcp = any("/reservations/" in c.target for c in plan.changes)
    return dns, dhcp


def normalize_key(key: str) -> str:
    kind, _, value = key.partition(":")
    if kind == "mac":
        return "mac:" + value.lower()
    if kind == "ip":
        return "ip:" + canonical(value)
    if kind == "name":
        return "name:" + normalize_name(value)
    raise ValidationError(f"host key must start with mac:, ip: or name: (got {key!r})")


def canonical(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return ip.strip().lower()


def reverse_to_ip(name: str) -> str | None:
    name = normalize_name(name)
    if name.endswith(".in-addr.arpa."):
        parts = name[: -len(".in-addr.arpa.")].split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return ".".join(reversed(parts))
        return None
    if name.endswith(".ip6.arpa."):
        nibbles = name[: -len(".ip6.arpa.")].split(".")
        if len(nibbles) != 32:
            return None
        hex_text = "".join(reversed(nibbles))
        try:
            return str(ipaddress.IPv6Address(int(hex_text, 16)))
        except ValueError:
            return None
    return None


def join_hosts(
    leases: Iterable[Lease], reservations: Iterable[Reservation], rrsets: Iterable[RRset]
) -> list[Host]:
    """The hosts join over data already read (the collector's consistency pass)."""
    join = _Join()
    for lease in leases:
        _attach_lease(join, lease)
    for res in reservations:
        _attach_reservation(join, res)
    for rr in rrsets:
        _attach_rrset(join, rr)
    return list(join.hosts.values())


def _attach_lease(join: _Join, lease: Lease) -> None:
    host = join.attach(_mac(lease.hw_address), [lease.ip_address], _name(lease.hostname))
    if host.lease is None or (
        host.lease.state is not LeaseState.DEFAULT and lease.state is LeaseState.DEFAULT
    ):
        host.lease = lease


def _attach_reservation(join: _Join, res: Reservation) -> None:
    mac = res.identifier if res.id_type is ReservationIdType.HW_ADDRESS else None
    ips = [res.ip_address] if res.ip_address else list(res.ip_addresses)
    host = join.attach(_mac(mac), ips, _name(res.hostname))
    if host.reservation is None:
        host.reservation = res


def _attach_rrset(join: _Join, rr: RRset) -> None:
    if rr.rtype in ("A", "AAAA"):
        owner = normalize_name(rr.name)
        for ip in rr.rdata:
            _add_record(join.attach(None, [ip], owner), rr)
    elif rr.rtype == "PTR":
        ip = reverse_to_ip(rr.name)
        if ip is None:
            return
        target = normalize_name(rr.rdata[0]) if rr.rdata else None
        _add_record(join.attach(None, [ip], target), rr)


def _add_record(host: Host, rr: RRset) -> None:
    if not any(r.name == rr.name and r.rtype == rr.rtype for r in host.records):
        host.records.append(rr)


def _view(value: Any, field: str, errors: list[dict[str, str]]) -> str | None:
    """A view name, None for the default view."""
    if value in (None, "", DEFAULT_VIEW):
        return None
    if not isinstance(value, str) or not VIEW_RE.match(value):
        errors.append(field_error(field, "a view name"))
        return None
    return value


def _mac(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", text):
        text = ":".join(text[i : i + 2] for i in range(0, 12, 2))
    return text if MAC_RE.match(text) else None


def _name(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip().lower()
    return value if value else None


def _ip_sort(ip: str) -> tuple[int, int]:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version, int(addr)
    except ValueError:
        return 9, 0


def _host_summary(fqdn: str, ip: str, mac: str | None) -> dict[str, Any]:
    m = (
        messages.msg("plan.host.reserved", fqdn=fqdn, ip=ip, mac=mac)
        if mac
        else messages.msg("plan.host", fqdn=fqdn, ip=ip)
    )
    return {"summary": messages.render(m), "summary_message": m}
