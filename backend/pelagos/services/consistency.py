# SPDX-License-Identifier: Apache-2.0
"""DNS/DHCP consistency checks (section 15, cross kinds). Owned by WP-COLLECTOR, run by the collector.

Pure functions over domain objects: the collector feeds leases, reservations and
RRsets it has read; this module returns the Alerts that are currently true.
Managed zones are recognized by their SOA at the apex; when a list carries no SOA
at all, every name in it counts as managed (crafted inputs in tests).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from typing import Any

from pelagos.domain import (
    EXCEPTABLE_KINDS,
    Alert,
    AlertKind,
    Lease,
    LeaseState,
    Reservation,
    ReservationIdType,
    RRset,
    Severity,
    exception_keys,
    messages,
)
from pelagos.domain.dns import normalize_name

ADDRESS_TYPES = ("A", "AAAA")

# Admin exceptions (cluster.toml [[exceptions]]): a check asks excepted(kind, key) before it raises
# for one object; the key is stable for that object (see object keys below and section 15).
Excepted = Callable[[str, str], bool]


def _never(_kind: str, _key: str) -> bool:
    return False


def excepted_from(entries: Iterable[dict[str, Any]] | None) -> Excepted:
    """The predicate of a list of exception records; incomplete records (a half-merged file) never match."""
    keys = {
        (str(e["kind"]), str(e["key"]))
        for e in entries or []
        if isinstance(e, dict) and e.get("kind") and e.get("key") is not None
    }
    if not keys:
        return _never
    return lambda kind, key: (kind, key) in keys


def excepted_for(cluster: Any) -> Excepted:
    """The predicate of a ClusterConfig (or anything with `exceptions`), for any collector check."""
    return excepted_from(getattr(cluster, "exceptions", None))


# Stable object keys, one per consistency kind.
def ptr_key(ip: str, name: str) -> str:
    return f"{canonical_ip(ip) or ip}|{normalize_name(name)}"


def lease_key(fqdn: str) -> str:
    return normalize_name(fqdn)


def record_key(name: str, rtype: str) -> str:
    return f"{normalize_name(name)}/{rtype.upper()}"


def reservation_key(reservation: str, ip: str) -> str:
    return f"{reservation}|{canonical_ip(ip) or ip}"


def _title(key: str, **params: Any) -> dict[str, Any]:
    return messages.fields("title", messages.msg(key, **params))


def canonical_ip(value: str) -> str | None:
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError:
        return None


def reverse_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer + "."


def _apexes(rrsets: Iterable[RRset]) -> set[str]:
    return {normalize_name(r.name) for r in rrsets if r.rtype.upper() == "SOA"}


def _in_zone(name: str, apexes: set[str]) -> str | None:
    """The longest apex that `name` falls under, or None (every name when no apex is known)."""
    if not apexes:
        return "."
    best = None
    for apex in apexes:
        if name == apex or name.endswith("." + apex) or apex == ".":
            if best is None or len(apex) > len(best):
                best = apex
    return best


def _active(lease: Lease) -> bool:
    return lease.state is LeaseState.DEFAULT


def _address_index(rrsets: Iterable[RRset]) -> dict[tuple[str, str], set[str]]:
    """(owner, A|AAAA) -> canonical addresses."""
    index: dict[tuple[str, str], set[str]] = {}
    for rr in rrsets:
        rtype = rr.rtype.upper()
        if rtype not in ADDRESS_TYPES:
            continue
        ips = {ip for ip in (canonical_ip(v) for v in rr.rdata) if ip}
        index.setdefault((normalize_name(rr.name), rtype), set()).update(ips)
    return index


def leases_without_record(
    leases: Iterable[Lease], forward: dict[str, list[RRset]], excepted: Excepted = _never
) -> list[Alert]:
    """Active lease with fqdn_fwd set and no A/AAAA for its hostname in its zone."""
    zones = {normalize_name(k): v for k, v in forward.items()}
    index: dict[str, dict[tuple[str, str], set[str]]] = {z: _address_index(rrs) for z, rrs in zones.items()}
    alerts: list[Alert] = []
    for lease in leases:
        if not _active(lease) or not lease.fqdn_fwd or not lease.hostname:
            continue
        fqdn = normalize_name(lease.hostname)
        zone = _in_zone(fqdn, set(zones))
        if zone is None or zone == ".":
            continue  # not one of the zones we were given, nothing to check against
        rtype = "AAAA" if ":" in lease.ip_address else "A"
        if (fqdn, rtype) in index[zone] or excepted(AlertKind.LEASE_WITHOUT_RECORD.value, lease_key(fqdn)):
            continue
        alerts.append(
            Alert(
                kind=AlertKind.LEASE_WITHOUT_RECORD,
                severity=Severity.INFO,
                engine=lease.family.kea_engine,
                subject=f"ip:{lease.ip_address}",
                **_title(
                    "alert.lease_without_record", ip=lease.ip_address, fqdn=fqdn, rtype=rtype, zone=zone
                ),
                details={
                    "hostname": fqdn,
                    "zone": zone,
                    "rtype": rtype,
                    "subnet_id": lease.subnet_id,
                    "hw_address": lease.hw_address,
                    "node_id": lease.node_id,
                    "exception_keys": [lease_key(fqdn)],
                },
            )
        )
    return alerts


def records_without_lease(
    rrsets: Iterable[RRset], leases: Iterable[Lease], excepted: Excepted = _never
) -> list[Alert]:
    """A/AAAA carrying a DHCID whose lease is gone."""
    rrsets = list(rrsets)
    dhcid_names = {normalize_name(r.name) for r in rrsets if r.rtype.upper() == "DHCID"}
    if not dhcid_names:
        return []
    active_ips = {canonical_ip(lease.ip_address) for lease in leases if _active(lease)}
    alerts: list[Alert] = []
    for (name, rtype), ips in sorted(_address_index(rrsets).items()):
        if name not in dhcid_names:
            continue
        missing = sorted(ip for ip in ips if ip not in active_ips)
        if not missing or excepted(AlertKind.RECORD_WITHOUT_LEASE.value, record_key(name, rtype)):
            continue
        alerts.append(
            Alert(
                kind=AlertKind.RECORD_WITHOUT_LEASE,
                severity=Severity.INFO,
                subject=f"name:{name}/{rtype}",
                **_title("alert.record_without_lease", rtype=rtype, name=name, addresses=missing),
                details={
                    "name": name,
                    "rtype": rtype,
                    "addresses": missing,
                    "exception_keys": [record_key(name, rtype)],
                },
            )
        )
    return alerts


def _reservation_ips(res: Reservation) -> list[str]:
    raw = [res.ip_address] if res.ip_address else list(res.ip_addresses)
    return [ip for ip in (canonical_ip(v) for v in raw) if ip]


def _reservation_fqdn(res: Reservation, names: Iterable[str]) -> str | None:
    """A short hostname matches the unique owner whose first label is that hostname."""
    if not res.hostname:
        return None
    host = res.hostname.strip().lower()
    if "." in host.rstrip("."):
        return normalize_name(host)
    candidates = {n for n in names if n.split(".", 1)[0] == host}
    return next(iter(candidates)) if len(candidates) == 1 else None


def reservation_mismatches(
    reservations: Iterable[Reservation], rrsets: Iterable[RRset], excepted: Excepted = _never
) -> list[Alert]:
    """Reservation hostname/IP disagreeing with the A/AAAA records, or with the PTR of the reserved IP."""
    rrsets = list(rrsets)
    index = _address_index(rrsets)
    ptr = {
        normalize_name(r.name): {normalize_name(v) for v in r.rdata}
        for r in rrsets
        if r.rtype.upper() == "PTR"
    }
    owners = {name for name, _ in index}
    alerts: list[Alert] = []
    for res in reservations:
        ips = _reservation_ips(res)
        fqdn = _reservation_fqdn(res, owners)
        if not ips or fqdn is None:
            continue
        for ip in ips:
            rtype = "AAAA" if ":" in ip else "A"
            problems: list[dict[str, Any]] = []
            recorded = index.get((fqdn, rtype))
            if recorded is not None and ip not in recorded:
                problems.append(
                    messages.msg(
                        "alert.reservation_mismatch.records",
                        rtype=rtype,
                        fqdn=fqdn,
                        addresses=sorted(recorded),
                    )
                )
            targets = ptr.get(reverse_name(ip))
            if targets is not None and fqdn not in targets:
                problems.append(
                    messages.msg("alert.reservation_mismatch.ptr", ip=ip, targets=sorted(targets))
                )
            key = reservation_key(res.key, ip)
            if not problems or excepted(AlertKind.RESERVATION_MISMATCH.value, key):
                continue
            alerts.append(
                Alert(
                    kind=AlertKind.RESERVATION_MISMATCH,
                    severity=Severity.WARNING,
                    subject=f"ip:{ip}",
                    **_title(
                        "alert.reservation_mismatch",
                        reservation=res.key,
                        fqdn=fqdn,
                        problems=messages.join(problems, "; "),
                    ),
                    details={
                        "reservation": res.key,
                        "hostname": fqdn,
                        "ip": ip,
                        "subnet_id": res.subnet_id,
                        "records": sorted(recorded) if recorded is not None else None,
                        "ptr": sorted(targets) if targets is not None else None,
                        "exception_keys": [key],
                    },
                )
            )
    return alerts


def _ptr_index(reverse: Iterable[RRset]) -> dict[str, set[str]]:
    ptr: dict[str, set[str]] = {}
    for rr in reverse:
        if rr.rtype.upper() == "PTR":
            ptr.setdefault(normalize_name(rr.name), set()).update(normalize_name(v) for v in rr.rdata)
    return ptr


def ptr_mismatches(
    forward: Iterable[RRset], reverse: Iterable[RRset], excepted: Excepted = _never
) -> list[Alert]:
    """A without matching PTR, or PTR pointing to a name without that A, within managed zones.

    Each problem is one (address, name) pair; an excepted pair is left out, and an address whose
    every pair is excepted raises nothing."""
    forward = list(forward)
    reverse = list(reverse)
    fwd_apexes = _apexes(forward)
    rev_apexes = _apexes(reverse)
    index = _address_index(forward)
    ptr = _ptr_index(reverse)
    kind = AlertKind.PTR_MISMATCH.value
    problems: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for (name, _rtype), ips in index.items():
        for ip in ips:
            rname = reverse_name(ip)
            if _in_zone(rname, rev_apexes) is None:
                continue
            targets = ptr.get(rname, set())
            if name not in targets and not excepted(kind, ptr_key(ip, name)):
                found = sorted(targets) if targets else messages.msg("common.none")
                problems.setdefault(ip, []).append(
                    (ptr_key(ip, name), messages.msg("alert.ptr_mismatch.no_ptr", name=name, found=found))
                )
    forward_by_ip: dict[str, set[str]] = {}
    for (name, _rtype), ips in index.items():
        for ip in ips:
            forward_by_ip.setdefault(ip, set()).add(name)
    for rname, targets in ptr.items():
        try:
            ip = ipaddress.ip_address(_ptr_to_ip(rname)).compressed
        except ValueError:
            continue
        for target in sorted(targets):
            if _in_zone(target, fwd_apexes) is None:
                continue
            if target not in forward_by_ip.get(ip, set()) and not excepted(kind, ptr_key(ip, target)):
                problems.setdefault(ip, []).append(
                    (ptr_key(ip, target), messages.msg("alert.ptr_mismatch.dangling", target=target))
                )
    alerts: list[Alert] = []
    for ip, pairs in sorted(problems.items()):
        items = [m for _k, m in pairs]
        keys = list(dict.fromkeys(k for k, _m in pairs))
        alerts.append(
            Alert(
                kind=AlertKind.PTR_MISMATCH,
                severity=Severity.WARNING,
                subject=f"ip:{ip}",
                **_title("alert.ptr_mismatch", ip=ip, problems=messages.join(items, "; ")),
                details={"ip": ip, "problems": [messages.render(m) for m in items], "exception_keys": keys},
            )
        )
    return alerts


def orphan_ptrs(
    forward: Iterable[RRset],
    reverse: Iterable[RRset],
    excepted: Excepted = _never,
) -> list[dict[str, Any]]:
    """PTRs whose target has no A/AAAA to their address, one item per (PTR owner, target).

    `forward` and `reverse` carry the SOA of each zone read. A target under a managed forward zone
    is `orphan`; one outside every managed zone is `external` (not verifiable). `fix` says what
    settles an orphan: `create_a` when the target has no address of that family at all, else
    `delete`. A DHCID at the PTR owner marks a record written by DDNS."""
    forward = list(forward)
    reverse = list(reverse)
    fwd_apexes = _apexes(forward)
    index = _address_index(forward)
    by_name: dict[str, set[str]] = {}
    for (name, _rtype), ips in index.items():
        by_name.setdefault(name, set()).update(ips)
    dhcid = {normalize_name(r.name) for r in reverse if r.rtype.upper() == "DHCID"}
    out: list[dict[str, Any]] = []
    for rname, targets in sorted(_ptr_index(reverse).items()):
        try:
            ip = ipaddress.ip_address(_ptr_to_ip(rname)).compressed
        except ValueError:
            continue
        rtype = "AAAA" if ":" in ip else "A"
        for target in sorted(targets):
            addresses = sorted(by_name.get(target, set()))
            if ip in addresses:
                continue
            zone = _in_zone(target, fwd_apexes) if fwd_apexes else None
            if zone is None:
                category, fix = "external", None
            else:
                category = "orphan"
                same_family = [a for a in addresses if (":" in a) == (rtype == "AAAA")]
                fix = "delete" if same_family else "create_a"
            key = ptr_key(ip, target)
            out.append(
                {
                    "ip": ip,
                    "name": rname,
                    "target": target,
                    "category": category,
                    "target_zone": zone,
                    "target_addresses": addresses,
                    "rtype": rtype,
                    "ddns": rname in dhcid,
                    "fix": fix,
                    "exception_key": key,
                    "excepted": excepted(AlertKind.PTR_MISMATCH.value, key),
                }
            )
    return out


def _ptr_to_ip(rname: str) -> str:
    name = rname.rstrip(".")
    if name.endswith(".in-addr.arpa"):
        octets = name[: -len(".in-addr.arpa")].split(".")
        if len(octets) != 4:
            raise ValueError(rname)
        return ".".join(reversed(octets))
    if name.endswith(".ip6.arpa"):
        nibbles = name[: -len(".ip6.arpa")].split(".")
        if len(nibbles) != 32:
            raise ValueError(rname)
        hexs = "".join(reversed(nibbles))
        return ":".join(hexs[i : i + 4] for i in range(0, 32, 4))
    raise ValueError(rname)


def _lease_identifier(lease: Lease, id_type: ReservationIdType) -> str | None:
    """The lease field comparable with a reservation of this identifier type; None when the lease
    does not carry one (circuit-id and flex-id never appear in a lease)."""
    if id_type is ReservationIdType.HW_ADDRESS:
        return lease.hw_address
    if id_type is ReservationIdType.DUID:
        return lease.duid
    if id_type is ReservationIdType.CLIENT_ID:
        return lease.client_id
    return None


def _hex(identifier: str) -> str:
    """Identifier without separators, lowercased: Kea writes aa:bb, configs often aabb or aa-bb."""
    return identifier.lower().replace(":", "").replace("-", "")


def duplicate_ips(
    reservations: Iterable[Reservation], leases: Iterable[Lease], excepted: Excepted = _never
) -> list[Alert]:
    """Same IP in two reservations, or in a reservation and a lease of another client (key: the IP)."""
    seen: dict[str, Reservation] = {}
    alerts: list[Alert] = []
    kind = AlertKind.DUPLICATE_IP.value
    for res in reservations:
        for ip in _reservation_ips(res):
            other = seen.get(ip)
            if other is not None and other.key != res.key:
                if excepted(kind, ip):
                    continue
                alerts.append(
                    Alert(
                        kind=AlertKind.DUPLICATE_IP,
                        severity=Severity.WARNING,
                        subject=f"ip:{ip}",
                        **_title("alert.duplicate_reservation", ip=ip),
                        details={"reservations": [other.key, res.key], "exception_keys": [ip]},
                    )
                )
            else:
                seen[ip] = res
    for lease in leases:
        if not _active(lease):
            continue
        ip = canonical_ip(lease.ip_address) or lease.ip_address
        res = seen.get(ip)
        if res is None:
            continue
        client = (_lease_identifier(lease, res.id_type) or "").lower()
        if client and _hex(client) != _hex(res.identifier) and not excepted(kind, ip):
            alerts.append(
                Alert(
                    kind=AlertKind.DUPLICATE_IP,
                    severity=Severity.WARNING,
                    subject=f"ip:{ip}",
                    **_title("alert.duplicate_lease", ip=ip, identifier=res.identifier, lease=client),
                    details={
                        "reservation": res.key,
                        "lease": client,
                        "subnet_id": lease.subnet_id,
                        "exception_keys": [ip],
                    },
                )
            )
    return alerts


def run_all(
    *,
    leases: list[Lease],
    reservations: list[Reservation],
    forward: dict[str, list[RRset]],
    reverse: list[RRset],
    excepted: Excepted | None = None,
) -> list[Alert]:
    """One consistency pass; `forward` maps zone name to its RRsets. Duplicate ids collapse to one alert.
    Objects `excepted` by the admin raise nothing."""
    ex = excepted or _never
    forward = {normalize_name(k): v for k, v in forward.items()}
    all_forward = [r for rs in forward.values() for r in rs]
    alerts: list[Alert] = []
    alerts += duplicate_ips(reservations, leases, ex)
    alerts += leases_without_record(leases, forward, ex)
    alerts += records_without_lease(all_forward, leases, ex)
    alerts += reservation_mismatches(reservations, all_forward + reverse, ex)
    alerts += ptr_mismatches(all_forward, reverse, ex)
    unique: dict[str, Alert] = {}
    for alert in alerts:
        unique.setdefault(alert.id, alert)
    return list(unique.values())


# IPv6 checks (section 27) ----------------------------------------------------------------------

IPV6_KINDS = frozenset(
    {AlertKind.IPV6_MISSING_AAAA, AlertKind.IPV6_REVERSE_MISSING, AlertKind.IPV6_STALE_AAAA}
)
# Grouped alerts whose details carry the keys of their hosts and addresses, not the subject.
OWN_KEYS = frozenset({AlertKind.IPV6_MISSING_AAAA, AlertKind.IPV6_STALE_AAAA})


def ipv6_missing_aaaa(rows: Iterable[dict[str, Any]], now: int, stable_min_days: int) -> list[Alert]:
    """One alert per forward zone listing the hosts with a proposal and no AAAA (rows of
    `ipv6_hosts.host_rows`, built with the exceptions: excepted hosts are skipped here)."""
    from pelagos.services import ipv6_hosts

    by_zone: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("excepted") or not ipv6_hosts.missing_aaaa(row, now, stable_min_days):
            continue
        p = row["proposal"]
        by_zone.setdefault(p["zone"], []).append(
            {"host_key": row["host_key"], "name": p["name"], "mac": row["mac"], "address": p["address"]}
        )
    alerts = []
    for zone, hosts in sorted(by_zone.items()):
        alerts.append(
            Alert(
                kind=AlertKind.IPV6_MISSING_AAAA,
                severity=Severity.INFO,
                subject=f"ipv6:aaaa:{zone}",
                **_title("alert.ipv6_missing_aaaa", zone=zone, count=len(hosts)),
                details={
                    "zone": zone,
                    "count": len(hosts),
                    "hosts": hosts,
                    "exception_keys": [ipv6_hosts.mac_key(h["mac"]) for h in hosts],
                },
            )
        )
    return alerts


def ipv6_reverse_missing(watched: Iterable[Any], reverse_zones: Iterable[str]) -> list[Alert]:
    """A watched prefix (`prefixes.Prefix`) no served `ip6.arpa` zone holds whole."""
    from pelagos.collector.ipv6 import prefixes

    zones = list(reverse_zones)
    alerts = []
    for p in watched:
        if prefixes.covered(p.network, zones):
            continue
        prefix = str(p.network)
        alerts.append(
            Alert(
                kind=AlertKind.IPV6_REVERSE_MISSING,
                severity=Severity.INFO,
                subject=f"ipv6:reverse:{prefix}",
                **_title("alert.ipv6_reverse_missing", prefix=prefix),
                details={"prefix": prefix, "reverse_zone": prefixes.reverse_zone_name(p.network)},
            )
        )
    return alerts


def ipv6_stale_aaaa(stale: Iterable[Any], stale_days: int) -> list[Alert]:
    """One alert per zone of `ipv6_hosts.Stale` records; `old_prefix` and `new_prefix` (the /64s)
    when every stale address of the zone left one /64 for one other."""
    from pelagos.services import ipv6_hosts

    by_zone: dict[str, list[Any]] = {}
    for item in stale:
        by_zone.setdefault(item.zone, []).append(item)
    alerts = []
    for zone, items in sorted(by_zone.items()):
        details: dict[str, Any] = {
            "zone": zone,
            "count": len(items),
            "records": [
                {
                    "name": i.name,
                    "address": i.address,
                    "mac": i.mac,
                    "last_seen": i.last_seen,
                    "current": i.current,
                }
                for i in items
            ],
        }
        old = {ipaddress.IPv6Network(f"{i.address}/64", strict=False) for i in items}
        new = {ipaddress.IPv6Network(f"{i.current}/64", strict=False) for i in items}
        if len(old) == 1 and len(new) == 1 and old != new:
            details["old_prefix"], details["new_prefix"] = str(old.pop()), str(new.pop())
        keys = [ipv6_hosts.addr_key(i.address) for i in items]
        details["exception_keys"] = list(dict.fromkeys(keys))
        alerts.append(
            Alert(
                kind=AlertKind.IPV6_STALE_AAAA,
                severity=Severity.WARNING,
                subject=f"ipv6:stale:{zone}",
                **_title("alert.ipv6_stale_aaaa", zone=zone, count=len(items), days=stale_days),
                details=details,
            )
        )
    return alerts


def is_excepted(alert: Alert, excepted: Excepted) -> bool:
    """True when an exception names this alert of EXCEPTABLE_KINDS (its node or every node)."""
    if alert.kind not in EXCEPTABLE_KINDS:
        return False
    return any(excepted(alert.kind.value, key) for key in exception_keys(alert))


def apply_exceptions(alerts: Iterable[Alert], excepted: Excepted) -> list[Alert]:
    """Alerts of any check without the excepted ones; an exceptable alert carries the key the UI
    offers (details.exception_keys, this node only). Consistency kinds set their own keys."""
    out: list[Alert] = []
    for alert in alerts:
        if alert.kind in EXCEPTABLE_KINDS:
            if is_excepted(alert, excepted):
                continue
            if alert.kind not in OWN_KEYS or "exception_keys" not in alert.details:
                alert.details = {**alert.details, "exception_keys": exception_keys(alert)[:1]}
        out.append(alert)
    return out


# Kea configuration file versus config-get (CONFIG_DIVERGENCE, cause "file"): lives in core.keafile
# so the Kea connectors use the same comparison; re-exported for the collector.
from pelagos.core.keafile import (  # noqa: E402
    is_sensitive_kea_key,
    kea_config_differences,
    redact_kea_difference,
)

__all__ = [
    "Excepted",
    "apply_exceptions",
    "excepted_for",
    "excepted_from",
    "ipv6_missing_aaaa",
    "ipv6_reverse_missing",
    "ipv6_stale_aaaa",
    "is_excepted",
    "is_sensitive_kea_key",
    "kea_config_differences",
    "orphan_ptrs",
    "redact_kea_difference",
    "run_all",
]
