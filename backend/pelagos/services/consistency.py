# SPDX-License-Identifier: Apache-2.0
"""DNS/DHCP consistency checks (section 15, cross kinds). Owned by WP-COLLECTOR, run by the collector.

Pure functions over domain objects: the collector feeds leases, reservations and
RRsets it has read; this module returns the Alerts that are currently true.
Managed zones are recognized by their SOA at the apex; when a list carries no SOA
at all, every name in it counts as managed (crafted inputs in tests).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator
from pathlib import PurePosixPath
from typing import Any

from pelagos.domain import (
    Alert,
    AlertKind,
    Lease,
    LeaseState,
    Reservation,
    ReservationIdType,
    RRset,
    Severity,
)
from pelagos.domain.dns import normalize_name

ADDRESS_TYPES = ("A", "AAAA")


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


def leases_without_record(leases: Iterable[Lease], forward: dict[str, list[RRset]]) -> list[Alert]:
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
        if (fqdn, rtype) in index[zone]:
            continue
        alerts.append(
            Alert(
                kind=AlertKind.LEASE_WITHOUT_RECORD,
                severity=Severity.INFO,
                engine=lease.family.kea_engine,
                subject=f"ip:{lease.ip_address}",
                title=f"lease {lease.ip_address} ({fqdn}) has no {rtype} record in {zone}",
                details={
                    "hostname": fqdn,
                    "zone": zone,
                    "rtype": rtype,
                    "subnet_id": lease.subnet_id,
                    "hw_address": lease.hw_address,
                    "node_id": lease.node_id,
                },
            )
        )
    return alerts


def records_without_lease(rrsets: Iterable[RRset], leases: Iterable[Lease]) -> list[Alert]:
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
        if not missing:
            continue
        alerts.append(
            Alert(
                kind=AlertKind.RECORD_WITHOUT_LEASE,
                severity=Severity.INFO,
                subject=f"name:{name}/{rtype}",
                title=f"{rtype} record {name} ({', '.join(missing)}) has a DHCID but no lease",
                details={"name": name, "rtype": rtype, "addresses": missing},
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


def reservation_mismatches(reservations: Iterable[Reservation], rrsets: Iterable[RRset]) -> list[Alert]:
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
            problems: list[str] = []
            recorded = index.get((fqdn, rtype))
            if recorded is not None and ip not in recorded:
                problems.append(f"{rtype} {fqdn} is {', '.join(sorted(recorded))}")
            targets = ptr.get(reverse_name(ip))
            if targets is not None and fqdn not in targets:
                problems.append(f"PTR {ip} is {', '.join(sorted(targets))}")
            if not problems:
                continue
            alerts.append(
                Alert(
                    kind=AlertKind.RESERVATION_MISMATCH,
                    severity=Severity.WARNING,
                    subject=f"ip:{ip}",
                    title=f"reservation {res.key} ({fqdn}) disagrees with DNS: " + "; ".join(problems),
                    details={
                        "reservation": res.key,
                        "hostname": fqdn,
                        "ip": ip,
                        "subnet_id": res.subnet_id,
                        "records": sorted(recorded) if recorded is not None else None,
                        "ptr": sorted(targets) if targets is not None else None,
                    },
                )
            )
    return alerts


def ptr_mismatches(forward: Iterable[RRset], reverse: Iterable[RRset]) -> list[Alert]:
    """A without matching PTR, or PTR pointing to a name without that A, within managed zones."""
    forward = list(forward)
    reverse = list(reverse)
    fwd_apexes = _apexes(forward)
    rev_apexes = _apexes(reverse)
    index = _address_index(forward)
    ptr: dict[str, set[str]] = {}
    for rr in reverse:
        if rr.rtype.upper() == "PTR":
            ptr.setdefault(normalize_name(rr.name), set()).update(normalize_name(v) for v in rr.rdata)
    problems: dict[str, list[str]] = {}
    for (name, _rtype), ips in index.items():
        for ip in ips:
            rname = reverse_name(ip)
            if _in_zone(rname, rev_apexes) is None:
                continue
            targets = ptr.get(rname, set())
            if name not in targets:
                found = ", ".join(sorted(targets)) if targets else "none"
                problems.setdefault(ip, []).append(f"{name} has no PTR (found {found})")
    forward_by_ip: dict[str, set[str]] = {}
    for (name, _rtype), ips in index.items():
        for ip in ips:
            forward_by_ip.setdefault(ip, set()).add(name)
    for rname, targets in ptr.items():
        try:
            ip = ipaddress.ip_address(_ptr_to_ip(rname)).compressed
        except ValueError:
            continue
        for target in targets:
            if _in_zone(target, fwd_apexes) is None:
                continue
            if target not in forward_by_ip.get(ip, set()):
                problems.setdefault(ip, []).append(
                    f"PTR points to {target} which has no address record for it"
                )
    return [
        Alert(
            kind=AlertKind.PTR_MISMATCH,
            severity=Severity.WARNING,
            subject=f"ip:{ip}",
            title=f"{ip}: " + "; ".join(items),
            details={"ip": ip, "problems": items},
        )
        for ip, items in sorted(problems.items())
    ]


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


def duplicate_ips(reservations: Iterable[Reservation], leases: Iterable[Lease]) -> list[Alert]:
    """Same IP in two reservations, or in a reservation and a lease of another client."""
    seen: dict[str, Reservation] = {}
    alerts: list[Alert] = []
    for res in reservations:
        for ip in _reservation_ips(res):
            other = seen.get(ip)
            if other is not None and other.key != res.key:
                alerts.append(
                    Alert(
                        kind=AlertKind.DUPLICATE_IP,
                        severity=Severity.WARNING,
                        subject=f"ip:{ip}",
                        title=f"{ip} is reserved twice",
                        details={"reservations": [other.key, res.key]},
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
        lease_key = (_lease_identifier(lease, res.id_type) or "").lower()
        if lease_key and _hex(lease_key) != _hex(res.identifier):
            alerts.append(
                Alert(
                    kind=AlertKind.DUPLICATE_IP,
                    severity=Severity.WARNING,
                    subject=f"ip:{ip}",
                    title=f"{ip} is reserved for {res.identifier} but leased to {lease_key}",
                    details={"reservation": res.key, "lease": lease_key, "subnet_id": lease.subnet_id},
                )
            )
    return alerts


def run_all(
    *,
    leases: list[Lease],
    reservations: list[Reservation],
    forward: dict[str, list[RRset]],
    reverse: list[RRset],
) -> list[Alert]:
    """One consistency pass; `forward` maps zone name to its RRsets. Duplicate ids collapse to one alert."""
    forward = {normalize_name(k): v for k, v in forward.items()}
    all_forward = [r for rs in forward.values() for r in rs]
    alerts: list[Alert] = []
    alerts += duplicate_ips(reservations, leases)
    alerts += leases_without_record(leases, forward)
    alerts += records_without_lease(all_forward, leases)
    alerts += reservation_mismatches(reservations, all_forward + reverse)
    alerts += ptr_mismatches(all_forward, reverse)
    unique: dict[str, Alert] = {}
    for alert in alerts:
        unique.setdefault(alert.id, alert)
    return list(unique.values())


# Kea configuration file versus config-get (CONFIG_DIVERGENCE, cause "file") -------------------------

KEA_ROOTS = ("Dhcp4", "Dhcp6", "DhcpDdns")
# Not compared: logging is not service behavior, and Kea 3.x rewrites log paths under its log dir.
KEA_IGNORED_TOP = frozenset({"loggers", "hash"})
KEA_LOWERCASE = frozenset({"hw-address", "duid", "client-id", "circuit-id", "flex-id"})
KEA_REDACTED = frozenset({"*****", "****", "***"})
_RANGE = re.compile(r"\s*-\s*")


def _kea_body(config: dict[str, Any]) -> dict[str, Any]:
    return next((config[k] for k in KEA_ROOTS if isinstance(config.get(k), dict)), config)


def _kea_scalar(key: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if key == "pool":
        return _RANGE.sub("-", value.strip())
    if key in KEA_LOWERCASE:
        return value.strip().lower()
    return value


def is_sensitive_kea_key(key: str) -> bool:
    """Keys whose values never appear in a difference (`secret`, `basic-auth-password`, ...)."""
    key = key.lower()
    return key.endswith(("password", "secret"))


_DIFF_PATH = re.compile(r"^(?P<path>[^:]*): ")
_LAST_KEY = re.compile(r"/(?P<key>[^/\[]+)(?:\[\d+\])*$")


def redact_kea_difference(line: str) -> str:
    """`<path>: differs` when the path ends on a sensitive key, the line unchanged otherwise."""
    m = _DIFF_PATH.match(line)
    if not m:
        return line
    last = _LAST_KEY.search(m.group("path"))
    if last and is_sensitive_kea_key(last.group("key")):
        return f"{m.group('path')}: differs"
    return line


def _same_scalar(key: str, file_value: Any, running: Any) -> bool:
    a, b = _kea_scalar(key, file_value), _kea_scalar(key, running)
    if a == b:
        return True
    if isinstance(b, str) and b in KEA_REDACTED:
        return True  # secrets and passwords are masked by config-get
    if isinstance(a, str) and isinstance(b, str) and (a.startswith("/") != b.startswith("/")):
        # Kea resolves relative socket, lease, hook and secret file names against its own directories.
        return PurePosixPath(a).name == PurePosixPath(b).name
    return False


def _kea_diff(file_value: Any, running: Any, path: str, key: str) -> Iterator[str]:
    if isinstance(file_value, dict):
        if not isinstance(running, dict):
            yield f"{path or '/'}: object in the file, {type(running).__name__} running"
            return
        for k, v in file_value.items():
            sub = f"{path}/{k}"
            if not path and k in KEA_IGNORED_TOP:
                continue
            if k == "comment" and "comment" not in running:
                # Kea moves a `comment` into user-context.
                v_running = (running.get("user-context") or {}).get("comment")
                if v_running != v:
                    yield f"{sub}: {v!r} in the file, {v_running!r} running"
                continue
            if not path and k == "control-socket" and k not in running and "control-sockets" in running:
                # Kea 3.x reports the singular form as a one-item control-sockets list.
                yield from _kea_diff([v], running["control-sockets"], "/control-sockets", k)
                continue
            if k not in running:
                yield f"{sub}: in the file, absent from the running configuration"
                continue
            yield from _kea_diff(v, running[k], sub, k)
        return
    if isinstance(file_value, list):
        if not isinstance(running, list):
            yield f"{path}: list in the file, {type(running).__name__} running"
        elif len(file_value) != len(running):
            yield f"{path}: {len(file_value)} item(s) in the file, {len(running)} running"
        else:
            for i, (a, b) in enumerate(zip(file_value, running, strict=True)):
                yield from _kea_diff(a, b, f"{path}[{i}]", key)
        return
    if not _same_scalar(key, file_value, running):
        if is_sensitive_kea_key(key):
            yield f"{path}: differs"
        else:
            yield f"{path}: {file_value!r} in the file, {running!r} running"


def kea_config_differences(file_config: dict[str, Any], running_config: dict[str, Any]) -> list[str]:
    """Paths where the file on disk says something the running daemon (config-get) does not.

    config-get adds every default, so the file is compared as a subset: each key the file sets must
    hold the same value at runtime; keys only present at runtime are defaults and ignored. Values are
    normalized as Kea does (pool ranges without blanks, lower-case identifiers, the singular
    control-socket as a list, `comment` in user-context, masked secrets, paths resolved by Kea).
    """
    return list(_kea_diff(_kea_body(file_config), _kea_body(running_config), "", ""))
