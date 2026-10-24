# SPDX-License-Identifier: Apache-2.0
"""DNS/DHCP consistency checks (section 15, cross kinds). Owned by WP-COLLECTOR, run by the collector.

Pure functions over domain objects: the collector feeds leases, reservations and
RRsets it has read; this module returns the Alerts that are currently true.
"""

from __future__ import annotations

from collections.abc import Iterable

from pelagos.domain import Alert, AlertKind, Lease, Reservation, RRset, Severity
from pelagos.domain.dns import normalize_name


def leases_without_record(leases: Iterable[Lease], forward: dict[str, list[RRset]]) -> list[Alert]:
    """Active lease with fqdn_fwd set and no A/AAAA for its hostname in its zone."""
    raise NotImplementedError("WP-COLLECTOR")


def records_without_lease(rrsets: Iterable[RRset], leases: Iterable[Lease]) -> list[Alert]:
    """A/AAAA carrying a DHCID whose lease is gone."""
    raise NotImplementedError("WP-COLLECTOR")


def reservation_mismatches(reservations: Iterable[Reservation], rrsets: Iterable[RRset]) -> list[Alert]:
    raise NotImplementedError("WP-COLLECTOR")


def ptr_mismatches(forward: Iterable[RRset], reverse: Iterable[RRset]) -> list[Alert]:
    raise NotImplementedError("WP-COLLECTOR")


def duplicate_ips(reservations: Iterable[Reservation], leases: Iterable[Lease]) -> list[Alert]:
    """Same IP in two reservations, or in a reservation and a lease of another client."""
    seen: dict[str, Reservation] = {}
    alerts: list[Alert] = []
    for res in reservations:
        ips = [res.ip_address] if res.ip_address else list(res.ip_addresses)
        for ip in ips:
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
        res = seen.get(lease.ip_address)
        if res is None:
            continue
        lease_key = (lease.hw_address or lease.duid or lease.client_id or "").lower()
        if lease_key and lease_key != res.identifier.lower():
            alerts.append(
                Alert(
                    kind=AlertKind.DUPLICATE_IP,
                    severity=Severity.WARNING,
                    subject=f"ip:{lease.ip_address}",
                    title=f"{lease.ip_address} is reserved for {res.identifier} but leased to {lease_key}",
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
    """One consistency pass; `forward` maps zone name to its RRsets."""
    forward = {normalize_name(k): v for k, v in forward.items()}
    alerts: list[Alert] = []
    alerts += duplicate_ips(reservations, leases)
    for fn in (
        lambda: leases_without_record(leases, forward),
        lambda: records_without_lease([r for rs in forward.values() for r in rs], leases),
        lambda: reservation_mismatches(reservations, [r for rs in forward.values() for r in rs]),
        lambda: ptr_mismatches([r for rs in forward.values() for r in rs], reverse),
    ):
        try:
            alerts += fn()
        except NotImplementedError:
            continue
    return alerts
