# SPDX-License-Identifier: Apache-2.0
"""IPv4 neighbor discovery (section 27, IPv4 neighbors and discovery): the collector's read of this
node's IPv4 neighbor table, and the `unknown_device` check of the consistency pass.

Subject: `mac:<mac>` (lower-case), cluster-wide.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable, Iterable
from typing import Any

from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import NeighborSource, SourceError, normalize_mac
from pelagos.collector.neighbors import NeighborsSource
from pelagos.core import settings_registry as reg
from pelagos.domain import (
    Alert,
    AlertKind,
    Lease,
    LeaseState,
    Reservation,
    ReservationIdType,
    RRset,
    Severity,
    messages,
)

log = logging.getLogger(__name__)

MODULE = "discovery"
FAMILY = 4
# A device counts as present while seen within this many passes.
PRESENT_PASSES = 3
ACTIVE_LEASES = (LeaseState.DEFAULT, LeaseState.REGISTERED)


def enabled(cluster: Any, settings: dict[str, Any]) -> bool:
    return bool(cluster.modules.get(MODULE, False)) and bool(reg.get(settings, "discovery.ipv4_enabled"))


class NeighborWatch:
    """One read of the IPv4 neighbor table per call, recorded in one transaction of the cache."""

    def __init__(
        self, ctx: Any, store: Any, clock: Callable[[], float], source: NeighborSource | None = None
    ) -> None:
        self.ctx = ctx
        self.store = store
        self.clock = clock
        self.node_id: str = ctx.node.id
        self.source = source or NeighborsSource(family=FAMILY)
        self._failing = False
        obs_store.ensure_neighbors(store.conn)

    def tick(self) -> dict[str, Any] | None:
        """Reads, records and prunes; returns the NeighborStatus, None when discovery is off here."""
        settings = self.ctx.settings()
        now = int(self.clock())
        days = int(reg.get(settings, "retention.neighbor_observation_days"))
        conn = self.store.conn
        if not enabled(self.ctx.cluster(), settings):
            with self.store.batch():
                obs_store.prune_neighbors(conn, now, days)
            return None
        error: str | None = None
        found: list[Any] = []
        try:
            found = self.source.poll()
        except SourceError as exc:
            error = exc.message
        except Exception as exc:  # a bug of the source must not stop the collector loop
            log.debug("IPv4 neighbor source raised", exc_info=True)
            error = f"unexpected error: {exc}"
        self._log_transition(error)
        with self.store.batch():
            last = obs_store.read_neighbor_status(conn)
            entries = 0 if error else obs_store.record_neighbors(conn, found, FAMILY, self.node_id, now)
            obs_store.prune_neighbors(conn, now, days)
            since = None
            if error is not None:
                kept = last.get("failing_since") if last and last.get("error") else None
                since = kept if isinstance(kept, int) and kept <= now else now
            status = {
                "node_id": self.node_id,
                "last_poll": now,
                "error": error,
                "entries": entries,
                "failing_since": since,
            }
            obs_store.write_neighbor_status(conn, status)
        return status

    def _log_transition(self, error: str | None) -> None:
        if error is not None and not self._failing:
            self._failing = True
            log.warning("IPv4 neighbor source failed: %s", error)
        elif error is None and self._failing:
            self._failing = False
            log.warning("IPv4 neighbor source works again")


def _v4(ip: Any) -> str | None:
    text = str(ip).strip()
    # Kea and zone files give dotted quads already: parse only what does not look like one.
    if (
        text.count(".") == 3
        and text.replace(".", "").isdigit()
        and not any(len(p) > 1 and p[0] == "0" for p in text.split("."))
    ):
        return text if all(int(p) < 256 for p in text.split(".")) else None
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return None


def _mac(value: Any) -> str | None:
    if isinstance(value, str) and len(value) == 17 and value[2::3] == ":::::":
        return value.lower()
    return normalize_mac(value)


def known_sets(
    leases: Iterable[Lease],
    reservations: Iterable[Reservation],
    forward: Iterable[RRset],
    reverse: Iterable[RRset],
) -> tuple[set[str], set[str]]:
    """(MACs, IPv4 addresses) a lease, a reservation, an A record or a PTR accounts for."""
    from pelagos.services.hosts_service import reverse_to_ip

    macs: set[str] = set()
    ips: set[str] = set()
    for lease in leases:
        if lease.state not in ACTIVE_LEASES:
            continue
        mac = _mac(lease.hw_address)
        if mac:
            macs.add(mac)
        ip = _v4(lease.ip_address)
        if ip:
            ips.add(ip)
    for res in reservations:
        if res.id_type is ReservationIdType.HW_ADDRESS:
            mac = _mac(res.identifier)
            if mac:
                macs.add(mac)
        for raw in [res.ip_address, *res.ip_addresses]:
            ip = _v4(raw) if raw else None
            if ip:
                ips.add(ip)
    for rr in forward:
        if rr.rtype == "A":
            ips.update(ip for ip in (_v4(r) for r in rr.rdata) if ip)
    for rr in reverse:
        if rr.rtype == "PTR":
            ip = _v4(reverse_to_ip(rr.name) or "")
            if ip:
                ips.add(ip)
    return macs, ips


def unknown_devices(
    neighbors: Iterable[dict[str, Any]],
    leases: Iterable[Lease],
    reservations: Iterable[Reservation],
    forward: Iterable[RRset],
    reverse: Iterable[RRset],
    now: int,
    after_seconds: int,
    present_seconds: int,
) -> list[Alert]:
    """`unknown_device` for each MAC first seen `after_seconds` ago, seen within `present_seconds`,
    that no lease, reservation, A record or PTR accounts for (by MAC or by one of its addresses)."""
    from pelagos.services.discovery_service import devices, rfc3339, vendor

    macs, ips = known_sets(leases, reservations, forward, reverse)
    alerts: list[Alert] = []
    for mac, dev in sorted(devices(neighbors).items()):
        if mac in macs or now - dev["first_seen"] < after_seconds or now - dev["last_seen"] > present_seconds:
            continue
        addresses = sorted(dev["addresses"].values(), key=lambda a: (-a["last_seen"], a["address"]))
        if any(a["address"] in ips for a in addresses):
            continue
        name = vendor(mac)
        params = {"mac": mac, "address": addresses[0]["address"]}
        title = (
            messages.msg("alert.unknown_device_vendor", vendor=name, **params)
            if name
            else (messages.msg("alert.unknown_device", **params))
        )
        alerts.append(
            Alert(
                kind=AlertKind.UNKNOWN_DEVICE,
                severity=Severity.INFO,
                subject=f"mac:{mac}",
                **messages.fields("title", title),
                details={
                    "mac": mac,
                    "vendor": name,
                    "addresses": [a["address"] for a in addresses],
                    "nodes": dev["nodes"],
                    # No last_seen: details stay the same from pass to pass while nothing changes.
                    "first_seen": rfc3339(dev["first_seen"]),
                },
            )
        )
    return alerts


def present_seconds(settings: dict[str, Any]) -> int:
    return PRESENT_PASSES * int(reg.get(settings, "discovery.poll_seconds"))


def after_seconds(settings: dict[str, Any]) -> int:
    return 60 * int(reg.get(settings, "discovery.unknown_after_minutes"))
