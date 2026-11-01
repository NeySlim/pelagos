# SPDX-License-Identifier: Apache-2.0
"""The host view: a join of lease, reservation and DNS records, never persisted."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pelagos.domain.alerts import Alert
from pelagos.domain.common import Model
from pelagos.domain.dhcp import Lease, Reservation
from pelagos.domain.dns import RRset


@dataclass(slots=True)
class Host(Model):
    key: str
    mac: str | None = None
    ips: list[str] = field(default_factory=list)
    hostname: str | None = None
    lease: Lease | None = None
    reservation: Reservation | None = None
    records: list[RRset] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    # B1-DISCOVERY (section 27): {"first","last","node"} of the IPv4 neighbor sightings, and the
    # OUI manufacturer of `mac`; null without the discovery module.
    seen: dict[str, Any] | None = None
    vendor: str | None = None


def host_key(mac: str | None, ip: str | None, name: str | None) -> str:
    """Join key priority: MAC, then IP, then name (section 6 of the design)."""
    if mac:
        return "mac:" + mac.lower()
    if ip:
        return "ip:" + ip
    if name:
        return "name:" + name.lower().rstrip(".") + "."
    raise ValueError("a host needs a mac, an ip or a name")
