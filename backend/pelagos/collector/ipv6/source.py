# SPDX-License-Identifier: Apache-2.0
"""The NeighborSource interface: one poll returns the (MAC, IPv6 address) pairs a source sees."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Protocol

MAC_RE = re.compile(r"^[0-9a-f]{1,2}([:-][0-9a-f]{1,2}){5}$")


class SourceError(Exception):
    """A source that could not be read; the message is shown in the sources screen."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass(frozen=True, slots=True)
class Neighbor:
    mac: str
    address: str
    state: str | None = None


class NeighborSource(Protocol):
    kind: str

    def poll(self) -> list[Neighbor]:
        """Every neighbor seen now; raises SourceError on any failure."""
        ...


def normalize_mac(value: object) -> str | None:
    """Lower-case, colon separated, two digits per octet; None for anything else or all zeros."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not MAC_RE.match(text):
        return None
    mac = ":".join(part.zfill(2) for part in re.split("[:-]", text))
    return None if mac == "00:00:00:00:00:00" else mac


def normalize_address(value: object) -> str | None:
    """Compressed IPv6 address without a zone index; None when it is not one."""
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.IPv6Address(value.strip().split("%", 1)[0])
    except ValueError:
        return None
    return addr.compressed


def neighbor(mac: object, address: object, state: str | None = None) -> Neighbor | None:
    m, a = normalize_mac(mac), normalize_address(address)
    return Neighbor(m, a, state) if m and a else None
