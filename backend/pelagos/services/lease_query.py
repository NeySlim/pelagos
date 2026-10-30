# SPDX-License-Identifier: Apache-2.0
"""Lease lookups and cursor pages over Kea's own commands, so no read walks the whole lease table.

A search term is sent to the matching Kea lookup (lease4-get, -get-by-hw-address, -get-by-hostname,
lease6-get-by-duid), a hostname also to a bounded substring walk; a page is one bounded
lease4-get-page / lease6-get-page walk from a cursor.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from pelagos.connectors.base import ConnectorError, NotSupported
from pelagos.domain import Lease

MAX_PAGE = 1000
# A subnet filter walks at most this many Kea pages before answering with a cursor.
MAX_SCAN_PAGES = 10
# A partial hostname search reads at most this many leases.
SCAN_LIMIT = 20000
_MAC = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.I)
_HEX_ID = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){6,}$", re.I)


def classify(q: str) -> str:
    """ip, mac, duid or hostname."""
    text = q.strip()
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    if _MAC.match(text):
        return "mac"
    if _HEX_ID.match(text):
        return "duid"
    return "hostname"


def lookup(backend: Any, q: str) -> list[Lease]:
    kind = classify(q)
    text = q.strip()
    if kind == "ip":
        lease = backend.lease(str(ipaddress.ip_address(text)))
        return [lease] if lease else []
    if kind == "mac":
        return list(backend.leases_by_hw(text.lower().replace("-", ":")))
    if kind == "duid":
        try:
            return list(backend.leases_by_duid(text.lower()))
        except (NotSupported, AttributeError):
            return list(backend.leases_by_hw(text.lower()))
    return by_hostname(backend, text.lower())


def by_hostname(backend: Any, needle: str) -> list[Lease]:
    """Leases whose hostname contains `needle`: Kea's exact lookup, then a bounded page walk for
    the partial matches ("printer" finds printer.example.lan.), at most SCAN_LIMIT leases read."""
    found: dict[tuple[str, str | None], Lease] = {}
    try:
        for lease in backend.leases_by_hostname(needle):
            found[(lease.ip_address, lease.lease_type)] = lease
    except ConnectorError:
        pass
    cursor: str | None = None
    read = 0
    while read < SCAN_LIMIT:
        try:
            rows, cursor = page(backend, None, cursor, MAX_PAGE)
        except (ConnectorError, NotSupported):
            break
        read += len(rows)
        for lease in rows:
            if needle in (lease.hostname or "").lower():
                found.setdefault((lease.ip_address, lease.lease_type), lease)
        if cursor is None or not rows:
            break
    return list(found.values())


def page(
    backend: Any, subnet_id: int | None, from_address: str | None, limit: int
) -> tuple[list[Lease], str | None]:
    """(leases, next cursor); the cursor is None once the table is exhausted."""
    limit = max(1, min(int(limit), MAX_PAGE))
    walker = getattr(backend, "lease_page", None)
    if callable(walker):
        return walker(subnet_id=subnet_id, from_address=from_address, limit=limit, max_pages=MAX_SCAN_PAGES)
    rows = backend.leases(subnet_id, limit=limit, from_address=from_address)
    return rows, (rows[-1].ip_address if len(rows) >= limit else None)
