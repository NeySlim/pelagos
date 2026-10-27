# SPDX-License-Identifier: Apache-2.0
"""Zones that come with the distribution or with named itself: never served outside, never checked.

One list for every zone check and for the security audit. Names are lower case with the final dot.
"""

from __future__ import annotations

# named.conf.default-zones and named.rfc1912.zones (Debian db.local, db.127, db.0, db.255).
DISTRIBUTION_ZONES = frozenset(
    {
        "localhost.",
        "localhost.localdomain.",
        "127.in-addr.arpa.",
        "1.0.0.127.in-addr.arpa.",
        "0.in-addr.arpa.",
        "255.in-addr.arpa.",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
    }
)

# Automatic empty zones of BIND 9.20 that are never a site's own space (list checked 2026-10-27:
# https://bind9.readthedocs.io/en/v9.20.30/reference.html, "Built-in empty zones"). The RFC 1918,
# RFC 6598 and RFC 4193 reverse zones are left out on purpose: sites serve them for real.
AUTOMATIC_EMPTY_ZONES = frozenset(
    {
        "254.169.in-addr.arpa.",
        "2.0.192.in-addr.arpa.",
        "100.51.198.in-addr.arpa.",
        "113.0.203.in-addr.arpa.",
        "255.255.255.255.in-addr.arpa.",
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
        "8.b.d.0.1.0.0.2.ip6.arpa.",
        "8.e.f.ip6.arpa.",
        "9.e.f.ip6.arpa.",
        "a.e.f.ip6.arpa.",
        "b.e.f.ip6.arpa.",
        "empty.as112.arpa.",
        "home.arpa.",
        "resolver.arpa.",
    }
)

BUILTIN_ZONES = DISTRIBUTION_ZONES | AUTOMATIC_EMPTY_ZONES


def is_builtin_zone(name: str) -> bool:
    return name.lower().rstrip(".") + "." in BUILTIN_ZONES
