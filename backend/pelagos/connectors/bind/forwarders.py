# SPDX-License-Identifier: Apache-2.0
"""The `forward` and `forwarders` options of a resolver fallback (section 25) as named.conf text.

With a TLS name every forwarder is `<address> port 853 tls "<name>"` and a top-level
`tls "<name>" { remote-hostname "<name>"; };` makes named check the server certificate against the
system store (BIND 9.20 ARM, `remote-hostname`, read on 2026-10-29).
"""

from __future__ import annotations

import ipaddress
import re

from pelagos.connectors.bind.namedconf.tree import quote

DOT_PORT = 853
_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
TLS_NAME_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")


def check_address(text: str) -> str:
    """The address in its canonical form; ValueError when it is not an IPv4 or IPv6 address."""
    return str(ipaddress.ip_address(str(text).strip()))


def check_tls_name(name: str) -> str:
    name = str(name).strip().rstrip(".")
    if not TLS_NAME_RE.match(name):
        raise ValueError(f"{name!r} is not a host name")
    return name


def element(address: str, tls_name: str | None = None) -> str:
    return f"{address} port {DOT_PORT} tls {quote(tls_name)}" if tls_name else address


def value(elements: list[str]) -> str:
    """The option value of a forwarders list, `{ a; b; }` (`{ }` for an empty list)."""
    return "{ " + "".join(f"{e}; " for e in elements) + "}"


def fallback_value(addresses: list[str], tls_name: str | None = None) -> str:
    return value([element(a, tls_name) for a in addresses])


def elements(text: str | None) -> list[str] | None:
    """Elements of a forwarders value as named prints it; None for an absent statement."""
    if text is None:
        return None
    return [" ".join(e.split()) for e in text.strip().strip("{}").split(";") if e.strip()]


def same(text: str | None, expected: list[str] | None) -> bool:
    """True when a forwarders value holds exactly the expected elements (quotes and spacing aside)."""
    got = elements(text)
    if got is None or expected is None:
        return got is None and expected is None
    return [e.replace('"', "") for e in got] == [" ".join(e.split()).replace('"', "") for e in expected]


def tls_statement(name: str) -> str:
    return f"tls {quote(name)} {{ remote-hostname {quote(name)}; }};"
