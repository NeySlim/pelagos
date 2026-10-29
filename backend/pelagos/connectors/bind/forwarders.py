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
    """The address in its canonical form; ValueError when it is not an IPv4 or IPv6 address.
    A scope id is refused: ipaddress takes almost any text after `%`, named.conf syntax included."""
    text = str(text).strip()
    if "%" in text:
        raise ValueError(f"{text!r}: a scoped address is not a forwarder")
    return str(ipaddress.ip_address(text))


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
    """Elements of a forwarders value as named prints it; None for an absent statement. ValueError
    for a value `value()` cannot write back as it was: the global `port`/`tls` prefix form
    (`port 5353 { ... }`), nested braces or a comment."""
    if text is None:
        return None
    body = text.strip()
    inner = body[1:-1] if body.startswith("{") and body.endswith("}") else None
    if inner is None or any(c in inner for c in "{}#") or "//" in inner or "/*" in inner:
        raise ValueError(f"forwarders {body!r} use a form the fallback cannot restore exactly")
    return [" ".join(e.split()) for e in inner.split(";") if e.strip()]


def same(text: str | None, expected: list[str] | None) -> bool:
    """True when a forwarders value holds exactly the expected elements (quotes and spacing aside)."""
    try:
        got = elements(text)
    except ValueError:
        return False
    if got is None or expected is None:
        return got is None and expected is None
    return [e.replace('"', "") for e in got] == [" ".join(e.split()).replace('"', "") for e in expected]


def tls_statement(name: str) -> str:
    return f"tls {quote(name)} {{ remote-hostname {quote(name)}; }};"
