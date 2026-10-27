# SPDX-License-Identifier: Apache-2.0
"""Item 24: delegation and SOA sanity of the primary zones this node serves.

Subjects (kind delegation_issue, `<z>` is `zone` or `zone@view`): `ns-unresolved:<z>:<ns>`,
`ns-silent:<z>:<ns>`, `ns-transfer:<z>:<ns>`, `ns-extra:<address>` (grouped over the zones by
`group_extra`), `soa-range:<z>` (one per zone, every out of range field in its details),
`view-unchecked:<view>` (no read key selects the view). Built-in and automatic empty zones are
skipped by the caller (`builtin_zones`). Every view is checked through its own read key; also-notify
and allow-transfer are the effective
lists (zone, else view, else options).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import Any, Protocol

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from pelagos.collector.checks.settings import CheckSettings
from pelagos.connectors.base import NotSupported
from pelagos.domain import Alert, AlertKind, Engine, Severity, messages


class Net(Protocol):
    def resolve(self, name: str, key: Any = None) -> list[str]: ...

    def answers_for(self, address: str, zone: str, key: Any = None) -> bool: ...


def _signed(query: dns.message.Message, key: Any) -> dns.message.Message:
    if key is not None:
        query.use_tsig(key.keyring, keyname=key.name, algorithm=key.dns_algorithm)
    return query


class DnsNet:
    """Real lookups: the local server first (in-zone names, in the view `key` selects), then the system
    resolver. Name servers are probed on `probe_port`."""

    def __init__(self, local_server: str, local_port: int, timeout: float, probe_port: int = 53) -> None:
        self.local = (local_server, local_port)
        self.timeout = timeout
        self.probe_port = probe_port
        # One instance serves one pass: a server that timed out is not asked again in that pass.
        self._silent: set[str] = set()
        self._local_silent = False

    def resolve(self, name: str, key: Any = None) -> list[str]:
        found: list[str] = []
        for rtype in ("A", "AAAA"):
            found.extend(self._lookup(name, rtype, key))
        return list(dict.fromkeys(found))

    def _lookup(self, name: str, rtype: str, key: Any = None) -> list[str]:
        query = _signed(dns.message.make_query(name, rtype), key)
        try:
            if self._local_silent:
                raise dns.exception.Timeout
            reply = dns.query.udp(query, self.local[0], port=self.local[1], timeout=self.timeout)
            answers = [
                r.to_text() for rr in reply.answer if rr.rdtype == dns.rdatatype.from_text(rtype) for r in rr
            ]
            if answers:
                return answers
        except dns.exception.Timeout:
            self._local_silent = True
        except Exception:  # noqa: S110 (falls through to the system resolver)
            pass
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout
            return [r.to_text() for r in resolver.resolve(name, rtype)]
        except Exception:
            return []

    def answers_for(self, address: str, zone: str, key: Any = None) -> bool:
        """The server answers authoritatively (AA) with an SOA for the zone, without recursion. With a
        view key the probe is signed first (the peer selects the same view), then sent unsigned.
        An address whose unsigned probe times out is not probed again during this pass."""
        if address in self._silent:
            return False
        verdict: bool | None = False
        for k in dict.fromkeys([key, None]):
            verdict = self._probe(address, zone, k)
            if verdict:
                return True
        if verdict is None:
            self._silent.add(address)
        return False

    def _probe(self, address: str, zone: str, key: Any) -> bool | None:
        """True when it answers for the zone, False when not, None when it did not answer at all."""
        query = _signed(dns.message.make_query(zone, dns.rdatatype.SOA), key)
        query.flags &= ~dns.flags.RD
        try:
            reply = dns.query.udp(query, address, port=self.probe_port, timeout=self.timeout)
        except dns.exception.Timeout:
            return None
        except Exception:
            return False
        has_soa = any(rr.rdtype == dns.rdatatype.SOA for rr in reply.answer)
        return reply.rcode() == dns.rcode.NOERROR and bool(reply.flags & dns.flags.AA) and has_soa


def _zone_label(zone: str, view: str) -> str:
    name = zone.rstrip(".") or "."
    return name if view in ("", "_default") else f"{name}@{view}"


def _nets(entries: list[str]) -> list[Any]:
    """IP addresses and CIDR blocks among the tokens of an also-notify or allow-transfer list."""
    out: list[Any] = []
    for entry in entries:
        for token in re.split(r"[\s;{}]+", entry):
            try:
                out.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                continue
    return out


def _all_literal(entries: list[str]) -> bool:
    """True when every token of the list is an address, a block or a BIND keyword that is not a name."""
    for entry in entries:
        for token in re.split(r"[\s;{}]+", entry):
            if not token or token in ("port", "dscp", "transport"):
                continue
            if token.isdigit():
                continue
            try:
                ipaddress.ip_network(token, strict=False)
            except ValueError:
                return False
    return True


def _covers(nets: list[Any], address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in n for n in nets if n.version == ip.version)


def parse_soa(text: str) -> dict[str, int] | None:
    parts = text.split()
    if len(parts) < 7:
        return None
    try:
        refresh, retry, expire, minimum = (int(x) for x in parts[3:7])
    except ValueError:
        return None
    return {"refresh": refresh, "retry": retry, "expire": expire, "minimum": minimum}


def soa_alerts(node_id: str, zone: str, view: str, soa_text: str, cfg: CheckSettings) -> list[Alert]:
    soa = parse_soa(soa_text)
    if soa is None:
        return []
    label = _zone_label(zone, view)
    fields = []
    for name in ("refresh", "retry", "expire", "minimum"):
        low, high = getattr(cfg, f"soa_{name}_min_seconds"), getattr(cfg, f"soa_{name}_max_seconds")
        if not low <= soa[name] <= high:
            fields.append({"field": name, "value": soa[name], "low": low, "high": high})
    if not fields:
        return []
    text = ", ".join(f"{f['field']} {f['value']} ({f['low']} to {f['high']})" for f in fields)
    return [
        _alert(
            node_id,
            Severity.INFO,
            f"soa-range:{label}",
            messages.msg("alert.soa_range", zone=label, fields=text),
            {"zone": label, "fields": fields},
        )
    ]


def _alert(
    node_id: str, severity: Severity, subject: str, message: dict[str, Any], details: dict[str, Any]
) -> Alert:
    return Alert(
        kind=AlertKind.DELEGATION_ISSUE,
        severity=severity,
        node_id=node_id,
        engine=Engine.BIND,
        subject=subject,
        **messages.fields("title", message),
        details=details,
    )


def delegation_alerts(
    node_id: str,
    zone: str,
    view: str,
    ns_names: list[str],
    also_notify: list[str],
    allow_transfer: list[str],
    net: Net,
    own_addresses: set[str],
    resolve_cache: Callable[[str], list[str]] | None = None,
    key: Any = None,
) -> list[Alert]:
    """`key` selects the view: name lookups on the local server and name server probes carry it."""
    label = _zone_label(zone, view)
    resolve = resolve_cache or (lambda name: net.resolve(name, key))
    out: list[Alert] = []
    ns_addresses: set[str] = set()
    unresolved = False
    notify_nets = _nets(also_notify)
    transfer_nets = _nets(allow_transfer)
    transfer_checkable = bool(allow_transfer) and _all_literal(allow_transfer)
    for ns in sorted({n.lower().rstrip(".") + "." for n in ns_names}):
        addresses = resolve(ns)
        if not addresses:
            unresolved = True
            out.append(
                _alert(
                    node_id,
                    Severity.WARNING,
                    f"ns-unresolved:{label}:{ns}",
                    messages.msg("alert.ns_unresolved", zone=label, ns=ns),
                    {"zone": label, "ns": ns},
                )
            )
            continue
        ns_addresses.update(addresses)
        silent = [a for a in addresses if not net.answers_for(a, zone, key)]
        if silent:
            out.append(
                _alert(
                    node_id,
                    Severity.WARNING,
                    f"ns-silent:{label}:{ns}",
                    messages.msg("alert.ns_silent", zone=label, ns=ns, address=silent[0]),
                    {"zone": label, "ns": ns, "addresses": silent},
                )
            )
        foreign = [a for a in addresses if a not in own_addresses]
        if transfer_checkable and foreign and not any(_covers(transfer_nets, a) for a in foreign):
            out.append(
                _alert(
                    node_id,
                    Severity.WARNING,
                    f"ns-transfer:{label}:{ns}",
                    messages.msg("alert.ns_no_transfer", zone=label, ns=ns, address=foreign[0]),
                    {"zone": label, "ns": ns, "addresses": foreign},
                )
            )
    listed: set[str] = set()
    for net_ in [*notify_nets, *transfer_nets]:
        if net_.num_addresses == 1:  # a single host: a CIDR block is an access rule, not a server
            listed.add(str(net_.network_address))
    for address in sorted(set() if unresolved else listed - ns_addresses - own_addresses):
        out.append(
            _alert(
                node_id,
                Severity.INFO,
                f"ns-extra:{label}:{address}",
                messages.msg("alert.ns_not_listed", zones=label, address=address),
                {"zone": label, "address": address},
            )
        )
    return out


def view_unchecked_alert(node_id: str, view: str, zones: int, error: Exception) -> Alert:
    """No usable read key for the view: none configured (NotSupported) or its secret is missing here."""
    key = "alert.view_unchecked" if isinstance(error, NotSupported) else "alert.view_key_missing"
    return _alert(
        node_id,
        Severity.INFO,
        f"view-unchecked:{view}",
        messages.msg(key, view=view, zones=zones),
        {"view": view, "zones": zones, "reason": str(error)},
    )


def group_extra(alerts: list[Alert], node_id: str, shown: int = 5) -> list[Alert]:
    """One ns-extra alert per address, listing its zones, instead of one per zone."""
    zones: dict[str, list[str]] = {}
    rest: list[Alert] = []
    for a in alerts:
        if a.subject.startswith("ns-extra:"):
            zones.setdefault(a.details["address"], []).append(a.details["zone"])
        else:
            rest.append(a)
    for address, names in sorted(zones.items()):
        text = ", ".join(names[:shown]) + (", ..." if len(names) > shown else "")
        rest.append(
            _alert(
                node_id,
                Severity.INFO,
                f"ns-extra:{address}",
                messages.msg("alert.ns_not_listed", address=address, zones=text),
                {"address": address, "zones": names},
            )
        )
    return rest
