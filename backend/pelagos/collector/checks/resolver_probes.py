# SPDX-License-Identifier: Apache-2.0
"""Direct probes of the root servers and the TLDs (section 25, batch R2).

Every root server and two servers of each probed TLD get a non-recursive `SOA` query from this
node. Their addresses come from the local resolver (`. NS`, `<tld>. NS`, then A and AAAA), never
from a built-in list. Subjects (kind resolver_health): `resolver:tld:<tld>`, `resolver:root-letters`.
"""

from __future__ import annotations

import errno
import socket
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import Any, Protocol

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from pelagos.collector.checks.settings import CheckSettings
from pelagos.connectors.bind.builtin_zones import is_builtin_zone
from pelagos.domain import Alert, AlertKind, Engine, Severity, messages

PROBE_TIMEOUT = 2.0
PROBE_WORKERS = 16
TLD_SERVERS = 2
# The root zone names its 13 servers a to m under root-servers.net (https://www.iana.org/domains/
# root/servers and https://www.internic.net/domain/named.root, read on 2026-10-29).
ROOT_SUFFIX = ".root-servers.net."
SUBJECTS = ("resolver:root-letters", "resolver:tld:")


def is_probe_subject(subject: str) -> bool:
    return subject == SUBJECTS[0] or subject.startswith(SUBJECTS[1])


@dataclass(slots=True, frozen=True)
class Target:
    kind: str  # "root" or "tld"
    name: str  # root letter or TLD
    address: str
    family: int  # 4 or 6


@dataclass(slots=True)
class ProbeRow:
    """One row of `resolver_probes`: the last result toward one address, `failures` in a row."""

    kind: str
    name: str
    address: str
    family: int
    ok: bool
    rtt_ms: float | None
    checked_at: int
    last_failure: int | None
    failures: int

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.kind, self.name, self.address)


class ProbeNet(Protocol):
    def lookup(self, name: str, rdtype: str) -> list[str] | None: ...
    def soa(self, address: str, zone: str) -> float | None: ...
    def routable(self, address: str) -> bool: ...


class DnsProbeNet:
    """Lookups through the local resolver, SOA probes toward `probe_port` (53 except in tests)."""

    def __init__(self, server: str, port: int, timeout: float = PROBE_TIMEOUT, probe_port: int = 53) -> None:
        self.server = server
        self.port = port
        self.timeout = timeout
        self.probe_port = probe_port

    def lookup(self, name: str, rdtype: str) -> list[str] | None:
        """Targets or addresses. []: the name or type does not exist. None: no answer to rely on
        (timeout, SERVFAIL, or a server that refuses us or does not recurse)."""
        query = dns.message.make_query(name, rdtype)
        try:
            reply = dns.query.udp(query, self.server, port=self.port, timeout=self.timeout)
            if reply.flags & dns.flags.TC:
                reply = dns.query.tcp(query, self.server, port=self.port, timeout=self.timeout)
        except (dns.exception.DNSException, OSError):
            return None
        if not reply.flags & dns.flags.RA:
            return None
        rcode = reply.rcode()
        if rcode == dns.rcode.NXDOMAIN:
            return []
        if rcode != dns.rcode.NOERROR:
            return None
        wanted = dns.rdatatype.from_text(rdtype)
        out: list[str] = []
        for rrset in reply.answer:
            if rrset.rdtype == wanted:
                out.extend(rd.to_text() for rd in rrset)
        return out

    def soa(self, address: str, zone: str) -> float | None:
        """Milliseconds to an authoritative SOA answer for `zone`, None when it did not come."""
        query = dns.message.make_query(zone, dns.rdatatype.SOA)
        query.flags &= ~dns.flags.RD
        start = time.monotonic()
        try:
            reply = dns.query.udp(query, address, port=self.probe_port, timeout=self.timeout)
        except (dns.exception.DNSException, OSError):
            return None
        elapsed = (time.monotonic() - start) * 1000.0
        if reply.rcode() != dns.rcode.NOERROR or not reply.flags & dns.flags.AA:
            return None
        origin = dns.name.from_text(zone)
        if not any(r.rdtype == dns.rdatatype.SOA and r.name == origin for r in reply.answer):
            return None
        return round(elapsed, 1)

    def routable(self, address: str) -> bool:
        """A UDP connect only looks the route up: no packet leaves."""
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            try:
                sock.connect((address, self.probe_port))
            except OSError as exc:
                return exc.errno not in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL)
        return True


def probed_tlds(configured: Iterable[str], zone_names: Iterable[str]) -> dict[str, bool]:
    """TLD -> served by this node, the configured ones first then those of the served zones."""
    out: dict[str, bool] = {}
    for tld in configured:
        tld = str(tld).strip(".").lower()
        if tld:
            out.setdefault(tld, False)
    for zone in zone_names:
        name = zone.strip(".").lower()
        if not name or is_builtin_zone(name):
            continue
        out[name.rsplit(".", 1)[-1]] = True
    return out


def root_letter(ns_name: str) -> str:
    name = ns_name.lower()
    if not name.endswith("."):
        name += "."
    return name[: -len(ROOT_SUFFIX)] if name.endswith(ROOT_SUFFIX) else name.rstrip(".")


class ResolverProbes:
    """Results of the last passes and the targets last resolved. `run` happens on the slow thread,
    `rows` and `load` on the loop thread: the lock covers the shared state."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        self.lock = threading.Lock()
        self.results: dict[tuple[str, str, str], ProbeRow] = {}
        self.tld_failures: dict[str, int] = {}
        self.tld_servers: dict[str, list[str]] = {}
        self.served: dict[str, bool] = {}
        self._roots: list[Target] = []
        self._tld_targets: dict[str, list[Target]] = {}
        self.dirty = False
        self.loaded = False

    def load(self, rows: Iterable[dict[str, Any]]) -> None:
        """Results kept by the cache before a restart; consecutive failures go on from there."""
        with self.lock:
            self.loaded = True
            for r in rows:
                row = ProbeRow(
                    kind=r["kind"], name=r["name"], address=r["address"], family=int(r["family"]),
                    ok=bool(r["ok"]), rtt_ms=r["rtt_ms"], checked_at=int(r["checked_at"]),
                    last_failure=r["last_failure"], failures=int(r["failures"]),
                )  # fmt: skip
                self.results.setdefault(row.key, row)
            for row in self.results.values():
                if row.kind == "tld":
                    seen = self.tld_failures.get(row.name)
                    self.tld_failures[row.name] = row.failures if seen is None else min(seen, row.failures)
                    self.tld_servers.setdefault(row.name, []).append(row.address)

    def rows(self) -> list[dict[str, Any]] | None:
        """Every row to store when a pass changed them, None otherwise."""
        with self.lock:
            if not self.dirty:
                return None
            self.dirty = False
            return [asdict(r) for r in sorted(self.results.values(), key=lambda r: r.key)]

    # Targets -----------------------------------------------------------------

    def _addresses(self, net: ProbeNet, host: str, ipv6: bool) -> list[tuple[str, int]] | None:
        v4 = net.lookup(host, "A")
        v6 = net.lookup(host, "AAAA") if ipv6 else []
        if v4 is None and v6 is None:
            return None
        return [(a, 4) for a in v4 or []] + [(a, 6) for a in v6 or []]

    def _root_targets(self, net: ProbeNet, ipv6: bool) -> list[Target] | None:
        names = net.lookup(".", "NS")
        if not names:
            return None
        out: list[Target] = []
        for host in sorted(set(names)):
            for address, family in self._addresses(net, host, ipv6) or []:
                out.append(Target("root", root_letter(host), address, family))
        return out or None

    def _tld_target(self, net: ProbeNet, tld: str, ipv6: bool) -> list[Target] | None:
        """Two servers of the TLD (first names in order), one address each, IPv4 first.
        []: the TLD does not exist in the public tree (a private `.lan`). None: no answer."""
        names = net.lookup(f"{tld}.", "NS")
        if names is None:
            return None
        out: list[Target] = []
        for host in sorted(set(names)):
            found = self._addresses(net, host, ipv6) or []
            pick = next((a for a in found if a[1] == 4), None) or next(iter(found), None)
            if pick:
                out.append(Target("tld", tld, pick[0], pick[1]))
            if len(out) == TLD_SERVERS:
                break
        return out if out or not names else None

    # Pass --------------------------------------------------------------------

    def run(self, net: ProbeNet, tlds: dict[str, bool], ipv6: bool) -> bool:
        """One pass; False when the root server list cannot be learnt (no verdict at all)."""
        roots = self._root_targets(net, ipv6)
        if roots is None:
            roots = self._roots
        if not roots:
            return False
        self._roots = roots
        targets = list(roots)
        tld_now: dict[str, list[Target]] = {}
        for tld in tlds:
            found = self._tld_target(net, tld, ipv6)
            if found is None:
                found = self._tld_targets.get(tld)
            if found:
                tld_now[tld] = found
                targets.extend(found)
        self._tld_targets = tld_now
        v6 = [t for t in targets if t.family == 6]
        if v6 and not net.routable(v6[0].address):
            targets = [t for t in targets if t.family == 4]
        with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
            zones = ["." if t.kind == "root" else f"{t.name}." for t in targets]
            rtts = list(pool.map(net.soa, [t.address for t in targets], zones))
        now = int(self.clock())
        with self.lock:
            fresh: dict[tuple[str, str, str], ProbeRow] = {}
            for target, rtt in zip(targets, rtts, strict=True):
                key = (target.kind, target.name, target.address)
                prev = self.results.get(key)
                ok = rtt is not None
                fresh[key] = ProbeRow(
                    kind=target.kind, name=target.name, address=target.address, family=target.family,
                    ok=ok, rtt_ms=rtt, checked_at=now,
                    last_failure=now if not ok else (prev.last_failure if prev else None),
                    failures=0 if ok else (prev.failures if prev else 0) + 1,
                )  # fmt: skip
            failures: dict[str, int] = {}
            for tld, found in tld_now.items():
                answered = any(fresh[(t.kind, t.name, t.address)].ok for t in found if t in targets)
                probed = any(t in targets for t in found)
                prev = self.tld_failures.get(tld, 0)
                failures[tld] = prev if not probed else 0 if answered else prev + 1
            self.results = fresh
            self.tld_failures = failures
            self.tld_servers = {
                tld: [t.address for t in found if t in targets] for tld, found in tld_now.items()
            }
            self.served = {tld: tlds[tld] for tld in tld_now}
            self.dirty = True
        return True

    # Alerts ------------------------------------------------------------------

    def alerts(self, node_id: str, cfg: CheckSettings) -> list[Alert]:
        need = int(cfg.resolver_tld_failures)
        out: list[Alert] = []
        with self.lock:
            for tld in sorted(self.tld_failures):
                count = self.tld_failures[tld]
                if count >= need:
                    out.append(
                        _alert(
                            Severity.WARNING,
                            f"tld:{tld}",
                            messages.msg("alert.resolver_tld", tld=tld, failures=count),
                            {
                                "tld": tld,
                                "failures": count,
                                "servers": self.tld_servers.get(tld, []),
                                "remediation": "resolver_fallback",
                            },
                            node_id,
                        )
                    )
            roots = [r for r in self.results.values() if r.kind == "root"]
            letters = sorted({r.name for r in roots})
            # Same patience as a TLD: one lost UDP answer is not a silent letter.
            down = sorted((r for r in roots if r.failures >= need), key=lambda r: r.key)
            if down:
                silent = sorted({r.name for r in down})
                out.append(
                    _alert(
                        Severity.INFO,
                        "root-letters",
                        messages.msg(
                            "alert.resolver_root_letters",
                            count=len(silent),
                            total=len(letters),
                            letters=", ".join(silent),
                        ),
                        {
                            "letters": silent,
                            "count": len(silent),
                            "total": len(letters),
                            "addresses": sorted(r.address for r in down),
                        },
                        node_id,
                    )
                )
        return out


def _alert(
    severity: Severity, subject: str, message: dict[str, Any], details: dict[str, Any], node_id: str
) -> Alert:
    return Alert(
        kind=AlertKind.RESOLVER_HEALTH,
        severity=severity,
        node_id=node_id,
        engine=Engine.BIND,
        subject=f"resolver:{subject}",
        **messages.fields("title", message),
        details=details,
    )
