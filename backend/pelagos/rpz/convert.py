# SPDX-License-Identifier: Apache-2.0
"""Public block lists to RPZ zone text: native RPZ, hosts, plain domains and simple adblock syntax.

Output is a zone body: owners are relative to the zone origin, `name CNAME .` blocks the name and
`*.name CNAME .` its subdomains. The response-policy `policy` clause or an IP redirect decides the
final answer; the records only say which names match.
"""

from __future__ import annotations

import io
import ipaddress
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import TextIO

FORMATS = ("rpz", "hosts", "domains", "adblock")
SOA_LINE = "@ 300 IN SOA localhost. hostmaster.localhost. ( {serial} 3600 600 86400 300 )"
HOSTS_SKIP = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
        "0.0.0.0",  # noqa: S104 (a hosts file entry, not a listen address)
    }
)
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*$", re.I)
_RPZ_RULE = re.compile(r"^(\S+)\s+(?:\d+\s+)?(?:IN\s+)?CNAME\s+\.\s*$", re.I)


class ConvertError(ValueError):
    pass


@dataclass(slots=True)
class Converted:
    text: str
    entries: int
    skipped: int = 0
    format: str = "rpz"
    domains: list[str] = field(default_factory=list)  # filled on request (tests, previews)


def valid_domain(name: str) -> str | None:
    """Lowercase ASCII (IDNA encoded) hostname-like name, or None."""
    name = name.strip().strip(".").lower()
    if not name or len(name) > 253 or _IP.match(name):
        return None
    try:
        if not name.isascii():
            name = name.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not all(_LABEL.match(label) for label in name.split(".")):
        return None
    return name


def detect_format(sample: str) -> str:
    """Guess the format from the first meaningful lines."""
    votes = {"rpz": 0, "hosts": 0, "adblock": 0, "domains": 0}
    seen = 0
    for raw in sample.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!;[":
            continue
        seen += 1
        if line.startswith("$") or re.match(r"^\S+\s+(\d+\s+)?(IN\s+)?(SOA|NS|CNAME|A|AAAA)\s", line, re.I):
            votes["rpz"] += 1
        elif line.startswith(("||", "@@")):
            votes["adblock"] += 1
        elif re.match(r"^\S+\s+\S+", line) and _IP.match(line.split()[0]):
            votes["hosts"] += 1
        else:
            votes["domains"] += 1
        if seen >= 50:
            break
    return max(votes, key=lambda k: votes[k]) if seen else "domains"


def _iter_hosts(lines: Iterable[str]) -> Iterator[str | None]:
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2 or not _IP.match(parts[0]):
            yield None
            continue
        for host in parts[1:]:
            if host.lower() not in HOSTS_SKIP:
                yield host


def _iter_domains(lines: Iterable[str]) -> Iterator[str | None]:
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line or line[0] in "!;[":
            continue
        yield line.removeprefix("*.").split()[0]


def _iter_adblock(lines: Iterable[str]) -> Iterator[str | None]:
    for raw in lines:
        line = raw.strip()
        if not line or line[0] in "!#[":
            continue
        if not line.startswith("||") or "##" in line or "#@#" in line or "#?#" in line:
            yield None
            continue
        host, caret, tail = line[2:].partition("^")
        # `$important` is a plain block; any other option narrows the rule (types, domains).
        narrow = bool(tail) and tail != "$important"
        if not caret or narrow or any(c in host for c in "/*|"):
            yield None
            continue
        yield host


def _iter_native(lines: Iterable[str], seen: dict[str, bool] | None = None) -> Iterator[str | None]:
    for raw in lines:
        line = raw.split(";", 1)[0].strip()
        if not line or line.startswith("$"):
            continue
        if seen is not None and re.search(r"\sSOA\s", line, re.I):
            seen["soa"] = True
        m = _RPZ_RULE.match(line)
        if not m:
            continue
        owner = m.group(1)
        # The apex rule written for `name` covers `*.name`; rpz-* owners are triggers, not names.
        if owner == "@" or owner.startswith(("*.", "rpz-")) or ".rpz-" in owner:
            continue
        yield owner


def header(serial: int, ttl: int = 300) -> list[str]:
    return [f"$TTL {ttl}", SOA_LINE.format(serial=serial), "  IN NS localhost."]


def rule_lines(domain: str, target: str) -> list[str]:
    """Records for one domain: target is a CNAME rdata, or "A <ip>" / "AAAA <ip>" for a redirect."""
    rtype, _, rdata = target.partition(" ")
    if rtype in ("A", "AAAA") and rdata:
        return [f"{domain} {rtype} {rdata}", f"*.{domain} {rtype} {rdata}"]
    return [f"{domain} CNAME {target}", f"*.{domain} CNAME {target}"]


def redirect_target(redirect_ip: str | None) -> str:
    if not redirect_ip:
        return "."
    return ("AAAA " if ":" in redirect_ip else "A ") + redirect_ip


def convert(
    text: str, fmt: str, serial: int, redirect_ip: str | None = None, keep_domains: bool = False
) -> Converted:
    """Convert a downloaded list held in memory (small inputs, tests)."""
    out = io.StringIO()
    result = convert_stream(text.splitlines(), fmt, serial, out, redirect_ip)
    result.text = out.getvalue()
    if keep_domains:
        result.domains = [
            ln.split(" ", 1)[0] for ln in result.text.splitlines() if " CNAME " in ln and ln[0] != "*"
        ]
    return result


def convert_stream(
    lines: Iterable[str], fmt: str, serial: int, out: TextIO, redirect_ip: str | None = None
) -> Converted:
    """Write the zone body for a list to `out`, line by line.

    Subdomains of a listed domain are dropped (the wildcard rule covers them) and duplicates merged.
    A native RPZ is reduced to its qname rules so that every format gets the same policy handling.
    """
    if fmt not in FORMATS:
        raise ConvertError(f"unknown format {fmt}")
    if redirect_ip:
        ipaddress.ip_address(redirect_ip)
    seen: dict[str, bool] = {}
    names: set[str] = set()
    skipped = 0
    items = _iter_native(lines, seen) if fmt == "rpz" else _READERS[fmt](lines)
    for item in items:
        domain = valid_domain(item) if item else None
        if domain is None:
            skipped += 1
        else:
            names.add(domain)
    if fmt == "rpz" and not names and not seen.get("soa"):
        raise ConvertError("not a native RPZ zone: no SOA and no rule")
    kept = _drop_covered(names)
    target = redirect_target(redirect_ip)
    out.write("\n".join(header(serial)) + "\n")
    for domain in sorted(kept):
        out.write("\n".join(rule_lines(domain, target)) + "\n")
    return Converted("", len(kept), skipped, fmt)


_READERS = {"hosts": _iter_hosts, "domains": _iter_domains, "adblock": _iter_adblock}


def _drop_covered(names: set[str]) -> set[str]:
    kept = set()
    for name in names:
        labels = name.split(".")
        if not any(".".join(labels[i:]) in names for i in range(1, len(labels))):
            kept.add(name)
    return kept


def count_rules(zone_text: str) -> int:
    """Domains in a zone body produced by `convert`: apex rules only, wildcard twins not counted."""
    return sum(1 for ln in zone_text.splitlines() if ln and ln[0] not in "$;@ \t*")


def client_ip_owner(cidr: str) -> str:
    """rpz-client-ip owner: `<prefix>.<reversed address words>.rpz-client-ip`, IPv6 zeros as `zz`."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version == 4:
        octets = str(net.network_address).split(".")[::-1]
        return f"{net.prefixlen}.{'.'.join(octets)}.rpz-client-ip"
    words = [w.lstrip("0") or "0" for w in net.network_address.exploded.split(":")]
    words = words[: (net.prefixlen + 15) // 16]
    best = (0, 0)
    start = None
    for i, w in enumerate([*words, "x"]):
        if w == "0":
            start = i if start is None else start
        elif start is not None:
            best = max(best, (i - start, start))
            start = None
    if best[0] >= 2:
        words = [*words[: best[1]], "zz", *words[best[1] + best[0] :]]
    return f"{net.prefixlen}.{'.'.join(reversed(words))}.rpz-client-ip"


def allow_zone_text(domains: Iterable[str], clients: Iterable[str], serial: int) -> str:
    """The local passthru zone: names the admin allows and client networks exempt from every list."""
    out = header(serial)
    for domain in sorted(set(domains)):
        out.extend(rule_lines(domain, "rpz-passthru."))
    for cidr in sorted(set(clients)):
        out.append(f"{client_ip_owner(cidr)} CNAME rpz-passthru.")
    return "\n".join(out) + "\n"
