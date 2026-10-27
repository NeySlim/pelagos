# SPDX-License-Identifier: Apache-2.0
"""The HTTP listener of the Kea HA hook, the firewall rules that guard it, and the guard Pelagos adds.

With HA+MT (the default in Kea 2.6 and 3.x), each server runs a dedicated listener on its own peer `url`.
It takes any command of the daemon unless `restrict-commands` is true (the default only since Kea
3.0.0), and it checks no basic authentication: `CmdResponseCreator::http_auth_config_` is never set
by the HA hook in Kea 2.6.3 to 3.2.0 (src/lib/config/cmd_response_creator.h). TLS with
`require-client-certs` (default true) is the only authentication it has. Sources, read 2026-10-27:
the ARM (https://gitlab.isc.org/isc-projects/kea/-/blob/Kea-2.6.3/doc/sphinx/arm/hooks-ha.rst, same
file at Kea-3.2.0: "HTTPS support", "Multi-Threaded Configuration (HA+MT)") and, under
src/hooks/dhcp/high_availability/ at both tags, ha_config_parser.cc (defaults), ha_service.cc (the
listener), command_creator.cc (what restrict-commands keeps); Kea ChangeLog entry 2367.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pelagos.installer import keaconf

GUARD_TABLE = "pelagos_kea_ha_guard"
GUARD_UNIT = "pelagos-kea-ha-guard.service"
GUARD_FILE = "kea-ha-guard.nft"
# Guards set up by hand that the audit recognizes by name (any table, or these units).
KNOWN_TABLES = frozenset({GUARD_TABLE, "kea_ha_guard"})
KNOWN_UNITS = (GUARD_UNIT, "kea-ha-guard.service")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
# restrict-commands exists since Kea 2.1.7 and defaults to true since 3.0.0 (ChangeLog 2367).
RESTRICT_SINCE = (2, 1, 7)
RESTRICT_DEFAULT_SINCE = (3, 0, 0)
# The commands a restricted listener keeps (command_creator.cc): still enough to stop DHCP.
RESTRICTED_KEEPS = ("dhcp-disable", "lease4-del", "lease6-del", "lease4-update", "lease6-update")


@dataclass(slots=True)
class HAListener:
    """The dedicated listener of one HA relationship of one daemon (hook and relationship index)."""

    engine: str
    server: str
    host: str
    port: int
    hook_index: int
    rel_index: int
    tls: bool
    require_client_certs: bool
    restrict_commands: bool
    restrict_explicit: bool
    peers: list[str] = field(default_factory=list)  # addresses of the other peers
    heartbeat_ms: int = 10000

    @property
    def address(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"

    @property
    def local(self) -> bool:
        if self.host in LOOPBACK_HOSTS:
            return True
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return False

    @property
    def open(self) -> bool:
        """Reachable off this host and accepting a client without a certificate."""
        return not self.local and not (self.tls and self.require_client_certs)


def supports_restrict(version: str | None) -> bool:
    return version is None or keaconf.version_tuple(version) >= RESTRICT_SINCE


def restrict_default(version: str | None) -> bool:
    return version is not None and keaconf.version_tuple(version) >= RESTRICT_DEFAULT_SINCE


def _url_host_port(url: str) -> tuple[str, int] | None:
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None
    return (host, port) if host else None


def _relationships(body: dict[str, Any]) -> list[tuple[int, int, dict[str, Any]]]:
    out = []
    for hi, hook in enumerate(body.get("hooks-libraries") or []):
        if not isinstance(hook, dict) or not str(hook.get("library", "")).endswith("libdhcp_ha.so"):
            continue
        params = hook.get("parameters") or {}
        rels = params.get("high-availability") if isinstance(params, dict) else None
        for ri, rel in enumerate(rels if isinstance(rels, list) else []):
            if isinstance(rel, dict):
                out.append((hi, ri, rel))
    return out


def _filled(rel: dict[str, Any], peer: dict[str, Any], name: str) -> bool:
    value = peer.get(name, rel.get(name))
    return isinstance(value, str) and value != ""


def listeners(engine: str, config: dict[str, Any], version: str | None) -> list[HAListener]:
    """The dedicated HA listeners `config` opens. Without HA+MT (core or HA multi-threading off, or
    http-dedicated-listener false) HA goes through kea-ctrl-agent, audited on its own."""
    try:
        body = config[keaconf.root_key(config)]
    except keaconf.KeaConfigError:
        return []
    core_mt = (body.get("multi-threading") or {}).get("enable-multi-threading", True)
    out: list[HAListener] = []
    for hi, ri, rel in _relationships(body):
        mt = rel.get("multi-threading") or {}
        if not (
            core_mt and mt.get("enable-multi-threading", True) and mt.get("http-dedicated-listener", True)
        ):
            continue
        name = rel.get("this-server-name")
        peers = [p for p in rel.get("peers") or [] if isinstance(p, dict)]
        me = next((p for p in peers if p.get("name") == name), None)
        where = _url_host_port(str(me.get("url", ""))) if me else None
        if me is None or where is None:
            continue
        others = []
        for p in peers:
            hp = _url_host_port(str(p.get("url", ""))) if p is not me else None
            if hp and hp[0] not in others:
                others.append(hp[0])
        tls = all(_filled(rel, me, k) for k in ("trust-anchor", "cert-file", "key-file"))
        explicit = "restrict-commands" in rel
        out.append(
            HAListener(
                engine=engine,
                server=str(name),
                host=where[0],
                port=where[1],
                hook_index=hi,
                rel_index=ri,
                tls=tls,
                require_client_certs=bool(rel.get("require-client-certs", True)),
                restrict_commands=bool(rel["restrict-commands"]) if explicit else restrict_default(version),
                restrict_explicit=explicit,
                peers=others,
                heartbeat_ms=int(rel.get("heartbeat-delay", 10000) or 10000),
            )
        )
    return out


def with_restrict_commands(config: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """A copy of `config` with `restrict-commands: true` in every HA relationship; how many changed."""
    new = json.loads(json.dumps(config))
    body = new[keaconf.root_key(new)]
    changed = 0
    for _hi, _ri, rel in _relationships(body):
        if rel.get("restrict-commands") is not True:
            rel["restrict-commands"] = True
            changed += 1
    return new, changed


# Firewall -----------------------------------------------------------------------------------------


@dataclass(slots=True)
class Guard:
    """A rule set that keeps other hosts off a port: where it is and the sources it lets in."""

    source: str
    allowed: list[str] = field(default_factory=list)


def _port_in(right: Any, port: int) -> bool:
    if isinstance(right, int):
        return right == port
    if isinstance(right, dict):
        if "set" in right:
            return any(_port_in(v, port) for v in right["set"])
        if "range" in right:
            lo, hi = right["range"]
            return isinstance(lo, int) and isinstance(hi, int) and lo <= port <= hi
    if isinstance(right, list):
        return any(_port_in(v, port) for v in right)
    return False


def _addresses(right: Any) -> list[str]:
    if isinstance(right, str):
        return [right]
    if isinstance(right, dict):
        if "set" in right:
            return [a for v in right["set"] for a in _addresses(v)]
        if "prefix" in right:
            p = right["prefix"]
            return [f"{p.get('addr')}/{p.get('len')}"]
        if "range" in right:
            return ["-".join(str(v) for v in right["range"])]
    return []


def _rule_shape(exprs: list[dict[str, Any]], port: int) -> tuple[bool, str | None, list[str], str | None]:
    """(matches the TCP port, saddr operator, saddr values, verdict) of one nft JSON rule."""
    dport = False
    op: str | None = None
    addrs: list[str] = []
    verdict = None
    for e in exprs:
        m = e.get("match") if isinstance(e, dict) else None
        if isinstance(m, dict):
            payload = (m.get("left") or {}).get("payload") if isinstance(m.get("left"), dict) else None
            if isinstance(payload, dict):
                if payload.get("field") == "dport" and payload.get("protocol") in ("tcp", "th"):
                    dport = m.get("op", "==") in ("==", "in") and _port_in(m.get("right"), port)
                elif payload.get("field") == "saddr" and payload.get("protocol") in ("ip", "ip6"):
                    op = "!=" if m.get("op") == "!=" else "=="
                    addrs += _addresses(m.get("right"))
            continue
        for v in ("accept", "drop", "reject"):
            if isinstance(e, dict) and v in e:
                verdict = v
    return dport, op, addrs, verdict


def nft_guard(ruleset: dict[str, Any] | None, port: int) -> Guard | None:
    """A drop or reject of `port` for every source but some (or behind an input policy drop that only
    sources lets through), in an `nft -j list ruleset` document."""
    if not isinstance(ruleset, dict):
        return None
    items = [i for i in ruleset.get("nftables") or [] if isinstance(i, dict)]
    drop_policy = {
        (c["family"], c["table"], c["name"])
        for c in (i.get("chain") for i in items)
        if isinstance(c, dict) and c.get("hook") == "input" and c.get("policy") == "drop"
    }
    allowed: list[str] = []
    found: str | None = None
    open_accept = False
    for rule in (i["rule"] for i in items if isinstance(i.get("rule"), dict)):
        dport, op, addrs, verdict = _rule_shape(rule.get("expr") or [], port)
        if not dport:
            continue
        where = f"nftables table {rule.get('family')} {rule.get('table')}"
        if verdict in ("drop", "reject") and op != "==":
            found = found or where
            if op == "!=":
                allowed += addrs
        elif verdict == "accept" and op == "==":
            allowed += addrs
            if rule.get("table") in KNOWN_TABLES:
                found = found or where
        elif verdict == "accept":
            open_accept = True
    if found is None and drop_policy and allowed and not open_accept:
        fam, table, _chain = sorted(drop_policy)[0]
        found = f"nftables table {fam} {table}"
    return Guard(found, sorted(set(allowed))) if found else None


_IPT_PORT = re.compile(r"--dports?\s+(\S+)")


def iptables_guard(save: str | None, port: int) -> Guard | None:
    """The same in `iptables-save` (or `ip6tables-save`) output, INPUT chain."""
    if not save:
        return None
    allowed: list[str] = []
    found = False
    policy_drop = False
    open_accept = False
    for line in save.splitlines():
        if line.startswith(":INPUT DROP"):
            policy_drop = True
        if not line.startswith("-A INPUT"):
            continue
        m = _IPT_PORT.search(line)
        if not m or "-p tcp" not in line:
            continue
        ports: list[int] = []
        for part in m.group(1).split(","):
            lo, _, hi = part.partition(":")
            if lo.isdigit():
                ports += list(range(int(lo), int(hi or lo) + 1))
        if port not in ports:
            continue
        src = re.search(r"(!\s+)?-s\s+(\S+)", line)
        target = re.search(r"-j\s+(\S+)", line)
        verdict = target.group(1) if target else ""
        if verdict in ("DROP", "REJECT") and not (src and not src.group(1)):
            found = True
            if src:
                allowed.append(src.group(2))
        elif verdict == "ACCEPT" and src and not src.group(1):
            allowed.append(src.group(2))
        elif verdict == "ACCEPT":
            open_accept = True
    if found or (policy_drop and allowed and not open_accept):
        return Guard("iptables INPUT", sorted(set(allowed)))
    return None


@dataclass(slots=True)
class Firewall:
    """What the audit could read of this host's packet filter."""

    nft: dict[str, Any] | None = None
    iptables: str | None = None
    units: list[str] = field(default_factory=list)  # known guard units that are active

    def guard(self, port: int) -> Guard | None:
        found = nft_guard(self.nft, port) or iptables_guard(self.iptables, port)
        if found is None and self.nft is None and self.units:
            # The rule set could not be read: an active guard unit is taken at its word.
            return Guard(f"service {self.units[0]}")
        return found


def read_firewall(env: Any) -> Firewall:
    """Read-only: `nft -j list ruleset`, `iptables-save` and `ip6tables-save` when present."""
    fw = Firewall()
    out = _run(env, ["nft", "-j", "list", "ruleset"])
    if out:
        try:
            fw.nft = json.loads(out)
        except ValueError:
            fw.nft = None
    saves = [s for s in (_run(env, ["iptables-save"]), _run(env, ["ip6tables-save"])) if s]
    fw.iptables = "\n".join(saves) or None
    for unit in KNOWN_UNITS:
        try:
            if env.services.is_active(unit):
                fw.units.append(unit)
        except Exception:  # noqa: S112 - a unit query that fails is only a missing hint
            continue
    return fw


def _run(env: Any, argv: list[str]) -> str | None:
    if env.binary(argv[0]) is None:
        return None
    try:
        res = env.runner.run(argv, privileged=True, check=False, mutates=False, timeout=15)
    except Exception:
        return None
    return res.stdout if getattr(res, "ok", False) else None


# Guard that Pelagos sets up ---------------------------------------------------------------------


def _family(addr: str) -> str:
    return "ip6" if ":" in addr else "ip"


def render_guard(ports: list[int], peers: list[str]) -> str:
    """An nft file (loaded atomically by `nft -f`) letting only loopback and `peers` reach `ports`."""
    plist = ", ".join(str(p) for p in sorted(set(ports)))
    lines = [
        "# pelagos:managed v1",
        "# Only the Kea HA peers reach the HA listeners of this node (security audit, kea_ha_listener_open).",
        f"table inet {GUARD_TABLE}",
        f"delete table inet {GUARD_TABLE}",
        f"table inet {GUARD_TABLE} {{",
        "\tchain input {",
        "\t\ttype filter hook input priority -10; policy accept;",
        f'\t\tiif "lo" tcp dport {{ {plist} }} accept',
    ]
    for fam in ("ip", "ip6"):
        mine = sorted({p for p in peers if _family(p) == fam})
        if mine:
            lines.append(f"\t\t{fam} saddr {{ {', '.join(mine)} }} tcp dport {{ {plist} }} counter accept")
    lines += [f"\t\ttcp dport {{ {plist} }} counter drop", "\t}", "}", ""]
    return "\n".join(lines)


def render_unit(nft: str, rules: Path) -> str:
    return (
        "# pelagos:managed v1\n"
        "[Unit]\n"
        "Description=Pelagos: only the Kea HA peers reach the HA listeners\n"
        "After=nftables.service firewalld.service\n"
        "Before=isc-kea-dhcp4-server.service isc-kea-dhcp6-server.service "
        "kea-dhcp4-server.service kea-dhcp6-server.service kea-dhcp4.service kea-dhcp6.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"ExecStart={nft} -f {rules}\n"
        f"ExecStop=-{nft} delete table inet {GUARD_TABLE}\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def guard_counters(env: Any) -> tuple[int, int] | None:
    """(packets accepted from the peers, packets dropped) by the Pelagos guard, None if not loaded."""
    out = _run(env, ["nft", "-j", "list", "table", "inet", GUARD_TABLE])
    if not out:
        return None
    try:
        doc = json.loads(out)
    except ValueError:
        return None
    accepted = dropped = 0
    for item in doc.get("nftables") or []:
        rule = item.get("rule") if isinstance(item, dict) else None
        if not isinstance(rule, dict):
            continue
        exprs = rule.get("expr") or []
        packets = sum(
            int(e["counter"].get("packets", 0)) for e in exprs if isinstance(e.get("counter"), dict)
        )
        if any("drop" in e for e in exprs):
            dropped += packets
        elif any("accept" in e for e in exprs):
            accepted += packets
    return accepted, dropped


def watch_peers(env: Any, seconds: float, sleep: Any = time.sleep) -> str:
    """'peers' when packets from the peers got through, 'blocked' when only drops grew, 'quiet'."""
    start = guard_counters(env)
    if start is None:
        return "quiet"
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        sleep(1.0)
        now = guard_counters(env)
        if now is None:
            break
        if now[0] > start[0]:
            return "peers"
    now = guard_counters(env) or start
    return "blocked" if now[1] > start[1] and now[0] == start[0] else "quiet"
