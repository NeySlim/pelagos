# SPDX-License-Identifier: Apache-2.0
"""The nftables guard of the Kea HA listeners as an object Pelagos manages: status, edit, adoption.

Pelagos's guard is table `inet pelagos_kea_ha_guard`, loaded by `pelagos-kea-ha-guard.service` from
`<etc>/kea-ha-guard.nft` (installer.ha_listener). A guard set up by hand under the names
`inet kea_ha_guard` / `kea-ha-guard.service` (rules usually in /etc/nftables.d) is adopted by
loading the same addresses into Pelagos's table first and only then retiring the hand-made one, so
the listener is never unguarded; any failure puts the hand-made guard back before removing Pelagos's.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.domain import Change, ChangeOp, Plan, PlanScope, PlanState, messages
from pelagos.domain.messages import join, msg
from pelagos.installer import ha_listener, keaconf, keasetup, ledger

KEY = "ha_guard"
LEGACY_TABLE = "kea_ha_guard"
LEGACY_UNIT = "kea-ha-guard.service"
LEGACY_RULES = "etc/nftables.d/kea-ha-guard.nft"  # under the host root
_EXEC_FILE = re.compile(r"^ExecStart=\S*nft\s+(?:-\S+\s+)*-f\s+(\S+)", re.M)
_EXEC_STOP = re.compile(r"^ExecStop=(.*)$", re.M)


@dataclass(slots=True)
class TableState:
    """The ports a guard table filters and the source addresses it admits (loopback aside)."""

    table: str
    ports: list[int] = field(default_factory=list)
    peers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Legacy:
    """A guard set up by hand under the names the audit knows."""

    unit: Path | None
    rules: list[Path]
    table: TableState | None
    exec_stop: list[str]

    @property
    def source(self) -> str:
        return f"table inet {LEGACY_TABLE}, {LEGACY_UNIT}"


# Addresses ---------------------------------------------------------------------------------------


def normalize_peers(values: Any) -> list[str]:
    """Sorted unique addresses or prefixes; a host prefix becomes the bare address. ValueError on
    anything else, since the values end up in an nft file."""
    if not isinstance(values, list) or not values:
        raise ValueError("peers must be a non-empty list of addresses or prefixes")
    out: set[str] = set()
    for v in values:
        if not isinstance(v, str) or not v.strip():
            raise ValueError(f"invalid peer address {v!r}")
        try:
            net = ipaddress.ip_network(v.strip(), strict=False)
        except ValueError:
            raise ValueError(f"invalid peer address {v!r}") from None
        full = net.prefixlen == net.max_prefixlen
        out.add(str(net.network_address) if full else str(net))
    return sorted(out, key=lambda a: (":" in a, ipaddress.ip_network(a, strict=False)))


def _safe_peers(values: list[str]) -> list[str]:
    try:
        return normalize_peers(values) if values else []
    except ValueError:
        return sorted(set(values))


# Reading -----------------------------------------------------------------------------------------


def _ports(right: Any) -> list[int]:
    if isinstance(right, int):
        return [right]
    if isinstance(right, dict) and "set" in right:
        return [p for v in right["set"] for p in _ports(v)]
    if isinstance(right, dict) and "range" in right:
        lo, hi = right["range"]
        return list(range(int(lo), int(hi) + 1)) if hi - lo < 1024 else []
    if isinstance(right, list):
        return [p for v in right for p in _ports(v)]
    return []


def parse_table(doc: Any, table: str) -> TableState | None:
    """The guard in an `nft -j list table inet <table>` (or ruleset) document."""
    if not isinstance(doc, dict):
        return None
    items = [i for i in doc.get("nftables") or [] if isinstance(i, dict)]
    tables = [i["table"].get("name") for i in items if isinstance(i.get("table"), dict)]
    if table not in tables:
        return None
    state = TableState(table)
    ports: set[int] = set()
    peers: list[str] = []
    for rule in (i["rule"] for i in items if isinstance(i.get("rule"), dict)):
        if rule.get("table") not in (None, table):
            continue
        rports: list[int] = []
        allow: list[str] = []
        deny_but: list[str] = []
        verdict = None
        for e in rule.get("expr") or []:
            m = e.get("match") if isinstance(e, dict) else None
            if isinstance(m, dict) and isinstance(m.get("left"), dict):
                payload = m["left"].get("payload")
                if isinstance(payload, dict) and payload.get("field") == "dport":
                    rports += _ports(m.get("right"))
                elif isinstance(payload, dict) and payload.get("field") == "saddr":
                    target = deny_but if m.get("op") == "!=" else allow
                    target += ha_listener._addresses(m.get("right"))
            elif isinstance(e, dict):
                verdict = next((v for v in ("accept", "drop", "reject") if v in e), verdict)
        ports.update(rports)
        # `saddr X accept` and `saddr != X drop` both admit exactly X.
        if rports and verdict == "accept":
            peers += allow
        elif rports and verdict in ("drop", "reject"):
            peers += deny_but
    state.ports = sorted(ports)
    state.peers = _safe_peers(peers)
    return state


def parse_text(text: str) -> TableState:
    """The same from an nft file, for a hand-made guard that is not loaded."""
    state = TableState(LEGACY_TABLE)
    ports: set[int] = set()
    peers: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        dport = re.search(r"dport\s+(\{[^}]*\}|\d+)", line)
        if not dport:
            continue
        ports.update(int(p) for p in re.findall(r"\d+", dport.group(1)))
        saddr = re.search(r"ip6?\s+saddr\s+(!=\s*)?(\{[^}]*\}|\S+)", line)
        negated = bool(saddr and saddr.group(1))
        verdict = re.search(r"\b(accept|drop|reject)\b", line)
        if saddr and verdict and (verdict.group(1) == "accept") != negated:
            peers += [a for a in re.split(r"[\s,{}]+", saddr.group(2)) if a]
    state.ports = sorted(ports)
    state.peers = _safe_peers(peers)
    return state


def loaded(env: Any, table: str) -> TableState | None:
    out = ha_listener._run(env, ["nft", "-j", "list", "table", "inet", table])
    if not out:
        return None
    try:
        return parse_table(json.loads(out), table)
    except ValueError:
        return None


def rules_path(env: Any) -> Path:
    return Path(env.node_paths.etc) / ha_listener.GUARD_FILE


def unit_path(env: Any) -> Path:
    return Path(env.paths.systemd_dir) / ha_listener.GUARD_UNIT


def legacy(env: Any) -> Legacy | None:
    unit = Path(env.paths.systemd_dir) / LEGACY_UNIT
    unit_text = unit.read_text() if unit.is_file() else ""
    rules = [Path(env.paths.root) / LEGACY_RULES]
    rules += [Path(p) for p in _EXEC_FILE.findall(unit_text)]
    rules = [p for p in dict.fromkeys(rules) if p.is_file()]
    table = loaded(env, LEGACY_TABLE) if env.binary("nft") else None
    if not unit_text and not rules and table is None:
        return None
    if table is None and rules:
        table = parse_text("\n".join(p.read_text() for p in rules))
    return Legacy(unit if unit_text else None, rules, table, _EXEC_STOP.findall(unit_text))


def _listeners(env: Any) -> list[ha_listener.HAListener]:
    out: list[ha_listener.HAListener] = []
    for engine in ("kea4", "kea6"):
        daemon = keasetup.DAEMONS[engine]
        conf = env.paths.kea_conf(daemon)
        try:
            config = keaconf.loads(conf.read_text(), str(conf))
        except (OSError, keaconf.KeaConfigError):
            continue
        out += [x for x in ha_listener.listeners(engine, config, env.t.kea_version(daemon)) if not x.local]
    return out


def _watch_seconds(listeners: list[ha_listener.HAListener]) -> float:
    beat = max((x.heartbeat_ms for x in listeners), default=10000)
    return min(30.0, max(5.0, 2.5 * beat / 1000))


def status(env: Any) -> dict[str, Any]:
    """Everything the UI shows about the guard of this node."""
    from pelagos.installer import drift

    lst = _listeners(env)
    rec = ledger.get(env, KEY)
    nft = env.binary("nft") is not None
    mine = loaded(env, ha_listener.GUARD_TABLE) if nft else None
    leg = legacy(env)
    state = (rec or {}).get("state") or {}
    return {
        "nft": nft,
        "listeners": [
            {"engine": x.engine, "server": x.server, "address": x.address, "port": x.port, "peers": x.peers}
            for x in lst
        ],
        "suggested_peers": _safe_peers(sorted({p for x in lst for p in x.peers})),
        "ports": sorted({x.port for x in lst}),
        "managed": {
            "table": f"inet {ha_listener.GUARD_TABLE}",
            "unit": ha_listener.GUARD_UNIT,
            "file": str(rules_path(env)),
            "peers": list(state.get("peers") or []),
            "ports": list(state.get("ports") or []),
            "recorded_at": rec.get("recorded_at"),
            "adopted_from": state.get("adopted_from"),
            "active": env.services.is_active(ha_listener.GUARD_UNIT),
        }
        if rec
        else None,
        "loaded": {"peers": mine.peers, "ports": mine.ports} if mine else None,
        "legacy": {
            "table": f"inet {LEGACY_TABLE}",
            "unit": str(leg.unit) if leg.unit else None,
            "files": [str(p) for p in leg.rules],
            "peers": leg.table.peers if leg.table else [],
            "ports": leg.table.ports if leg.table else [],
        }
        if leg
        else None,
        "differences": drift.guard_differences(env, rec) if rec else [],
    }


# Loading -----------------------------------------------------------------------------------------


def _write(path: Path, text: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text)
    tmp.chmod(mode)
    tmp.replace(path)


def _put_back(env: Any, nft: str, before: dict[Path, str | None]) -> None:
    """The guard as it was before: its previous files reloaded, or no Pelagos guard at all."""
    rules = rules_path(env)
    if before.get(rules) is None:
        env.services.disable_now(ha_listener.GUARD_UNIT)
        drop = [nft, "delete", "table", "inet", ha_listener.GUARD_TABLE]
        env.runner.run(drop, privileged=True, check=False)
    for path, old in before.items():
        if old is None:
            path.unlink(missing_ok=True)
        else:
            _write(path, old, 0o640 if path == rules else 0o644)
    env.services.daemon_reload()
    if before.get(rules) is not None:
        env.services.restart(ha_listener.GUARD_UNIT)


def install(
    env: Any, ports: list[int], peers: list[str], watch: float | None, adopted_from: dict | None = None
) -> str:
    """Writes and loads Pelagos's guard; with `watch`, put back as it was if only drops grow."""
    nft = env.binary("nft")
    if nft is None:
        raise RuntimeError("nft not found: install nftables first")
    if not ports or not peers:
        raise RuntimeError("the guard needs at least one port and one peer address")
    rules, unit = rules_path(env), unit_path(env)
    text = ha_listener.render_guard(ports, peers)
    unit_text = ha_listener.render_unit(nft, rules)
    if env.dry_run:
        return f"dry run: would load {rules} through {ha_listener.GUARD_UNIT}"
    before = {p: (p.read_text() if p.exists() else None) for p in (rules, unit)}
    _write(rules, text, 0o640)
    _write(unit, unit_text, 0o644)
    env.services.daemon_reload()
    env.services.enable_now(ha_listener.GUARD_UNIT)
    env.services.restart(ha_listener.GUARD_UNIT)
    note = ""
    if watch:
        seen = ha_listener.watch_peers(env, watch, _sleep)
        if seen == "blocked":
            _put_back(env, nft, before)
            raise RuntimeError(
                f"packets to port(s) {ports} were dropped and none came from {', '.join(peers)} within "
                f"{watch:.0f}s: previous guard put back"
            )
        note = " (peer traffic seen through it)" if seen == "peers" else " (no HA traffic, nothing dropped)"
    state = {"table": ha_listener.GUARD_TABLE, "unit": ha_listener.GUARD_UNIT, "file": str(rules)}
    state.update(ports=sorted(set(ports)), peers=list(peers))
    if adopted_from:
        state["adopted_from"] = adopted_from
    elif (old := ledger.get(env, KEY)) and (old.get("state") or {}).get("adopted_from"):
        state["adopted_from"] = old["state"]["adopted_from"]
    ledger.record(env, KEY, "ha_guard", state, {rules: text, unit: unit_text})
    return f"{ha_listener.GUARD_UNIT}: only {', '.join(peers)} reach port(s) {sorted(set(ports))}{note}"


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _guard_ports(env: Any, extra: list[int] | None = None) -> list[int]:
    ports = {x.port for x in _listeners(env)} | set(extra or [])
    rec = ledger.get(env, KEY)
    ports |= set(((rec or {}).get("state") or {}).get("ports") or [])
    return sorted(ports)


# Adoption ----------------------------------------------------------------------------------------


def _systemctl(env: Any, *args: str) -> None:
    tool = env.binary("systemctl")
    if tool:
        env.runner.run([tool, *args], privileged=True, check=False)


def adopt(env: Any) -> str:
    """Takes over the hand-made guard: Pelagos's table with the same addresses first, then the old
    unit, table and files go (kept in the backup directory); any failure restores the old guard."""
    leg = legacy(env)
    if leg is None:
        if ledger.get(env, KEY):
            return "no hand-made guard left: already adopted"
        raise RuntimeError(f"no guard named {LEGACY_TABLE} or {LEGACY_UNIT} on this node")
    nft = env.binary("nft")
    if nft is None:
        raise RuntimeError("nft not found")
    old = leg.table or TableState(LEGACY_TABLE)
    peers = list(old.peers)
    mine = loaded(env, ha_listener.GUARD_TABLE)
    if mine is not None:
        # Both guards filter today: only the addresses both admit get through.
        peers = [p for p in peers if p in mine.peers]
    if not peers:
        raise RuntimeError(f"the hand-made guard admits no peer address that can be kept: {leg.source}")
    ports = sorted(set(old.ports) | set(_guard_ports(env)))
    if env.dry_run:
        return f"dry run: would load {', '.join(peers)} into {ha_listener.GUARD_TABLE}, retire {leg.source}"
    backup = Path(env.backup_root) / f"ha-guard-adopt-{time.strftime('%Y%m%dT%H%M%S')}"
    backup.mkdir(parents=True, exist_ok=True)
    saved = [p for p in ([leg.unit] if leg.unit else []) + leg.rules]
    for p in saved:
        shutil.copy2(p, backup / p.name)
    before = {p: (p.read_text() if p.exists() else None) for p in (rules_path(env), unit_path(env))}
    origin = {
        "table": LEGACY_TABLE,
        "unit": str(leg.unit) if leg.unit else None,
        "files": [str(p) for p in leg.rules],
        "backup": str(backup),
    }
    out = [install(env, ports, peers, None, adopted_from=origin)]
    try:
        now = loaded(env, ha_listener.GUARD_TABLE)
        if now is None or not set(peers) <= set(now.peers) or not set(old.ports) <= set(now.ports):
            raise RuntimeError(f"{ha_listener.GUARD_TABLE} did not load with {', '.join(peers)}")
        if leg.unit is not None:
            # Stopping runs ExecStop: only when it removes nothing but the old table.
            safe = all(f"delete table inet {LEGACY_TABLE}" in s for s in leg.exec_stop)
            if safe:
                env.services.disable_now(LEGACY_UNIT)
            else:
                _systemctl(env, "disable", LEGACY_UNIT)
        env.runner.run([nft, "delete", "table", "inet", LEGACY_TABLE], privileged=True, check=False)
        for p in saved:
            p.unlink(missing_ok=True)
        env.services.daemon_reload()
        if loaded(env, LEGACY_TABLE) is not None:
            raise RuntimeError(f"table inet {LEGACY_TABLE} is still loaded")
    except Exception:
        for p in saved:
            _write(p, (backup / p.name).read_text(), 0o644 if p == leg.unit else 0o640)
        env.services.daemon_reload()
        if leg.unit is not None:
            env.services.enable_now(LEGACY_UNIT)
            if loaded(env, LEGACY_TABLE) is None:
                env.services.restart(LEGACY_UNIT)
        elif leg.rules and loaded(env, LEGACY_TABLE) is None:
            env.runner.run([nft, "-f", str(leg.rules[0])], privileged=True, check=False)
        _put_back(env, nft, before)
        ledger.update(env, {KEY: None})
        raise
    out.append(f"{leg.source} retired (copies in {backup})")
    return "\n".join(out)


# Plans -------------------------------------------------------------------------------------------


def build_plan(env: Any, peers: Any, created_by: str = "") -> Plan:
    """A security plan that loads Pelagos's guard with `peers` (the HA peers and backups allowed)."""
    peers = normalize_peers(peers)
    if env.binary("nft") is None:
        raise ValueError("nft is not installed on this node")
    if legacy(env) is not None:
        raise ValueError("a guard set up by hand is still in place: adopt it first (kea_ha_guard_unmanaged)")
    ports = _guard_ports(env)
    if not ports:
        raise ValueError("no Kea HA listener off loopback on this node")
    rec = ledger.get(env, KEY)
    old = list(((rec or {}).get("state") or {}).get("peers") or [])
    summary = msg("plan.ha_guard.set", peers=join(peers, ", "), ports=join([str(p) for p in ports], ", "))
    diff = "".join(f"- {p}\n" for p in old if p not in peers)
    diff += "".join(f"+ {p}\n" for p in peers if p not in old)
    change = Change(
        ChangeOp.REPLACE if rec else ChangeOp.ADD,
        "security/ha-guard",
        before={"peers": old, "ports": list(((rec or {}).get("state") or {}).get("ports") or [])},
        after={
            "details": {"remediation": "ha_guard_set", "peers": peers, "ports": ports},
            "summary": messages.render(summary),
        },
        node_ids=[env.node_id],
    )
    return Plan(
        scope=PlanScope.SECURITY,
        node_id=env.node_id,
        summary=messages.render(summary),
        summary_message=summary,
        created_by=created_by,
        changes=[change],
        diff=diff or "(same addresses: the guard is loaded again)\n",
        target_node_ids=[env.node_id],
        requires_confirmation=True,
        state=PlanState.VALIDATED,
    )


def remediate_set(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    peers = normalize_peers(d.get("peers"))
    ports = sorted({int(p) for p in d.get("ports") or [] if 0 < int(p) < 65536})
    return install(env, ports, peers, _watch_seconds(_listeners(env)))


def remediate_adopt(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    return adopt(env)


# Audit -------------------------------------------------------------------------------------------


def findings(env: Any) -> list[Any]:
    """kea_ha_guard_unmanaged: a hand-made guard Pelagos can take over."""
    from pelagos.domain import Severity
    from pelagos.installer.security_audit import Finding, finding_id

    leg = legacy(env)
    if leg is None:
        return []
    peers = leg.table.peers if leg.table else []
    ports = leg.table.ports if leg.table else []
    params = {
        "source": leg.source,
        "peers": join(peers or ["?"], ", "),
        "ports": join([str(p) for p in ports] or ["?"], ", "),
    }
    nft = env.binary("nft") is not None
    return [
        Finding.of(
            finding_id("kea", "kea_ha_guard_unmanaged", LEGACY_TABLE),
            "kea_ha_guard_unmanaged",
            Severity.INFO,
            "kea",
            leg.source,
            msg("finding.kea_ha_guard_unmanaged.description", **params),
            msg("finding.kea_ha_guard_unmanaged.proposal", **params),
            msg("finding.kea_ha_guard_unmanaged.risk"),
            {
                "remediation": "ha_guard_adopt",
                "remediable": nft and bool(peers),
                "peers": peers,
                "ports": ports,
                "unit": str(leg.unit) if leg.unit else None,
                "files": [str(p) for p in leg.rules],
            },
        )
    ]
