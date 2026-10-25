# SPDX-License-Identifier: Apache-2.0
"""What must be equal across the servers of a Kea HA relationship, hashed for config_divergence.

Only what the servers hand out to clients and the relationship itself are compared: subnets and
shared networks (pools, reservations, options, lifetimes, classes they name), global reservations,
options, option definitions and client classes, and the relationship's mode and peers. Per-server
keys (this-server-name, interfaces, sockets, loggers, lease database, hooks paths, multi-threading,
ddns settings, timers of the HA hook) and the defaults a Kea version adds are left out, so a pair
on Kea 2.6 and a backup on Kea 3.0 hash alike when they serve the same thing.

With several relationships on one server (Kea 3 hub and spoke), a subnet belongs to the
relationship named by its `user-context.ha-server-name`; untagged ones count in each of them.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

OPTION_KEYS = ("code", "name", "space", "data", "csv-format", "always-send", "never-send")
# Values Kea fills in when the option does not set them.
OPTION_DEFAULTS = {"csv-format": True, "always-send": False, "never-send": False}
CLASS_LISTS = ("client-class", "client-classes", "require-client-classes", "evaluate-additional-classes")
POOL_KEYS = ("pool", "option-data", *CLASS_LISTS)
PD_POOL_KEYS = (
    "prefix",
    "prefix-len",
    "delegated-len",
    "excluded-prefix",
    "excluded-prefix-len",
    "option-data",
    *CLASS_LISTS,
)
RESERVATION_KEYS = (
    "hw-address",
    "duid",
    "client-id",
    "circuit-id",
    "flex-id",
    "ip-address",
    "ip-addresses",
    "prefixes",
    "excluded-prefixes",
    "hostname",
    "option-data",
    "client-classes",
    "next-server",
    "server-hostname",
    "boot-file-name",
)
LIFETIMES = ("valid-lifetime", "preferred-lifetime", "renew-timer", "rebind-timer")
SUBNET_KEYS = (
    "id",
    "subnet",
    "pools",
    "pd-pools",
    "reservations",
    "option-data",
    "relay",
    "next-server",
    "server-hostname",
    "boot-file-name",
    "rapid-commit",
    *LIFETIMES,
    *CLASS_LISTS,
)
NETWORK_KEYS = ("name", "option-data", "relay", "rapid-commit", *LIFETIMES, *CLASS_LISTS)
CLASS_KEYS = (
    "name",
    "test",
    "template-test",
    "option-data",
    "option-def",
    "only-if-required",
    "only-in-additional-list",
    "next-server",
    "server-hostname",
    "boot-file-name",
    *LIFETIMES,
)
OPTION_DEF_KEYS = ("name", "code", "space", "type", "array", "record-types", "encapsulate")
EMPTY = (None, "", "0.0.0.0", "::")  # noqa: S104 (Kea unset addresses, not a bind)


def _empty(value: Any) -> bool:
    return value in EMPTY or value == [] or value == {} or value is False


def _pick(obj: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(obj, dict):
        return {}
    return {k: obj[k] for k in keys if k in obj and not _empty(obj[k])}


def _options(items: Any) -> list[dict[str, Any]]:
    out = []
    for item in items if isinstance(items, list) else []:
        opt = {k: item[k] for k in OPTION_KEYS if isinstance(item, dict) and k in item}
        for key, default in OPTION_DEFAULTS.items():
            if opt.get(key) == default:
                opt.pop(key)
        if "code" in opt:
            opt.pop("name", None)  # Kea answers both; a file may give either
        opt.setdefault("space", "")
        if isinstance(opt.get("data"), str):
            opt["data"] = ",".join(part.strip() for part in opt["data"].split(","))
        out.append({k: v for k, v in opt.items() if v not in (None, "") or k == "data"})
    return sorted(out, key=lambda o: json.dumps(o, sort_keys=True))


def _classes(value: Any) -> Any:
    if isinstance(value, str):
        return [value] if value else []
    return list(value) if isinstance(value, list) else value


def _with_options(obj: dict[str, Any]) -> dict[str, Any]:
    if "option-data" in obj:
        obj["option-data"] = _options(obj["option-data"])
        if not obj["option-data"]:
            obj.pop("option-data")
    for key in CLASS_LISTS:
        if key in obj:
            obj[key] = _classes(obj[key])
    return obj


def _reservations(items: Any) -> list[dict[str, Any]]:
    out = []
    for item in items if isinstance(items, list) else []:
        r = _with_options(_pick(item, RESERVATION_KEYS))
        for key in ("hw-address", "duid", "client-id"):
            if isinstance(r.get(key), str):
                r[key] = r[key].lower()
        out.append(r)
    return sorted(out, key=lambda o: json.dumps(o, sort_keys=True))


def _subnet(subnet: dict[str, Any]) -> dict[str, Any]:
    s = _with_options(_pick(subnet, SUBNET_KEYS))
    if "pools" in s:
        pools = [_with_options(_pick(p, POOL_KEYS)) for p in s["pools"]]
        for p in pools:
            if isinstance(p.get("pool"), str):
                p["pool"] = "".join(p["pool"].split())
        s["pools"] = sorted(pools, key=lambda o: json.dumps(o, sort_keys=True))
    if "pd-pools" in s:
        s["pd-pools"] = sorted(
            (_with_options(_pick(p, PD_POOL_KEYS)) for p in s["pd-pools"]),
            key=lambda o: json.dumps(o, sort_keys=True),
        )
    if "reservations" in s:
        s["reservations"] = _reservations(s["reservations"])
    if "relay" in s:
        s["relay"] = _pick(s["relay"], ("ip-address", "ip-addresses")) or None
        if s["relay"] is None:
            s.pop("relay")
    return s


def _tag(obj: Any) -> str | None:
    ctx = obj.get("user-context") if isinstance(obj, dict) else None
    name = ctx.get("ha-server-name") if isinstance(ctx, dict) else None
    return str(name) if name else None


def _belongs(obj: Any, names: frozenset[str] | None, inherited: str | None = None) -> bool:
    if names is None:
        return True
    tag = _tag(obj) or inherited
    return tag is None or tag in names


def ha_entries(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Every `high-availability` relationship of a Dhcp4/Dhcp6 body, in configuration order."""
    for lib in body.get("hooks-libraries") or []:
        if isinstance(lib, dict) and "libdhcp_ha" in str(lib.get("library", "")):
            entries = (lib.get("parameters") or {}).get("high-availability") or []
            return [e for e in entries if isinstance(e, dict)]
    return []


def _relationship(entry: dict[str, Any]) -> dict[str, Any]:
    peers = []
    for p in entry.get("peers") or []:
        if not isinstance(p, dict):
            continue
        failover = p.get("auto-failover")
        peers.append(
            {
                "name": str(p.get("name") or ""),
                "role": str(p.get("role") or ""),
                "url": str(p.get("url") or "").rstrip("/").lower(),
                "auto-failover": failover if isinstance(failover, bool) else True,
            }
        )
    return {"mode": entry.get("mode"), "peers": sorted(peers, key=lambda p: p["name"])}


def shared_view(body: dict[str, Any], names: frozenset[str] | None = None) -> dict[str, Any]:
    """The part of a Dhcp4/Dhcp6 body that HA servers must share; `names` keeps the subnets of
    one relationship (None keeps them all)."""
    view: dict[str, Any] = {
        "option-data": _options(body.get("option-data")),
        "option-def": sorted(
            (_pick(d, OPTION_DEF_KEYS) for d in body.get("option-def") or []),
            key=lambda o: json.dumps(o, sort_keys=True),
        ),
        "client-classes": [_with_options(_pick(c, CLASS_KEYS)) for c in body.get("client-classes") or []],
        "reservations": _reservations(body.get("reservations")),
    }
    for key in ("subnet4", "subnet6"):
        subnets = [_subnet(s) for s in body.get(key) or [] if isinstance(s, dict) and _belongs(s, names)]
        if subnets:
            view[key] = sorted(subnets, key=lambda s: (s.get("id") or 0, str(s.get("subnet"))))
    networks = []
    for net in body.get("shared-networks") or []:
        if not isinstance(net, dict):
            continue
        tag = _tag(net)
        n = _with_options(_pick(net, NETWORK_KEYS))
        for key in ("subnet4", "subnet6"):
            subnets = [
                _subnet(s) for s in net.get(key) or [] if isinstance(s, dict) and _belongs(s, names, tag)
            ]
            if subnets:
                n[key] = sorted(subnets, key=lambda s: (s.get("id") or 0, str(s.get("subnet"))))
        if _belongs(net, names) or any(k in n for k in ("subnet4", "subnet6")):
            networks.append(n)
    if networks:
        view["shared-networks"] = sorted(networks, key=lambda n: str(n.get("name")))
    return view


def _digest(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


def body_of(config: dict[str, Any]) -> dict[str, Any]:
    body = next((config[k] for k in ("Dhcp4", "Dhcp6") if k in config), config)
    return body if isinstance(body, dict) else {}


def shared_hashes(config: dict[str, Any]) -> dict[str, Any]:
    """{"shared": hash of what every server hands out, "relationships": [{"this", "servers",
    "hash"}]}: one entry per relationship this server belongs to, hashing its subnets with the
    relationship's mode and peers. Servers of one relationship publish equal hashes."""
    body = body_of(config)
    entries = ha_entries(body)
    out: dict[str, Any] = {"shared": _digest(shared_view(body)), "relationships": []}
    for entry in entries:
        rel = _relationship(entry)
        names = frozenset(p["name"] for p in rel["peers"])
        scope = None if len(entries) == 1 else names
        out["relationships"].append(
            {
                "this": entry.get("this-server-name"),
                "servers": sorted(names),
                "hash": _digest({"relationship": rel, "config": shared_view(body, scope)}),
            }
        )
    return out


def divergent(payloads: dict[str, dict[str, Any]]) -> tuple[dict[str, str | None], list[dict[str, Any]]]:
    """Nodes whose shared configuration differs from the other servers of their relationship, from
    the `config_hash` payloads of every node ({node: payload}). Relationships are joined when their
    server lists share a name, so a peers list that differs on one server is caught too. Nodes in no
    relationship are compared with each other. Returns ({node: hash}, [{"servers", "hashes"}])."""
    entries: list[tuple[str, frozenset[str], str]] = []
    standalone: dict[str, str] = {}
    for node, payload in payloads.items():
        rels = payload.get("relationships") or []
        if not rels and payload.get("shared"):
            standalone[node] = str(payload["shared"])
        for rel in rels:
            if isinstance(rel, dict) and rel.get("hash"):
                entries.append((node, frozenset(rel.get("servers") or []), str(rel["hash"])))
    # Union of entries whose server lists intersect.
    groups: list[tuple[set[str], list[tuple[str, str]]]] = []
    for node, servers, digest in entries:
        joined = [g for g in groups if g[0] & servers]
        merged: tuple[set[str], list[tuple[str, str]]] = (set(servers), [(node, digest)])
        for g in joined:
            merged[0].update(g[0])
            merged[1].extend(g[1])
            groups.remove(g)
        groups.append(merged)
    hashes: dict[str, str | None] = {}
    details: list[dict[str, Any]] = []
    for servers, members in groups:
        nodes = {n for n, _ in members}
        if len(nodes) > 1 and len({d for _, d in members}) > 1:
            by_node = {n: d for n, d in members}
            hashes.update(by_node)
            details.append({"servers": sorted(servers), "hashes": by_node})
    if len(standalone) > 1 and len(set(standalone.values())) > 1:
        hashes.update(standalone)
        details.append({"servers": [], "hashes": dict(standalone)})
    return hashes, details
