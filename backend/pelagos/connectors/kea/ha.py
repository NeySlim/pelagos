# SPDX-License-Identifier: Apache-2.0
"""High availability: HAState from status-get and the maintenance commands of the ha hook."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

from pelagos.domain import Family, HAMode, HAPartner, HAPeer, HAState, to_rfc3339, utcnow

# States in which a server does what its role expects (the pair serving, a backup receiving).
NORMAL_STATES = frozenset({"hot-standby", "load-balancing", "passive-backup", "backup"})
MAINTENANCE_COMMANDS = {"start": "ha-maintenance-start", "cancel": "ha-maintenance-cancel"}
# States in which a peer serves what its mode expects; anything else is degraded (section 15).
HEALTHY_STATES = {
    HAMode.HOT_STANDBY: {"hot-standby"},
    HAMode.LOAD_BALANCING: {"load-balancing"},
    HAMode.PASSIVE_BACKUP: {"passive-backup", "backup"},
}


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return int(value)


def _bool_or_none(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def partner_lost(partner: HAPartner | None) -> bool:
    """The partner is out of reach: never in touch, or in touch once and now silent for longer
    than max-response-delay (status-get `communication-interrupted`)."""
    return partner is not None and (partner.in_touch is False or partner.communication_interrupted is True)


def _state_of_entry(node_id: str, family: Family, entry: dict[str, Any]) -> HAState:
    servers = entry.get("ha-servers") or {}
    local = servers.get("local") or {}
    remote = servers.get("remote")
    mode_raw = entry.get("ha-mode")
    try:
        mode = HAMode(mode_raw) if mode_raw else None
    except ValueError:
        mode = None
    partner = None
    if remote:
        partner = HAPartner(
            role=remote.get("role"),
            server_name=remote.get("server-name") or None,
            state=remote.get("last-state") or None,
            scopes=[str(s) for s in remote.get("last-scopes") or []],
            in_touch=remote.get("in-touch"),
            communication_interrupted=_bool_or_none(remote.get("communication-interrupted")),
            last_state=remote.get("last-state") or None,
            age=remote.get("age"),
            connecting_clients=remote.get("connecting-clients"),
            unacked_clients=remote.get("unacked-clients"),
            unacked_clients_left=remote.get("unacked-clients-left"),
            analyzed_packets=remote.get("analyzed-packets"),
            clock_skew=_int_or_none(remote.get("clock-skew")),
        )
    return HAState(
        node_id=node_id,
        family=family,
        collected_at=utcnow(),
        server_name=local.get("server-name"),
        mode=mode,
        role=local.get("role"),
        state=local.get("state"),
        scopes=[str(s) for s in local.get("scopes") or []],
        unsent_update_count=local.get("unsent-update-count"),
        partner=partner,
        enabled=True,
        raw=dict(entry),
    )


def ha_state_from_status(node_id: str, family: Family, status: dict[str, Any]) -> HAState:
    """status-get -> arguments.high-availability: the first relationship, the others (Kea 3 hub and
    spoke) in `other_relationships`; `enabled` is False when the hook is not loaded."""
    entries = [e for e in status.get("high-availability") or [] if isinstance(e, dict)]
    if not entries:
        return HAState(node_id=node_id, family=family, collected_at=utcnow(), enabled=False, raw={})
    first = _state_of_entry(node_id, family, entries[0])
    first.other_relationships = [_state_of_entry(node_id, family, e) for e in entries[1:]]
    return first


def flatten(states: list[HAState]) -> list[HAState]:
    """One HAState per relationship a server belongs to: a hub's other relationships follow it."""
    out: list[HAState] = []
    for st in states:
        out.append(st)
        out.extend(o for o in st.other_relationships if o.enabled)
    return out


def is_healthy(state: HAState) -> bool:
    if not state.enabled or state.mode is None:
        return True
    return (state.state or "") in HEALTHY_STATES[state.mode]


def ha_serving(state: HAState) -> bool:
    """The relationship is back: this server in a normal state and its partner in touch in one
    (a backup, which has no partner, only needs its own state)."""
    if (state.state or "") not in NORMAL_STATES:
        return False
    partner = state.partner
    if partner is None:
        return True
    return not partner_lost(partner) and (partner.state or "") in NORMAL_STATES


def ha_configured(cfg: dict[str, Any]) -> bool:
    """True when the ha hook is in hooks-libraries of a Dhcp4/Dhcp6 object."""
    return any("libdhcp_ha" in str(h.get("library", "")) for h in cfg.get("hooks-libraries") or [])


def kea_time(answer: dict[str, Any]) -> datetime | None:
    """`date-time` of an ha-heartbeat answer (RFC 1123, whole seconds, the server's own clock)."""
    raw = answer.get("date-time")
    if not isinstance(raw, str):
        return None
    try:
        value = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return None
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def heartbeat_window(
    age: Any, sent_at: datetime, received_at: datetime, kea_now: datetime | None = None
) -> dict[str, Any] | None:
    """Bounds of the partner's last heartbeat from one status-get exchange.

    Kea reports `age` in whole seconds, truncated: the beat happened in (T - age - 1, T - age] where
    T, the instant status-get ran, lies between the request and the answer. ha-heartbeat, sent right
    after, carries Kea's clock in whole seconds: T < kea_now + 1 narrows the upper bound.
    """
    if not isinstance(age, int) or isinstance(age, bool) or age < 0:
        return None
    upper = received_at
    if kea_now is not None:
        upper = max(sent_at, min(upper, kea_now + timedelta(seconds=1)))
    lo = sent_at - timedelta(seconds=age + 1)
    hi = upper - timedelta(seconds=age)
    return {
        "lo": to_rfc3339(lo),
        "hi": to_rfc3339(hi),
        "age": age,
        "sent_at": to_rfc3339(sent_at),
        "received_at": to_rfc3339(received_at),
        "kea_time": to_rfc3339(kea_now) if kea_now is not None else None,
    }


# Kea ARM (2.6 and 3.x), "high-availability" peers: the roles each mode accepts, with their counts.
# A backup server takes lease updates from the active servers and is promoted by hand.
ROLES = ("primary", "secondary", "standby", "backup")
MODE_ROLES: dict[str, dict[str, tuple[int, int | None]]] = {
    "hot-standby": {"primary": (1, 1), "standby": (1, 1), "backup": (0, None)},
    "load-balancing": {"primary": (1, 1), "secondary": (1, 1), "backup": (0, None)},
    "passive-backup": {"primary": (1, 1), "backup": (1, None)},
}
# ha hook parameters the setup accepts (snake_case in the API, dashed in Kea).
TUNABLES = (
    "heartbeat_delay",
    "max_response_delay",
    "max_ack_delay",
    "max_unacked_clients",
    "max_rejected_lease_updates",
    "delayed_updates_limit",
    "sync_leases",
    "sync_timeout",
    "sync_page_limit",
    "send_lease_updates",
    "wait_backup_ack",
)
BOOL_TUNABLES = frozenset({"sync_leases", "send_lease_updates", "wait_backup_ack"})
# Roles that take part in heartbeats and failover; a backup only receives lease updates.
ACTIVE_ROLES = frozenset({"primary", "secondary", "standby"})


def ha_hook_entries(cfg: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Every `high-availability` relationship of a Dhcp4/Dhcp6 object, None without the hook."""
    for lib in cfg.get("hooks-libraries") or []:
        if isinstance(lib, dict) and "libdhcp_ha" in str(lib.get("library", "")):
            entries = (lib.get("parameters") or {}).get("high-availability") or []
            return [e for e in entries if isinstance(e, dict)]
    return None


def ha_hook(cfg: dict[str, Any]) -> dict[str, Any] | None:
    """The first `high-availability` relationship of a Dhcp4/Dhcp6 object, None without the hook."""
    entries = ha_hook_entries(cfg)
    if entries is None:
        return None
    return entries[0] if entries else {}


def ha_peers_from_config(cfg: dict[str, Any], server_name: str | None = None) -> list[HAPeer]:
    """The `peers` list of the relationship this server takes part in as `server_name` (the first
    relationship when None or not found), in configuration order."""
    entries = ha_hook_entries(cfg) or []
    entry = next((e for e in entries if server_name and e.get("this-server-name") == server_name), None)
    if entry is None:
        entry = entries[0] if entries else {}
    out: list[HAPeer] = []
    for p in entry.get("peers") or []:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        failover = p.get("auto-failover")
        out.append(
            HAPeer(
                name=str(p["name"]),
                role=str(p.get("role") or ""),
                url=str(p["url"]) if p.get("url") else None,
                auto_failover=failover if isinstance(failover, bool) else None,
            )
        )
    return out


def partner_name(state: HAState) -> str | None:
    """The server this one exchanges heartbeats with: status-get's remote, else the other active
    server of the configured peers. A backup has none."""
    if state.partner is not None and state.partner.server_name:
        return state.partner.server_name
    if state.role == "backup":
        return None
    for p in state.peers:
        if p.name != state.server_name and p.role in ACTIVE_ROLES:
            return p.name
    return None


def validate_setup(spec: dict[str, Any]) -> list[tuple[str, str]]:
    """(field, message) problems of an HA setup body; empty when Kea would take it."""
    mode = spec.get("mode")
    if mode not in MODE_ROLES:
        return [("mode", "hot-standby, load-balancing or passive-backup")]
    servers = spec.get("servers")
    if not isinstance(servers, list) or len(servers) < 2:
        return [("servers", "at least two servers")]
    problems: list[tuple[str, str]] = []
    names: set[str] = set()
    urls: set[str] = set()
    counts: dict[str, int] = {}
    for i, s in enumerate(servers):
        if not isinstance(s, dict):
            problems.append((f"servers[{i}]", "object expected"))
            continue
        name = str(s.get("name") or "").strip()
        url = str(s.get("url") or "").strip()
        role = s.get("role")
        if not name or any(c.isspace() for c in name):
            problems.append((f"servers[{i}].name", "a name without spaces"))
        elif name in names:
            problems.append((f"servers[{i}].name", "duplicate name"))
        names.add(name)
        if not url.startswith(("http://", "https://")) or not url.split("://", 1)[1].strip("/"):
            problems.append((f"servers[{i}].url", "http://address:port/ or https://address:port/"))
        elif url in urls:
            problems.append((f"servers[{i}].url", "duplicate url"))
        urls.add(url)
        failover = s.get("auto_failover")
        if failover is not None and not isinstance(failover, bool):
            problems.append((f"servers[{i}].auto_failover", "boolean expected"))
        if role not in MODE_ROLES[mode]:
            problems.append((f"servers[{i}].role", f"{mode} takes {', '.join(MODE_ROLES[mode])}"))
            continue
        counts[role] = counts.get(role, 0) + 1
    for role, (low, high) in MODE_ROLES[mode].items():
        n = counts.get(role, 0)
        if n < low or (high is not None and n > high):
            want = str(low) if high == low else f"at least {low}"
            problems.append(("servers", f"{mode} needs {want} {role} server(s), got {n}"))
    for key in TUNABLES:
        value = spec.get(key)
        if value is None:
            continue
        if key in BOOL_TUNABLES:
            if not isinstance(value, bool):
                problems.append((key, "boolean expected"))
        elif not isinstance(value, int) or isinstance(value, bool) or value < 0:
            problems.append((key, "a non-negative integer"))
    return problems


def setup_relationships(body: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    """The relationships of a setup body ({"relationships": [...]} or one relationship) and the
    field prefix of their problems."""
    if "relationships" in body:
        rels = body.get("relationships")
        return (rels if isinstance(rels, list) else []), "relationships"
    return [body], ""


def validate_relationships(body: dict[str, Any]) -> list[tuple[str, str]]:
    """(field, message) problems of a setup with one or several relationships (Kea 3 hub and spoke):
    each relationship on its own, then server names and URLs unique across all of them (a hub
    listens on its own URL in each relationship) and one server per node in a relationship."""
    rels, prefix = setup_relationships(body)
    if prefix and (not rels or not all(isinstance(r, dict) for r in rels)):
        return [("relationships", "a list of relationships, each with mode and servers")]
    problems: list[tuple[str, str]] = []
    names: set[str] = set()
    urls: set[str] = set()
    for i, rel in enumerate(rels):
        at = f"{prefix}[{i}]." if prefix else ""
        problems.extend((f"{at}{f}", m) for f, m in validate_setup(rel))
        nodes: set[str] = set()
        for j, srv in enumerate(rel.get("servers") or []):
            if not isinstance(srv, dict):
                continue
            name = str(srv.get("name") or "").strip()
            url = str(srv.get("url") or "").strip().rstrip("/")
            if len(rels) > 1 and name and name in names:
                problems.append((f"{at}servers[{j}].name", "a server name is used in one relationship only"))
            if len(rels) > 1 and url and url in urls:
                problems.append((f"{at}servers[{j}].url", "each relationship needs its own url"))
            names.add(name)
            urls.add(url)
            node = srv.get("node_id")
            if node:
                if node in nodes:
                    problems.append(
                        (f"{at}servers[{j}].node_id", "a node runs one server of the relationship")
                    )
                nodes.add(str(node))
    return problems


def relationship_entry(spec: dict[str, Any], this_server: str) -> dict[str, Any]:
    """The `high-availability[0]` object of one server: the same peers everywhere, its own name."""
    entry: dict[str, Any] = {"this-server-name": this_server, "mode": spec["mode"]}
    for key in TUNABLES:
        if spec.get(key) is not None:
            entry[key.replace("_", "-")] = spec[key]
    peers = []
    for s in spec["servers"]:
        peer: dict[str, Any] = {
            "name": str(s["name"]).strip(),
            "url": str(s["url"]).strip(),
            "role": s["role"],
        }
        if isinstance(s.get("auto_failover"), bool):
            peer["auto-failover"] = s["auto_failover"]
        peers.append(peer)
    entry["peers"] = peers
    return entry


def _ha_tag(obj: Any) -> str | None:
    ctx = obj.get("user-context") if isinstance(obj, dict) else None
    name = ctx.get("ha-server-name") if isinstance(ctx, dict) else None
    return str(name) if name else None


def untagged_subnets(body: dict[str, Any]) -> list[str]:
    """Subnets of a Dhcp4/Dhcp6 body with no `user-context.ha-server-name`, on themselves or their
    shared network: a hub serves them in every relationship."""
    out: list[str] = []
    for key in ("subnet4", "subnet6"):
        out += [str(s.get("subnet")) for s in body.get(key) or [] if isinstance(s, dict) and not _ha_tag(s)]
    for net in body.get("shared-networks") or []:
        if not isinstance(net, dict) or _ha_tag(net):
            continue
        for key in ("subnet4", "subnet6"):
            out += [
                str(s.get("subnet")) for s in net.get(key) or [] if isinstance(s, dict) and not _ha_tag(s)
            ]
    return out


def hub_subnets_warning(body: dict[str, Any], names: list[str]) -> str | None:
    """The warning a hub plan carries while some of its subnets name no relationship."""
    untagged = untagged_subnets(body)
    if not untagged:
        return None
    shown = ", ".join(untagged[:10]) + (f" and {len(untagged) - 10} more" if len(untagged) > 10 else "")
    return (
        f"warning: {len(untagged)} subnet(s) set no user-context.ha-server-name ({shown}): this hub"
        f" serves them in each of its relationships ({', '.join(names)}), and the shared configuration"
        " check expects them on every spoke. Set ha-server-name to the hub's name in the"
        " relationship each subnet belongs to."
    )


def hooks_dir_of(hooks: list[dict[str, Any]]) -> str | None:
    """Directory of the loaded hook libraries (lease_cmds first), None when none is loaded."""
    paths = [str(h.get("library", "")) for h in hooks if isinstance(h, dict) and h.get("library")]
    paths.sort(key=lambda p: "libdhcp_lease_cmds" not in p)
    for path in paths:
        if "/" in path:
            return path.rsplit("/", 1)[0]
    return None


def hooks_with_ha(
    hooks: list[dict[str, Any]],
    entries: dict[str, Any] | list[dict[str, Any]] | None,
    hooks_dir: str | None,
) -> list[dict[str, Any]]:
    """hooks-libraries with the ha hook set to `entries` (one relationship or several; None removes
    it); lease_cmds is loaded before it, as the ha hook requires. Other libraries and their order
    are kept."""
    previous = next((h for h in hooks if "libdhcp_ha" in str(h.get("library", ""))), None)
    out = [dict(h) for h in hooks if "libdhcp_ha" not in str(h.get("library", ""))]
    if entries is None:
        return out
    wanted = [entries] if isinstance(entries, dict) else list(entries)

    def located(name: str) -> str:
        if hooks_dir is None:
            raise ValueError("the hooks directory is unknown: no hook library is loaded to locate it")
        return f"{hooks_dir.rstrip('/')}/{name}"

    if not any("libdhcp_lease_cmds" in str(h.get("library", "")) for h in out):
        out.append({"library": located("libdhcp_lease_cmds.so")})
    library = str(previous["library"]) if previous else located("libdhcp_ha.so")
    params: dict[str, Any] = {}
    olds: list[dict[str, Any]] = []
    if previous is not None:
        params = dict(previous.get("parameters") or {})
        olds = [e for e in params.get("high-availability") or [] if isinstance(e, dict)]
    merged_entries = []
    for i, entry in enumerate(wanted):
        # Keys the setup does not manage (multi-threading, TLS files, ...) are kept, per peer too:
        # from the relationship this server had under the same name, else the one at the same place.
        old = next((o for o in olds if o.get("this-server-name") == entry.get("this-server-name")), None)
        if old is None and i < len(olds) and len(olds) == len(wanted):
            old = olds[i]
        if old is None and len(wanted) == 1 and olds:
            old = olds[0]
        if old is not None:
            old_peers = {p.get("name"): p for p in old.get("peers") or [] if isinstance(p, dict)}
            merged = {k: v for k, v in old.items() if k != "peers"}
            merged.update(entry)
            merged["peers"] = [
                {**{k: v for k, v in old_peers.get(p["name"], {}).items() if k not in ("role", "url")}, **p}
                for p in entry["peers"]
            ]
            entry = merged
        merged_entries.append(entry)
    params["high-availability"] = merged_entries
    out.append({"library": library, "parameters": params})
    return out


def relationships(states: list[HAState], node_names: dict[str, str]) -> list[dict[str, Any]]:
    """Every HA relationship seen across the nodes: each configured server with its role, the node
    that runs it (None when no Pelagos node does) and its state as that node, or its partner,
    reports it. Servers are grouped by the configured peers list."""
    groups: dict[tuple[str, ...], list[HAState]] = {}
    for st in flatten(states):
        if not st.enabled:
            continue
        key = tuple(sorted(p.name for p in st.peers)) or (st.server_name or st.node_id,)
        groups.setdefault(key, []).append(st)
    out = []
    for members in groups.values():
        by_name = {m.server_name: m for m in members if m.server_name}
        peers = next((m.peers for m in members if m.peers), None) or [
            HAPeer(name=m.server_name or m.node_id, role=m.role or "") for m in members
        ]
        servers = []
        for p in peers:
            own = by_name.get(p.name)
            seen_by = next(
                (m for m in members if m.partner is not None and m.partner.server_name == p.name), None
            )
            remote = seen_by.partner if seen_by is not None else None
            servers.append(
                {
                    "name": p.name,
                    "role": p.role,
                    "url": p.url,
                    "auto_failover": p.auto_failover,
                    "node_id": own.node_id if own else None,
                    "node_name": node_names.get(own.node_id) if own else None,
                    "state": own.state if own else (remote.state if remote else None),
                    "scopes": list(own.scopes) if own else [],
                    "unsent_update_count": own.unsent_update_count if own else None,
                    "partner": partner_name(own) if own else None,
                    "in_touch": remote.in_touch if remote else None,
                    "communication_interrupted": remote.communication_interrupted if remote else None,
                    "collected_at": to_rfc3339(own.collected_at) if own else None,
                    "managed": own is not None,
                }
            )
        out.append(
            {
                "family": members[0].family.value,
                "mode": next((m.mode.value for m in members if m.mode), None),
                "servers": servers,
                "active": [s["name"] for s in servers if s["role"] in ACTIVE_ROLES],
                "backups": [s["name"] for s in servers if s["role"] == "backup"],
            }
        )
    return out
