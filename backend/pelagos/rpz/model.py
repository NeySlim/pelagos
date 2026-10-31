# SPDX-License-Identifier: Apache-2.0
"""Subscriptions as the cluster settings describe them: resolved list, zone names, response-policy text.

`settings.rpz` holds the desired state (categories with a level, custom subscriptions, the order,
the allow list); every node renders its own side of it, filtered by the `nodes` of each entry.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from pelagos.core import settings_registry as reg
from pelagos.rpz import catalog

ACTIONS = ("nxdomain", "nodata", "redirect", "passthru")
KINDS = ("url", "axfr")
FORMATS = ("auto", "rpz", "hosts", "domains", "adblock")
ZONE_SUFFIX = "rpz.invalid"
ALLOW_ZONE = f"pelagos-allow.{ZONE_SUFFIX}"
ALLOW_ID = "allow"
# named holds back a reload of a policy zone for 60 s by default: an update shows at once instead.
NO_DEFER = "min-update-interval 0"
SUB_ID = re.compile(r"[a-z][a-z0-9-]{0,39}")
HOST = re.compile(r"(?=.{1,253}$)([a-z0-9_-]{1,63}\.)*[a-z0-9_-]{1,63}\.?", re.I)

# Registered settings come from the registry; the rest are the entries the RPZ screen writes.
DEFAULTS: dict[str, Any] = {
    **reg.domain(None, "rpz"),
    "categories": {},
    "subscriptions": {},
    "order": [],
    "allow": [],
    "exempt_clients": [],
}


class RpzInputError(ValueError):
    def __init__(self, message: str, field_name: str = "") -> None:
        super().__init__(message)
        self.field = field_name


@dataclass(slots=True)
class Sub:
    id: str
    name: str
    kind: str = "url"
    url: str = ""
    format: str = "auto"
    zone: str = ""
    enabled: bool = True
    action: str = "nxdomain"
    redirect: str = ""
    interval_hours: int = 24
    nodes: list[str] | None = None  # None: every node running BIND
    category: str | None = None
    source: str = "custom"  # catalog | category_url | custom
    license: str = ""
    homepage: str = ""
    entries_hint: int = 0
    primaries: list[str] = field(default_factory=list)
    tsig_key: str = ""
    tsig_algorithm: str = "hmac-sha256"
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def on_node(self, node_id: str) -> bool:
        return self.enabled and (self.nodes is None or node_id in self.nodes)


def config(settings: dict[str, Any]) -> dict[str, Any]:
    out = dict(DEFAULTS)
    out.update(settings.get("rpz") or {})
    return out


def slug(sub_id: str) -> str:
    return re.sub(r"[^a-z0-9-]", "-", sub_id.lower())


def zone_for(sub_id: str) -> str:
    return f"{slug(sub_id)}.{ZONE_SUFFIX}"


def zone_file_name(zone: str) -> str:
    return zone.rstrip(".") + ".db"


def url_id(category: str, url: str) -> str:
    return f"{category}-u{hashlib.sha256(url.encode()).hexdigest()[:6]}"


def _nodes(value: Any) -> list[str] | None:
    return [str(n) for n in value] if isinstance(value, list) and value else None


def _common(entry: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "action": entry.get("action") or "nxdomain",
        "redirect": entry.get("redirect") or "",
        "interval_hours": int(entry.get("interval_hours") or cfg["default_interval_hours"]),
        "nodes": _nodes(entry.get("nodes")),
    }


def category_lists(entry: dict[str, Any], category: str) -> list[str]:
    """List ids a category selection turns on: the level's lists (or the picked ones) plus add-ons."""
    cat = catalog.categories()[category]
    level = entry.get("level") or "normal"
    if level == "custom":
        picked = [i for i in entry.get("lists") or [] if i in cat["lists"]]
    else:
        picked = catalog.level_lists(category, level)
    addons = [i for i in entry.get("addons") or [] if i in cat.get("addons", [])]
    return list(dict.fromkeys([*picked, *addons]))


def resolve(settings: dict[str, Any]) -> list[Sub]:
    """Every subscription, disabled ones included, in the configured order."""
    cfg = config(settings)
    lists = catalog.lists()
    subs: dict[str, Sub] = {}
    for category, entry in (cfg["categories"] or {}).items():
        if category not in catalog.categories() or not isinstance(entry, dict):
            continue
        common = _common(entry, cfg)
        enabled = bool(entry.get("enabled"))
        for list_id in category_lists(entry, category):
            item = lists[list_id]
            subs[list_id] = Sub(
                id=list_id,
                name=item["name"],
                url=item["url"],
                format=item["format"],
                zone=zone_for(list_id),
                enabled=enabled,
                category=category,
                source="catalog",
                license=item["license"],
                homepage=item.get("homepage", ""),
                entries_hint=int(item["entries"]),
                note=item.get("note", ""),
                **common,
            )
        for extra in entry.get("urls") or []:
            sid = url_id(category, extra["url"])
            subs[sid] = Sub(
                id=sid,
                name=extra.get("name") or extra["url"],
                url=extra["url"],
                format=extra.get("format") or "auto",
                zone=zone_for(sid),
                enabled=enabled,
                category=category,
                source="category_url",
                **common,
            )
    for sid, entry in (cfg["subscriptions"] or {}).items():
        axfr = entry.get("kind") == "axfr"
        subs[sid] = Sub(
            id=sid,
            name=entry.get("name") or sid,
            kind="axfr" if axfr else "url",
            url=entry.get("url") or "",
            format=entry.get("format") or "auto",
            zone=entry.get("zone") if axfr and entry.get("zone") else zone_for(sid),
            enabled=bool(entry.get("enabled", True)),
            category=entry.get("category") or None,
            source="custom",
            primaries=list(entry.get("primaries") or []),
            tsig_key=entry.get("tsig_key") or "",
            tsig_algorithm=entry.get("tsig_algorithm") or "hmac-sha256",
            license=entry.get("license") or "",
            note=entry.get("note") or "",
            **_common(entry, cfg),
        )
    order = [i for i in cfg["order"] if i in subs]
    return [subs[i] for i in [*order, *[i for i in subs if i not in order]]]


def managed_zones(settings: dict[str, Any]) -> set[str]:
    """Names (lower case, final dot) of every policy zone the cluster RPZ state makes Pelagos own:
    each subscription's zone and, once there is one, the allow zone."""
    zones = [s.zone for s in resolve(settings)]
    if zones:
        zones.append(ALLOW_ZONE)
    return {z.lower().rstrip(".") + "." for z in zones}


def for_node(subs: list[Sub], node_id: str) -> list[Sub]:
    return [s for s in subs if s.on_node(node_id)]


def policy_clause(sub: Sub) -> str:
    if sub.action == "redirect" and not is_ip(sub.redirect):
        return f"policy cname {sub.redirect.rstrip('.')}."
    # An IP redirect is written into the zone records (policy given); the others are policy keywords.
    return {"nodata": "policy nodata", "passthru": "policy passthru", "redirect": "policy given"}.get(
        sub.action, "policy nxdomain"
    )


def response_policy_value(subs: list[Sub], break_dnssec: bool = True, allow: bool = True) -> str:
    """The `response-policy` statement value for one node: the allow zone first, then the lists."""
    parts = []
    if allow:
        parts.append(f'zone "{ALLOW_ZONE}" policy passthru {NO_DEFER};')
    for sub in subs:
        # A transferred zone keeps the provider's records (policy given) unless an action overrides.
        clause = "" if sub.kind == "axfr" and sub.action == "nxdomain" else " " + policy_clause(sub)
        parts.append(f'zone "{sub.zone}"{clause} {NO_DEFER};')
    tail = " break-dnssec yes" if break_dnssec else ""
    return "{ " + " ".join(parts) + " }" + tail


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


# Input validation -----------------------------------------------------------------------


def _check_action(body: dict[str, Any], kind: str = "url") -> dict[str, Any]:
    action = body.get("action") or "nxdomain"
    if action not in ACTIONS:
        raise RpzInputError(f"action must be one of {', '.join(ACTIONS)}", "action")
    redirect = str(body.get("redirect") or "").strip()
    if action == "redirect":
        if not redirect:
            raise RpzInputError("a redirect needs an IP address or a host name", "redirect")
        if not is_ip(redirect) and not HOST.fullmatch(redirect):
            raise RpzInputError("redirect must be an IP address or a host name", "redirect")
        if kind == "axfr" and is_ip(redirect):
            raise RpzInputError("a transferred zone can only redirect to a name", "redirect")
    else:
        redirect = ""
    hours = body.get("interval_hours", 24)
    if not isinstance(hours, int) or isinstance(hours, bool) or not 1 <= hours <= 24 * 30:
        raise RpzInputError("interval_hours must be between 1 and 720", "interval_hours")
    nodes = body.get("nodes")
    if nodes is not None and (not isinstance(nodes, list) or not all(isinstance(n, str) for n in nodes)):
        raise RpzInputError("nodes must be a list of node ids, or null for every node", "nodes")
    return {"action": action, "redirect": redirect, "interval_hours": hours, "nodes": nodes or None}


def check_url(url: Any, field_name: str = "url") -> str:
    if not isinstance(url, str) or not re.fullmatch(r"https?://[^\s/]+(/\S*)?", url):
        raise RpzInputError("url must be an http or https address", field_name)
    return url


def clean_category(category: str, body: dict[str, Any]) -> dict[str, Any]:
    cat = catalog.categories().get(category)
    if cat is None:
        raise RpzInputError(f"unknown category {category}", "category")
    level = body.get("level") or "normal"
    if level not in (*catalog.LEVELS, "custom"):
        raise RpzInputError("level must be light, normal, strict or custom", "level")
    out: dict[str, Any] = {"enabled": bool(body.get("enabled", True)), "level": level}
    if level == "custom":
        picked = body.get("lists") or []
        if not picked or any(i not in cat["lists"] for i in picked):
            raise RpzInputError("lists must name catalog lists of this category", "lists")
        out["lists"] = list(picked)
    addons = body.get("addons") or []
    if any(i not in cat.get("addons", []) for i in addons):
        raise RpzInputError("addons must name add-on lists of this category", "addons")
    out["addons"] = list(addons)
    urls = []
    for i, extra in enumerate(body.get("urls") or []):
        if not isinstance(extra, dict):
            raise RpzInputError("urls entries must be objects", f"urls[{i}]")
        fmt = extra.get("format") or "auto"
        if fmt not in FORMATS:
            raise RpzInputError(f"format must be one of {', '.join(FORMATS)}", f"urls[{i}].format")
        urls.append(
            {
                "url": check_url(extra.get("url"), f"urls[{i}].url"),
                "format": fmt,
                "name": str(extra.get("name") or ""),
            }
        )
    out["urls"] = urls
    out.update(_check_action(body))
    return _strip(out)


def _strip(entry: dict[str, Any]) -> dict[str, Any]:
    """TOML has no null: an absent value is a missing key."""
    return {k: v for k, v in entry.items() if v is not None}


def clean_subscription(sub_id: str, body: dict[str, Any], taken_zones: set[str]) -> dict[str, Any]:
    if not SUB_ID.fullmatch(sub_id) or sub_id in catalog.lists() or sub_id == ALLOW_ID:
        raise RpzInputError("id must be lowercase letters, digits and dashes, and not a catalog list", "id")
    kind = body.get("kind") or "url"
    if kind not in KINDS:
        raise RpzInputError("kind must be url or axfr", "kind")
    out: dict[str, Any] = {
        "name": str(body.get("name") or sub_id)[:80],
        "kind": kind,
        "enabled": bool(body.get("enabled", True)),
        "note": str(body.get("note") or "")[:200],
    }
    category = body.get("category") or None
    if category and category not in catalog.categories():
        raise RpzInputError(f"unknown category {category}", "category")
    out["category"] = category
    out.update(_check_action(body, kind))
    if kind == "url":
        out["url"] = check_url(body.get("url"))
        fmt = body.get("format") or "auto"
        if fmt not in FORMATS:
            raise RpzInputError(f"format must be one of {', '.join(FORMATS)}", "format")
        out["format"] = fmt
        return _strip(out)
    zone = str(body.get("zone") or "").strip().rstrip(".").lower()
    if not zone or not HOST.fullmatch(zone):
        raise RpzInputError("zone must be the name of the policy zone to transfer", "zone")
    if zone in taken_zones or zone == ALLOW_ZONE:
        raise RpzInputError(f"zone {zone} is already used", "zone")
    primaries = body.get("primaries") or []
    if not isinstance(primaries, list) or not primaries or not all(is_ip(str(p)) for p in primaries):
        raise RpzInputError("primaries must be a list of IP addresses", "primaries")
    key = str(body.get("tsig_key") or "").strip()
    if key and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", key):
        raise RpzInputError("tsig_key is not a valid key name", "tsig_key")
    algorithm = str(body.get("tsig_algorithm") or "hmac-sha256").lower()
    if algorithm not in ("hmac-sha256", "hmac-sha384", "hmac-sha512"):
        raise RpzInputError("tsig_algorithm must be hmac-sha256 or stronger", "tsig_algorithm")
    out.update(zone=zone, primaries=[str(p) for p in primaries], tsig_key=key, tsig_algorithm=algorithm)
    return _strip(out)
