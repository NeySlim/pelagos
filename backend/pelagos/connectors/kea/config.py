# SPDX-License-Identifier: Apache-2.0
"""Kea configuration round trip (section 9): projections between config-get JSON and domain objects.

Rules: `raw` keeps the original Kea object, `*_to_kea()` starts from `raw` and
overlays the typed fields, so any key Pelagos does not model survives an edit.
Kea 2.6 and 3.x key names are normalized here and nowhere else. The second
half of the module edits a whole Dhcp4/Dhcp6 object in memory from a `Change`
(the config-set write path and the diff shown in every plan).
"""

from __future__ import annotations

import copy
import difflib
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from pelagos.connectors.base import ConnectorError, NotSupported
from pelagos.domain import (
    Change,
    ChangeOp,
    ClientClass,
    Family,
    OptionData,
    PdPool,
    Pool,
    Reservation,
    ReservationIdType,
    SharedNetwork,
    Subnet,
)

PELAGOS_CONTEXT_KEY = "pelagos"
ID_KEYS = tuple(t.value for t in ReservationIdType)
# Top-level keys whose edits are configuration plumbing rather than DHCP options (scope dhcp.config).
CONFIG_SCOPE_KEYS = frozenset(
    {
        "hooks-libraries",
        "control-socket",
        "control-sockets",
        "lease-database",
        "hosts-database",
        "hosts-databases",
        "interfaces-config",
        "multi-threading",
        "loggers",
        "config-control",
        "server-tag",
        "sanity-checks",
        "dhcp-queue-control",
        "expired-leases-processing",
    }
)
# Keys that only Kea 3.x understands (anywhere in the tree).
V3_ONLY_KEYS = frozenset({"control-sockets", "evaluate-additional-classes", "only-in-additional-list"})
_SPACE_DEFAULT = {Family.V4: "dhcp4", Family.V6: "dhcp6"}


# Version helpers -------------------------------------------------------------


def is_v3(version: str | None) -> bool:
    """Unknown versions are treated as 3.x: that is the target and the only one we can probe."""
    try:
        return int((version or "3").split(".")[0]) >= 3
    except ValueError:
        return True


def root_key(family: Family) -> str:
    return "Dhcp4" if family is Family.V4 else "Dhcp6"


def subnet_key(family: Family) -> str:
    return "subnet4" if family is Family.V4 else "subnet6"


def additional_classes_key(version: str | None) -> str:
    return "evaluate-additional-classes" if is_v3(version) else "require-client-classes"


def only_additional_key(version: str | None) -> str:
    return "only-in-additional-list" if is_v3(version) else "only-if-required"


def check_version_support(obj: Any, version: str | None, path: str = "") -> None:
    """Raise NotSupported when a 3.x-only key is about to be written to a 2.6 server."""
    if is_v3(version):
        return
    if isinstance(obj, dict):
        scoped = any(k in obj for k in ("pool", "subnet", "prefix", "subnet4", "subnet6"))
        for key, value in obj.items():
            where = f"{path}/{key}" if path else key
            if key in V3_ONLY_KEYS or (key == "client-classes" and scoped):
                raise NotSupported(f"{where} needs Kea 3.x (server runs {version})")
            check_version_support(value, version, where)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            check_version_support(item, version, f"{path}[{i}]")


# Small overlay helpers ---------------------------------------------------------


def _set(out: dict[str, Any], key: str, value: Any) -> None:
    """None removes the key; an empty list or dict keeps an explicit empty only where Kea printed one."""
    if value is None:
        out.pop(key, None)
    elif isinstance(value, list | dict) and not value:
        if key in out:
            out[key] = type(value)()
    else:
        out[key] = value


def _classes_from(obj: dict[str, Any]) -> list[str]:
    if "client-classes" in obj:
        return [str(c) for c in obj.get("client-classes") or []]
    value = obj.get("client-class")
    return [str(value)] if value else []


def _set_classes(out: dict[str, Any], classes: list[str], version: str | None) -> None:
    had = "client-classes" in out or "client-class" in out
    out.pop("client-classes", None)
    out.pop("client-class", None)
    if is_v3(version):
        if classes or had:
            out["client-classes"] = list(classes)
    elif len(classes) > 1:
        raise NotSupported("Kea 2.6 accepts a single client-class per pool or subnet")
    elif classes:
        out["client-class"] = classes[0]


def _rename(out: dict[str, Any], old: str, new: str) -> None:
    if old in out and new not in out:
        out[new] = out.pop(old)
    else:
        out.pop(old, None)


def _version_keys(out: dict[str, Any], version: str | None) -> None:
    """Rename the version-dependent keys of a pool, subnet or network object in place."""
    if is_v3(version):
        _rename(out, "require-client-classes", "evaluate-additional-classes")
    else:
        _rename(out, "evaluate-additional-classes", "require-client-classes")


def _none_if_blank(value: Any) -> str | None:
    if value in (None, "", "0.0.0.0"):  # noqa: S104 (Kea prints 0.0.0.0 for "unset")
        return None
    return str(value)


# Options -----------------------------------------------------------------------


def option_from_kea(obj: dict[str, Any], space_default: str) -> OptionData:
    return OptionData(
        name=obj.get("name"),
        code=obj.get("code"),
        space=obj.get("space", space_default),
        data=str(obj.get("data", "")),
        csv_format=obj.get("csv-format"),
        always_send=obj.get("always-send"),
        never_send=obj.get("never-send"),
        raw=dict(obj),
    )


def option_to_kea(opt: OptionData) -> dict[str, Any]:
    out = dict(opt.raw)
    for key, value in (
        ("name", opt.name),
        ("code", opt.code),
        ("space", opt.space),
        ("data", opt.data),
        ("csv-format", opt.csv_format),
        ("always-send", opt.always_send),
        ("never-send", opt.never_send),
    ):
        if value is None:
            out.pop(key, None)
        else:
            out[key] = value
    return out


def options_from_kea(objs: list[dict[str, Any]] | None, family: Family) -> list[OptionData]:
    return [option_from_kea(o, _SPACE_DEFAULT[family]) for o in objs or []]


def option_matches(obj: dict[str, Any], space: str, code_or_name: str, family: Family) -> bool:
    if obj.get("space", _SPACE_DEFAULT[family]) != space:
        return False
    if code_or_name.isdigit():
        return str(obj.get("code")) == code_or_name
    return obj.get("name") == code_or_name


# Pools -------------------------------------------------------------------------


def pool_from_kea(obj: dict[str, Any], family: Family) -> Pool:
    return Pool(
        pool=str(obj.get("pool", "")),
        client_classes=_classes_from(obj),
        options=options_from_kea(obj.get("option-data"), family),
        user_context=dict(obj.get("user-context") or {}),
        raw=dict(obj),
    )


def pool_to_kea(pool: Pool, version: str | None = None) -> dict[str, Any]:
    out = dict(pool.raw)
    out["pool"] = pool.pool
    _set_classes(out, pool.client_classes, version)
    _set(out, "option-data", [option_to_kea(o) for o in pool.options])
    _set(out, "user-context", dict(pool.user_context))
    _version_keys(out, version)
    return out


def pd_pool_from_kea(obj: dict[str, Any]) -> PdPool:
    return PdPool(
        prefix=str(obj.get("prefix", "")),
        prefix_len=int(obj.get("prefix-len", 0)),
        delegated_len=int(obj.get("delegated-len", 0)),
        excluded_prefix=obj.get("excluded-prefix") or None,
        excluded_prefix_len=obj.get("excluded-prefix-len"),
        client_classes=_classes_from(obj),
        options=options_from_kea(obj.get("option-data"), Family.V6),
        user_context=dict(obj.get("user-context") or {}),
        raw=dict(obj),
    )


def pd_pool_to_kea(pd: PdPool, version: str | None = None) -> dict[str, Any]:
    out = dict(pd.raw)
    out["prefix"] = pd.prefix
    out["prefix-len"] = pd.prefix_len
    out["delegated-len"] = pd.delegated_len
    _set(out, "excluded-prefix", pd.excluded_prefix)
    _set(out, "excluded-prefix-len", pd.excluded_prefix_len if pd.excluded_prefix else None)
    _set_classes(out, pd.client_classes, version)
    _set(out, "option-data", [option_to_kea(o) for o in pd.options])
    _set(out, "user-context", dict(pd.user_context))
    _version_keys(out, version)
    return out


# Reservations ------------------------------------------------------------------


def reservation_key(obj: dict[str, Any]) -> str:
    """`<id_type>=<identifier>` as used in Change targets; identifiers compare lowercase."""
    for key in ID_KEYS:
        if obj.get(key):
            return f"{key}={str(obj[key]).lower()}"
    raise ConnectorError("reservation without identifier")


def reservation_from_kea(obj: dict[str, Any], subnet_id: int | None) -> Reservation:
    id_type = next((k for k in ID_KEYS if obj.get(k)), None)
    if id_type is None:
        raise ConnectorError(f"reservation without identifier: {json.dumps(obj)[:200]}")
    if "subnet-id" in obj and subnet_id is None:
        subnet_id = int(obj["subnet-id"]) or None
    family = Family.V6 if ("ip-addresses" in obj or "prefixes" in obj) else Family.V4
    return Reservation(
        subnet_id=subnet_id,
        id_type=ReservationIdType(id_type),
        identifier=str(obj[id_type]).lower(),
        ip_address=obj.get("ip-address") or None,
        ip_addresses=[str(a) for a in obj.get("ip-addresses") or []],
        prefixes=[str(p) for p in obj.get("prefixes") or []],
        hostname=obj.get("hostname") or None,
        client_classes=[str(c) for c in obj.get("client-classes") or []],
        options=options_from_kea(obj.get("option-data"), family),
        next_server=_none_if_blank(obj.get("next-server")),
        server_hostname=obj.get("server-hostname") or None,
        boot_file_name=obj.get("boot-file-name") or None,
        user_context=dict(obj.get("user-context") or {}),
        raw={k: v for k, v in obj.items() if k != "subnet-id"},
    )


def reservation_to_kea(res: Reservation, with_subnet_id: bool = False) -> dict[str, Any]:
    out = dict(res.raw)
    for key in ID_KEYS:
        out.pop(key, None)
    out[res.id_type.value] = res.identifier
    _set(out, "ip-address", res.ip_address)
    _set(out, "ip-addresses", list(res.ip_addresses))
    _set(out, "prefixes", list(res.prefixes))
    _set(out, "hostname", res.hostname)
    _set(out, "client-classes", list(res.client_classes))
    _set(out, "option-data", [option_to_kea(o) for o in res.options])
    _set(out, "next-server", res.next_server)
    _set(out, "server-hostname", res.server_hostname)
    _set(out, "boot-file-name", res.boot_file_name)
    _set(out, "user-context", dict(res.user_context))
    out.pop("subnet-id", None)
    if with_subnet_id:
        out["subnet-id"] = res.subnet_id or 0
    return out


# Subnets and shared networks -----------------------------------------------------


def subnet_from_kea(
    obj: dict[str, Any], family: Family, shared_network: str | None = None, version: str | None = None
) -> Subnet:
    sid = int(obj.get("id", 0))
    return Subnet(
        id=sid,
        subnet=str(obj.get("subnet", "")),
        family=family,
        shared_network=shared_network,
        pools=[pool_from_kea(p, family) for p in obj.get("pools") or []],
        pd_pools=[pd_pool_from_kea(p) for p in obj.get("pd-pools") or []],
        options=options_from_kea(obj.get("option-data"), family),
        reservations=[reservation_from_kea(r, sid) for r in obj.get("reservations") or []],
        client_classes=_classes_from(obj),
        relay=[str(a) for a in (obj.get("relay") or {}).get("ip-addresses") or []],
        interface=obj.get("interface") or None,
        valid_lifetime=obj.get("valid-lifetime"),
        min_valid_lifetime=obj.get("min-valid-lifetime"),
        max_valid_lifetime=obj.get("max-valid-lifetime"),
        preferred_lifetime=obj.get("preferred-lifetime"),
        reservations_global=obj.get("reservations-global"),
        reservations_in_subnet=obj.get("reservations-in-subnet"),
        reservations_out_of_pool=obj.get("reservations-out-of-pool"),
        ddns={k: v for k, v in obj.items() if k.startswith("ddns-")},
        user_context=dict(obj.get("user-context") or {}),
        raw=dict(obj),
    )


def subnet_to_kea(subnet: Subnet, version: str | None = None) -> dict[str, Any]:
    out = dict(subnet.raw)
    out["id"] = subnet.id
    out["subnet"] = subnet.subnet
    _set(out, "pools", [pool_to_kea(p, version) for p in subnet.pools])
    if subnet.family is Family.V6:
        _set(out, "pd-pools", [pd_pool_to_kea(p, version) for p in subnet.pd_pools])
    _set(out, "option-data", [option_to_kea(o) for o in subnet.options])
    _set(out, "reservations", [reservation_to_kea(r) for r in subnet.reservations])
    _set_classes(out, subnet.client_classes, version)
    if subnet.relay or "relay" in out:
        out["relay"] = {**(out.get("relay") or {}), "ip-addresses": list(subnet.relay)}
    _set(out, "interface", subnet.interface)
    _set(out, "valid-lifetime", subnet.valid_lifetime)
    _set(out, "min-valid-lifetime", subnet.min_valid_lifetime)
    _set(out, "max-valid-lifetime", subnet.max_valid_lifetime)
    if subnet.family is Family.V6:
        _set(out, "preferred-lifetime", subnet.preferred_lifetime)
    _set(out, "reservations-global", subnet.reservations_global)
    _set(out, "reservations-in-subnet", subnet.reservations_in_subnet)
    _set(out, "reservations-out-of-pool", subnet.reservations_out_of_pool)
    for key in [k for k in out if k.startswith("ddns-")]:
        del out[key]
    out.update(subnet.ddns)
    _set(out, "user-context", dict(subnet.user_context))
    _version_keys(out, version)
    return out


def shared_network_from_kea(obj: dict[str, Any], family: Family, version: str | None = None) -> SharedNetwork:
    name = str(obj.get("name", ""))
    return SharedNetwork(
        name=name,
        family=family,
        subnets=[subnet_from_kea(s, family, name, version) for s in obj.get(subnet_key(family)) or []],
        options=options_from_kea(obj.get("option-data"), family),
        interface=obj.get("interface") or None,
        relay=[str(a) for a in (obj.get("relay") or {}).get("ip-addresses") or []],
        user_context=dict(obj.get("user-context") or {}),
        raw=dict(obj),
    )


def shared_network_to_kea(net: SharedNetwork, version: str | None = None) -> dict[str, Any]:
    out = dict(net.raw)
    out["name"] = net.name
    key = subnet_key(net.family)
    out[key] = [subnet_to_kea(s.replace(shared_network=net.name), version) for s in net.subnets]
    _set(out, "option-data", [option_to_kea(o) for o in net.options])
    _set(out, "interface", net.interface)
    if net.relay or "relay" in out:
        out["relay"] = {**(out.get("relay") or {}), "ip-addresses": list(net.relay)}
    _set(out, "user-context", dict(net.user_context))
    _version_keys(out, version)
    return out


# Client classes --------------------------------------------------------------------


def client_class_from_kea(obj: dict[str, Any], version: str | None = None) -> ClientClass:
    only = obj.get("only-in-additional-list", obj.get("only-if-required"))
    family = Family.V6 if any(o.get("space") == "dhcp6" for o in obj.get("option-data") or []) else Family.V4
    return ClientClass(
        name=str(obj.get("name", "")),
        test=obj.get("test"),
        options=options_from_kea(obj.get("option-data"), family),
        option_def=[dict(d) for d in obj.get("option-def") or []],
        only_in_additional_list=only,
        next_server=_none_if_blank(obj.get("next-server")),
        server_hostname=obj.get("server-hostname") or None,
        boot_file_name=obj.get("boot-file-name") or None,
        user_context=dict(obj.get("user-context") or {}),
        raw=dict(obj),
    )


def client_class_to_kea(cls: ClientClass, version: str | None = None) -> dict[str, Any]:
    out = dict(cls.raw)
    out["name"] = cls.name
    _set(out, "test", cls.test)
    _set(out, "option-data", [option_to_kea(o) for o in cls.options])
    _set(out, "option-def", [dict(d) for d in cls.option_def])
    out.pop("only-in-additional-list", None)
    out.pop("only-if-required", None)
    if cls.only_in_additional_list is not None:
        out[only_additional_key(version)] = cls.only_in_additional_list
    _set(out, "next-server", cls.next_server)
    _set(out, "server-hostname", cls.server_hostname)
    _set(out, "boot-file-name", cls.boot_file_name)
    _set(out, "user-context", dict(cls.user_context))
    return out


# Pelagos metadata in user-context ----------------------------------------------------


def pelagos_context(user_context: dict[str, Any]) -> dict[str, Any]:
    """Pelagos metadata lives under user-context.pelagos; other keys are untouched."""
    return dict(user_context.get(PELAGOS_CONTEXT_KEY) or {})


def with_pelagos_context(user_context: dict[str, Any], **meta: Any) -> dict[str, Any]:
    out = dict(user_context)
    current = dict(out.get(PELAGOS_CONTEXT_KEY) or {})
    current.update({k: v for k, v in meta.items() if v is not None})
    out[PELAGOS_CONTEXT_KEY] = current
    return out


# Navigation inside a Dhcp4 / Dhcp6 object -----------------------------------------------


def iter_subnets(cfg: dict[str, Any], family: Family) -> Iterator[tuple[dict[str, Any], str | None]]:
    """Every subnet object with the name of its shared network (None at top level), in config order."""
    key = subnet_key(family)
    for obj in cfg.get(key) or []:
        yield obj, None
    for net in cfg.get("shared-networks") or []:
        for obj in net.get(key) or []:
            yield obj, str(net.get("name", ""))


def find_subnet(
    cfg: dict[str, Any], family: Family, subnet_id: int
) -> tuple[list[Any], int, str | None] | None:
    """(containing list, index, shared network name) of the subnet with that id, or None."""
    key = subnet_key(family)
    top = cfg.get(key) or []
    for i, obj in enumerate(top):
        if int(obj.get("id", -1)) == subnet_id:
            return top, i, None
    for net in cfg.get("shared-networks") or []:
        subs = net.get(key) or []
        for i, obj in enumerate(subs):
            if int(obj.get("id", -1)) == subnet_id:
                return subs, i, str(net.get("name", ""))
    return None


def next_subnet_id(cfg: dict[str, Any], family: Family) -> int:
    ids = [int(obj.get("id", 0)) for obj, _ in iter_subnets(cfg, family)]
    return max(ids, default=0) + 1


def find_by_name(items: list[dict[str, Any]], name: str) -> int | None:
    for i, obj in enumerate(items):
        if str(obj.get("name")) == name:
            return i
    return None


def find_reservation(items: list[dict[str, Any]], key: str) -> int | None:
    key = key.lower()
    for i, obj in enumerate(items):
        try:
            if reservation_key(obj) == key:
                return i
        except ConnectorError:
            continue
    return None


# Change targets -------------------------------------------------------------------------

_SUBNET_RE = re.compile(r"^subnet(?P<fam>[46])/(?P<id>new|\d+)$")
_RESERVATION_RE = re.compile(
    r"^(?:subnet(?P<fam>[46])/(?P<id>\d+)|(?P<glob>global))/reservations/(?P<idtype>[a-z-]+)=(?P<ident>.+)$"
)
_NETWORK_RE = re.compile(r"^shared-networks/(?P<name>.+)$")
_CLASS_RE = re.compile(r"^client-classes/(?P<name>.+)$")
_OPTION_RE = re.compile(r"^option-data/(?P<space>[^/]+)/(?P<key>[^/]+)$")
_LEASE_RE = re.compile(r"^lease(?P<fam>[46])/(?P<ip>.+)$")


@dataclass(slots=True)
class Target:
    # subnet | reservation | shared_network | client_class | option | key | config | lease | ha | service
    kind: str
    subnet_id: int | None = None
    name: str | None = None  # network, class, top-level key, option name/code, lease ip
    space: str | None = None
    reservation_key: str | None = None
    global_reservation: bool = False


def parse_target(target: str) -> Target:
    if target == "config":
        return Target("config")
    if target == "ha/maintenance":
        return Target("ha")
    if target == "service":
        return Target("service")
    if m := _SUBNET_RE.match(target):
        return Target("subnet", subnet_id=None if m["id"] == "new" else int(m["id"]))
    if m := _RESERVATION_RE.match(target):
        return Target(
            "reservation",
            subnet_id=int(m["id"]) if m["id"] else None,
            reservation_key=f"{m['idtype']}={m['ident'].lower()}",
            global_reservation=bool(m["glob"]),
        )
    if m := _NETWORK_RE.match(target):
        return Target("shared_network", name=m["name"])
    if m := _CLASS_RE.match(target):
        return Target("client_class", name=m["name"])
    if m := _OPTION_RE.match(target):
        return Target("option", space=m["space"], name=m["key"])
    if m := _LEASE_RE.match(target):
        return Target("lease", name=m["ip"])
    if "/" not in target and target:
        return Target("key", name=target)
    raise ConnectorError(f"unknown change target {target!r}")


def is_domain_dict(value: Any) -> bool:
    """Domain dicts use snake_case keys (and `raw`), Kea dicts use dashes."""
    return isinstance(value, dict) and any("_" in k or k == "raw" for k in value)


def option_value_to_kea(value: Any) -> dict[str, Any]:
    if is_domain_dict(value):
        return option_to_kea(OptionData.from_dict(value))
    if isinstance(value, dict):
        return dict(value)
    raise ConnectorError("option change needs an OptionData or Kea option object")


# In-memory edits ----------------------------------------------------------------------------


def apply_change(
    cfg: dict[str, Any], change: Change, family: Family, version: str | None = None
) -> dict[str, Any]:
    """Return a deep copy of the Dhcp4/Dhcp6 object with one Change applied; raises on a stale change."""
    out = copy.deepcopy(cfg)
    t = parse_target(change.target)
    op = change.op
    if t.kind == "config":
        if not isinstance(change.after, dict):
            raise ConnectorError("config change needs the whole Dhcp4/Dhcp6 object in `after`")
        new = copy.deepcopy(change.after)
        check_version_support(new, version)
        return new
    if t.kind == "subnet":
        _edit_subnet(out, t, change, family, version)
    elif t.kind == "shared_network":
        _edit_named(out, "shared-networks", t.name or "", op, change.after, family, version, kind="network")
    elif t.kind == "client_class":
        _edit_named(out, "client-classes", t.name or "", op, change.after, family, version, kind="class")
    elif t.kind == "reservation":
        _edit_reservation(out, t, change, family)
    elif t.kind == "option":
        items = out.setdefault("option-data", [])
        idx = next(
            (i for i, o in enumerate(items) if option_matches(o, t.space or "", t.name or "", family)), None
        )
        if op is ChangeOp.DELETE:
            if idx is None:
                raise ConnectorError(f"option {change.target} not found")
            del items[idx]
        else:
            obj = option_value_to_kea(change.after)
            obj.setdefault("space", t.space)
            if idx is None:
                items.append(obj)
            else:
                items[idx] = obj
    elif t.kind == "key":
        if op is ChangeOp.DELETE:
            out.pop(t.name or "", None)
        else:
            check_version_support({t.name: change.after}, version)
            out[t.name or ""] = copy.deepcopy(change.after)
    else:
        raise ConnectorError(f"change {change.target} does not edit the configuration")
    return out


def apply_changes(
    cfg: dict[str, Any], changes: list[Change], family: Family, version: str | None = None
) -> dict[str, Any]:
    for change in changes:
        cfg = apply_change(cfg, change, family, version)
    return cfg


def _edit_subnet(out: dict[str, Any], t: Target, change: Change, family: Family, version: str | None) -> None:
    key = subnet_key(family)
    found = find_subnet(out, family, t.subnet_id) if t.subnet_id is not None else None
    if change.op is ChangeOp.DELETE:
        if found is None:
            raise ConnectorError(f"subnet {t.subnet_id} not found")
        del found[0][found[1]]
        return
    subnet = Subnet.from_dict(change.after) if is_domain_dict(change.after) else None
    if subnet is None:
        raise ConnectorError("subnet change needs a Subnet in `after`")
    if change.op is ChangeOp.REPLACE:
        if found is None:
            raise ConnectorError(f"subnet {t.subnet_id} not found")
        container, idx, current_net = found
        # A caller without `raw` gets the object as it is now, so keys it never saw survive.
        subnet = subnet.replace(id=t.subnet_id or subnet.id, raw=subnet.raw or dict(container[idx]))
        obj = subnet_to_kea(subnet, version)
        if subnet.shared_network == current_net:
            container[idx] = obj
            return
        del container[idx]
    else:
        if found is not None:
            raise ConnectorError(f"subnet {t.subnet_id} already exists")
        if not subnet.id:
            subnet = subnet.replace(id=t.subnet_id or next_subnet_id(out, family))
        obj = subnet_to_kea(subnet, version)
    check_version_support(obj, version)
    if subnet.shared_network:
        nets = out.setdefault("shared-networks", [])
        n = find_by_name(nets, subnet.shared_network)
        if n is None:
            raise ConnectorError(f"shared network {subnet.shared_network!r} not found")
        nets[n].setdefault(key, []).append(obj)
    else:
        out.setdefault(key, []).append(obj)


def _edit_named(
    out: dict[str, Any],
    list_key: str,
    name: str,
    op: ChangeOp,
    after: Any,
    family: Family,
    version: str | None,
    kind: str,
) -> None:
    items = out.setdefault(list_key, [])
    idx = find_by_name(items, name)
    if op is ChangeOp.DELETE:
        if idx is None:
            raise ConnectorError(f"{list_key}/{name} not found")
        del items[idx]
        return
    if not is_domain_dict(after):
        raise ConnectorError(f"{list_key} change needs a domain object in `after`")
    if kind == "network":
        net = SharedNetwork.from_dict(after)
        if idx is not None and not net.raw:
            net = net.replace(raw=dict(items[idx]))
        obj = shared_network_to_kea(net, version)
    else:
        cls = ClientClass.from_dict(after)
        if idx is not None and not cls.raw:
            cls = cls.replace(raw=dict(items[idx]))
        obj = client_class_to_kea(cls, version)
    check_version_support(obj, version)
    if op is ChangeOp.ADD:
        if idx is not None:
            raise ConnectorError(f"{list_key}/{name} already exists")
        items.append(obj)
    else:
        if idx is None:
            raise ConnectorError(f"{list_key}/{name} not found")
        items[idx] = obj


def reservation_list(out: dict[str, Any], t: Target, family: Family) -> list[dict[str, Any]]:
    if t.global_reservation:
        return out.setdefault("reservations", [])
    found = find_subnet(out, family, t.subnet_id or 0)
    if found is None:
        raise ConnectorError(f"subnet {t.subnet_id} not found")
    return found[0][found[1]].setdefault("reservations", [])


def _edit_reservation(out: dict[str, Any], t: Target, change: Change, family: Family) -> None:
    items = reservation_list(out, t, family)
    idx = find_reservation(items, t.reservation_key or "")
    if change.op is ChangeOp.DELETE:
        if idx is None:
            raise ConnectorError(f"reservation {t.reservation_key} not found")
        del items[idx]
        return
    if not is_domain_dict(change.after):
        raise ConnectorError("reservation change needs a Reservation in `after`")
    res = Reservation.from_dict(change.after)
    if idx is not None and not res.raw:
        res = res.replace(raw=dict(items[idx]))
    obj = reservation_to_kea(res)
    if change.op is ChangeOp.ADD:
        if idx is not None:
            raise ConnectorError(f"reservation {t.reservation_key} already exists")
        items.append(obj)
    else:
        if idx is None:
            raise ConnectorError(f"reservation {t.reservation_key} not found")
        items[idx] = obj


# Diff and comparison ------------------------------------------------------------------------------


def canonical(cfg: Any) -> str:
    return json.dumps(cfg, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def config_diff(before: Any, after: Any, path: str) -> str:
    return "".join(
        difflib.unified_diff(
            canonical(before).splitlines(keepends=True),
            canonical(after).splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            n=3,
        )
    )
