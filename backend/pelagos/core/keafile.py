# SPDX-License-Identifier: Apache-2.0
"""Kea configuration files: parsing (comments, trailing commas, `<?include?>`), comparison with the
running configuration (config-get), and the merges Pelagos needs to write a file back losslessly.

Shared by the installer, the collector and the Kea connectors; the lossless text editor itself is
`pelagos.core.keadoc`.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterator
from difflib import SequenceMatcher
from pathlib import Path, PurePosixPath
from typing import Any

_INCLUDE_RE = re.compile(r"<\?\s*include\s+\"([^\"\n]+)\"\s*\?>")


class KeaConfigError(ValueError):
    pass


def strip_comments(text: str) -> str:
    """Removes the three comment kinds outside strings; keeps the JSON otherwise byte-identical."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i) or ch == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def strip_trailing_commas(text: str) -> str:
    """Drops a comma followed only by blanks and `}` or `]`, which Kea's parser tolerates and JSON not."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            in_str = ch != '"'
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j >= n or text[j] not in "}]":
                out.append(ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def has_include(text: str) -> bool:
    return bool(_INCLUDE_RE.search(strip_comments(text)))


def loads(text: str, path: str | None = None) -> dict[str, Any]:
    """Parses a Kea config file. `<?include?>` is resolved when `path` names the file (the included
    files are read from disk, relative names as Kea opens them); without a path it is refused."""
    from pelagos.core.keadoc import KeaDocument

    if has_include(text) and path is None:
        raise KeaConfigError("config uses <?include?> and no file path was given to resolve it")
    try:
        data = KeaDocument.from_text(text, path or "config").value
    except KeaConfigError as exc:
        raise KeaConfigError(f"{path or 'config'}: {exc}") from exc
    if not isinstance(data, dict):
        raise KeaConfigError(f"{path or 'config'}: top level is not an object")
    return data


def load(path: Path) -> dict[str, Any]:
    """The configuration a Kea file says, includes resolved."""
    try:
        text = path.read_text()
    except (OSError, UnicodeDecodeError) as exc:
        raise KeaConfigError(f"cannot read {path}: {exc}") from exc
    return loads(text, str(path))


def included_files(path: Path) -> list[Path]:
    """Every file a Kea configuration pulls in through `<?include?>`, the file itself excluded."""
    from pelagos.core.keadoc import KeaDocument

    doc = KeaDocument(path)
    return [p for p in dict.fromkeys(doc.paths) if p != doc.path]


# File versus running configuration (CONFIG_DIVERGENCE, cause "file") ------------------------------

KEA_ROOTS = ("Dhcp4", "Dhcp6", "DhcpDdns")
# Not compared: logging is not service behavior, and Kea 3.x rewrites log paths under its log dir.
KEA_IGNORED_TOP = frozenset({"loggers", "hash"})
KEA_LOWERCASE = frozenset({"hw-address", "duid", "client-id", "circuit-id", "flex-id"})
KEA_REDACTED = frozenset({"*****", "****", "***"})
_RANGE = re.compile(r"\s*-\s*")


def kea_body(config: dict[str, Any]) -> dict[str, Any]:
    return next((config[k] for k in KEA_ROOTS if isinstance(config.get(k), dict)), config)


def _kea_scalar(key: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if key == "pool":
        return _pool_range(value) or _RANGE.sub("-", value.strip())
    if key in KEA_LOWERCASE:
        return value.strip().lower()
    if key == "library":
        return PurePosixPath(value).name  # the directory depends on the architecture
    if key == "data" and "," in value:
        return ",".join(part.strip() for part in value.split(","))
    return value


def _pool_range(value: str) -> tuple[int, int, int] | None:
    """(version, first, last) of "a - b" or "prefix/len": Kea prints an aligned range as a prefix."""
    text = value.strip()
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            return net.version, int(net.network_address), int(net.broadcast_address)
        first, _, last = _RANGE.sub("-", text).partition("-")
        a, b = ipaddress.ip_address(first), ipaddress.ip_address(last)
        return a.version, int(a), int(b)
    except ValueError:
        return None


def is_sensitive_kea_key(key: str) -> bool:
    """Keys whose values never appear in a difference (`secret`, `basic-auth-password`, ...)."""
    key = key.lower()
    return key.endswith(("password", "secret"))


_DIFF_PATH = re.compile(r"^(?P<path>.*?): ")
_LAST_KEY = re.compile(r"/(?P<key>[^/\[]+)(?:\[[^\]]*\])*$")


def redact_kea_difference(line: str) -> str:
    """`<path>: differs` when the path ends on a sensitive key, the line unchanged otherwise."""
    m = _DIFF_PATH.match(line)
    if not m:
        return line
    last = _LAST_KEY.search(m.group("path"))
    if last and is_sensitive_kea_key(last.group("key")):
        return f"{m.group('path')}: differs"
    return line


def same_scalar(key: str, file_value: Any, running: Any) -> bool:
    a, b = _kea_scalar(key, file_value), _kea_scalar(key, running)
    if a == b:
        return True
    if isinstance(b, str) and b in KEA_REDACTED:
        return True  # secrets and passwords are masked by config-get
    if isinstance(a, str) and isinstance(b, str) and (a.startswith("/") != b.startswith("/")):
        # Kea resolves relative socket, lease, hook and secret file names against its own directories.
        return PurePosixPath(a).name == PurePosixPath(b).name
    return False


# Lists whose items are matched by identity, not position (config-get orders them as it likes).
RESERVATION_IDS = ("hw-address", "client-id", "duid", "circuit-id", "flex-id")
IDENTIFIED_LISTS = frozenset(
    {
        "reservations",
        "subnet4",
        "subnet6",
        "pools",
        "pd-pools",
        "option-data",
        "option-def",
        "hooks-libraries",
        "client-classes",
        "shared-networks",
        "ddns-domains",
        "tsig-keys",
        "dns-servers",
        "peers",
    }
)
_DEFAULT_SPACES = frozenset({"", "dhcp4", "dhcp6"})
Ident = tuple[str, str]


def _pool_text(value: str) -> str:
    parsed = _pool_range(value)
    if parsed is None:
        return _RANGE.sub("-", value.strip())
    version, first, last = parsed
    addr = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return f"{addr(first)}-{addr(last)}"


def item_idents(key: str, item: dict[str, Any]) -> list[Ident]:
    """The identities of one list item, preferred first: two items are the same when they share one."""
    out: list[Ident] = []
    if key == "reservations":
        present = [(f, str(item[f]).strip().lower()) for f in RESERVATION_IDS if item.get(f)]
        if present:
            out.append((present[0][0], "+".join(v for _, v in present)))
        for f in ("ip-address", "hostname"):
            if item.get(f) and not present:
                out.append((f, str(item[f]).lower()))
    elif key in ("subnet4", "subnet6"):
        if item.get("id") is not None:
            out.append(("id", str(item["id"])))
        if item.get("subnet"):
            out.append(("subnet", str(item["subnet"]).strip().lower()))
    elif key == "pools":
        if isinstance(item.get("pool"), str):
            out.append(("pool", _pool_text(item["pool"])))
    elif key == "pd-pools":
        if item.get("prefix") is not None:
            out.append(("prefix", f"{item['prefix']}/{item.get('prefix-len', '')}"))
    elif key in ("option-data", "option-def"):
        space = str(item.get("space") or "")
        pre = "" if space in _DEFAULT_SPACES else f"{space}."
        if item.get("code") is not None:
            out.append(("code", f"{pre}{item['code']}"))
        if item.get("name"):
            out.append(("name", f"{pre}{item['name']}"))
    elif key == "hooks-libraries":
        if item.get("library"):
            out.append(("library", PurePosixPath(str(item["library"])).name))
    elif key == "dns-servers":
        if item.get("ip-address"):
            out.append(("ip-address", str(item["ip-address"])))
    elif item.get("name"):
        out.append(("name", str(item["name"]).lower()))
    return out or [("item", json.dumps(item, sort_keys=True))]


def _identified(key: str, *lists: list[Any]) -> bool:
    return key in IDENTIFIED_LISTS and all(isinstance(x, dict) for lst in lists for x in lst)


def pair_items(key: str, a: list[Any], b: list[Any]) -> tuple[list[tuple[int, int]], list[int], list[int]]:
    """(pairs of indexes, indexes only in a, indexes only in b), items matched by identity."""
    index: dict[Ident, list[int]] = {}
    for j, item in enumerate(b):
        for ident in item_idents(key, item):
            index.setdefault(ident, []).append(j)
    used: set[int] = set()
    pairs: list[tuple[int, int]] = []
    only_a: list[int] = []
    for i, item in enumerate(a):
        hit = next(
            (j for ident in item_idents(key, item) for j in index.get(ident, ()) if j not in used), None
        )
        if hit is None:
            only_a.append(i)
        else:
            used.add(hit)
            pairs.append((i, hit))
    return pairs, only_a, [j for j in range(len(b)) if j not in used]


def item_label(key: str, item: dict[str, Any]) -> str:
    kind, value = item_idents(key, item)[0]
    return f"{kind}={value}" if kind != "item" else "item"


def _summary(key: str, item: dict[str, Any]) -> str:
    """What a reservation is for, to read a difference without opening the file."""
    if key != "reservations":
        return ""
    bits = [f"{k}={item[k]}" for k in ("hostname", "ip-address") if item.get(k)]
    return f" ({', '.join(bits)})" if bits else ""


def _kea_diff(file_value: Any, running: Any, path: str, key: str) -> Iterator[str]:
    if isinstance(file_value, dict):
        if not isinstance(running, dict):
            yield f"{path or '/'}: object in the file, {type(running).__name__} running"
            return
        for k, v in file_value.items():
            sub = f"{path}/{k}"
            if not path and k in KEA_IGNORED_TOP:
                continue
            if k == "comment" and "comment" not in running:
                # Kea moves a `comment` into user-context.
                v_running = (running.get("user-context") or {}).get("comment")
                if v_running != v:
                    yield f"{sub}: {v!r} in the file, {v_running!r} running"
                continue
            if not path and k == "control-socket" and k not in running and "control-sockets" in running:
                # Kea 3.x reports the singular form as a one-item control-sockets list.
                yield from _kea_diff([v], running["control-sockets"], "/control-sockets", k)
                continue
            if k not in running:
                yield f"{sub}: in the file, absent from the running configuration"
                continue
            yield from _kea_diff(v, running[k], sub, k)
        return
    if isinstance(file_value, list):
        if not isinstance(running, list):
            yield f"{path}: list in the file, {type(running).__name__} running"
        elif _identified(key, file_value, running):
            pairs, only_file, only_running = pair_items(key, file_value, running)
            for i in only_file:
                item = file_value[i]
                what = f"{path}[{item_label(key, item)}]: in the file{_summary(key, item)}"
                yield f"{what}, absent from the running configuration"
            for j in only_running:
                item = running[j]
                yield f"{path}[{item_label(key, item)}]: running{_summary(key, item)}, absent from the file"
            for i, j in pairs:
                yield from _kea_diff(
                    file_value[i], running[j], f"{path}[{item_label(key, file_value[i])}]", key
                )
        elif len(file_value) != len(running):
            yield f"{path}: {len(file_value)} item(s) in the file, {len(running)} running"
        else:
            for i, (a, b) in enumerate(zip(file_value, running, strict=True)):
                yield from _kea_diff(a, b, f"{path}[{i}]", key)
        return
    if not same_scalar(key, file_value, running):
        if is_sensitive_kea_key(key):
            yield f"{path}: differs"
        else:
            yield f"{path}: {file_value!r} in the file, {running!r} running"


def _sym_diff(a: Any, b: Any, path: str, key: str, na: str, nb: str) -> Iterator[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        for k in [*a, *(k for k in b if k not in a)]:
            sub = f"{path}/{k}"
            if k not in b:
                yield f"{sub}: only on {na}"
            elif k not in a:
                yield f"{sub}: only on {nb}"
            else:
                yield from _sym_diff(a[k], b[k], sub, k, na, nb)
    elif isinstance(a, list) and isinstance(b, list):
        if _identified(key, a, b):
            pairs, only_a, only_b = pair_items(key, a, b)
            for i in only_a:
                yield f"{path}[{item_label(key, a[i])}]: only on {na}{_summary(key, a[i])}"
            for j in only_b:
                yield f"{path}[{item_label(key, b[j])}]: only on {nb}{_summary(key, b[j])}"
            for i, j in pairs:
                yield from _sym_diff(a[i], b[j], f"{path}[{item_label(key, a[i])}]", key, na, nb)
        elif all(not isinstance(x, dict | list) for x in a + b):
            for x in a:
                if x not in b:
                    yield f"{path}: {x!r} only on {na}"
            for x in b:
                if x not in a:
                    yield f"{path}: {x!r} only on {nb}"
        elif len(a) != len(b):
            yield f"{path}: {len(a)} item(s) on {na}, {len(b)} on {nb}"
        else:
            for i, (x, y) in enumerate(zip(a, b, strict=True)):
                yield from _sym_diff(x, y, f"{path}[{i}]", key, na, nb)
    elif a != b:
        yield f"{path}: {a!r} on {na}, {b!r} on {nb}"


def view_differences(a: Any, b: Any, name_a: str, name_b: str) -> list[str]:
    """Paths where two normalized views (collector.kea_shared) differ, lists matched by identity."""
    return list(_sym_diff(a, b, "", "", name_a, name_b))


def kea_config_differences(file_config: dict[str, Any], running_config: dict[str, Any]) -> list[str]:
    """Paths where the file on disk says something the running daemon (config-get) does not.

    config-get adds every default, so the file is compared as a subset: each key the file sets must
    hold the same value at runtime; keys only present at runtime are defaults and ignored. Values are
    normalized as Kea does (pool ranges without blanks, lower-case identifiers, the singular
    control-socket as a list, `comment` in user-context, masked secrets, paths resolved by Kea).
    """
    return list(_kea_diff(kea_body(file_config), kea_body(running_config), "", ""))


# Merges used to write a file back ---------------------------------------------------------------

# Keys identifying list items, so a running-config change follows the item rather than its index.
_ITEM_KEYS = ("id", "name", "library", "subnet", "prefix", "pool", "hw-address", "duid", "client-id")


def _item_id(value: Any) -> str:
    if isinstance(value, dict):
        for k in _ITEM_KEYS:
            if k in value and not isinstance(value[k], dict | list):
                return f"{k}={value[k]!r}"
    return json.dumps(value, sort_keys=True)


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _strip_inherited(value: Any, inherited: dict[str, Any] | None) -> Any:
    """`value` without the global values config-get copies into nested objects (inherited ones)."""
    if inherited is None:
        return _copy(value)
    if isinstance(value, list):
        return [_strip_inherited(v, inherited) for v in value]
    if not isinstance(value, dict):
        return _copy(value)
    out = {}
    for k, v in value.items():
        if k in inherited and not isinstance(v, dict | list) and inherited[k] == v:
            continue
        v = _strip_inherited(v, inherited)
        if v in ("", [], {}):
            continue  # Kea's empty defaults (4o6-interface, relay addresses, option-data)
        out[k] = v
    return out


def _children_stripped(value: Any, inherited: dict[str, Any] | None) -> Any:
    """A new top-level value (a list of subnets, say) whose items do not repeat global values."""
    if isinstance(value, list):
        return [_strip_inherited(v, inherited) for v in value]
    return _copy(value)


def rebase(
    file_value: Any,
    before: Any,
    after: Any,
    key: str = "",
    inherited: dict[str, Any] | None = None,
    nested: bool = False,
) -> Any:
    """What the file should say once the running configuration went from `before` to `after`.

    The file is a subset of `before` (config-get adds defaults): what did not change keeps the file's
    spelling, changed values take `after`, new items and keys come from `after`, and keys that left
    the running configuration leave the file. Lists that do not line up with `before` are replaced.
    `inherited` holds the global values: below the top level, a value equal to its global one is
    inherited (config-get writes it everywhere) and is not added to the file.
    """
    if json.dumps(before, sort_keys=True) == json.dumps(after, sort_keys=True):
        return _copy(file_value)
    if isinstance(file_value, dict) and isinstance(before, dict) and isinstance(after, dict):
        out: dict[str, Any] = {}
        for k, v in file_value.items():
            if k in before and k in after:
                out[k] = rebase(v, before[k], after[k], k, inherited, True)
            elif k in before:
                continue  # removed from the running configuration
            elif k == "control-socket" and "control-sockets" in before and "control-sockets" not in after:
                continue
            else:
                out[k] = _copy(v)  # spelled differently in the file (comment, control-socket)
        for k, v in after.items():
            if k in out or k in file_value:
                continue
            if (
                nested
                and inherited is not None
                and k in inherited
                and not isinstance(v, dict | list)
                and inherited[k] == v
            ):
                continue
            if k not in before or json.dumps(before[k], sort_keys=True) != json.dumps(v, sort_keys=True):
                out[k] = _strip_inherited(v, inherited) if nested else _children_stripped(v, inherited)
        return out
    if isinstance(file_value, list) and isinstance(before, list) and isinstance(after, list):
        if _identified(key, file_value, before, after):
            pairs, _, only_after = pair_items(key, file_value, after)
            before_of = dict(pair_items(key, file_value, before)[0])
            kept = [
                rebase(
                    file_value[i],
                    before[before_of[i]] if i in before_of else after[j],
                    after[j],
                    key,
                    inherited,
                    True,
                )
                for i, j in pairs
            ]
            return kept + [_strip_inherited(after[j], inherited) for j in only_after]
        if len(file_value) != len(before):
            return _strip_inherited(after, inherited)
        a = [_item_id(x) for x in before]
        b = [_item_id(x) for x in after]
        result = []
        for tag, i1, i2, j1, j2 in SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
            if tag == "equal":
                result.extend(
                    rebase(file_value[i], before[i], after[j], key, inherited, True)
                    for i, j in zip(range(i1, i2), range(j1, j2), strict=True)
                )
            elif tag == "replace":
                paired = min(i2 - i1, j2 - j1)
                result.extend(
                    rebase(file_value[i1 + p], before[i1 + p], after[j1 + p], key, inherited, True)
                    for p in range(paired)
                )
                result.extend(_strip_inherited(after[j], inherited) for j in range(j1 + paired, j2))
            elif tag == "insert":
                result.extend(_strip_inherited(after[j], inherited) for j in range(j1, j2))
        return result
    return _copy(after)


def conform(file_value: Any, running: Any, key: str = "") -> Any:
    """The file made to agree with `running` (adopt running): values that differ take the running
    value, keys absent at runtime go, defaults config-get adds stay out of the file."""
    if isinstance(file_value, dict) and isinstance(running, dict):
        out: dict[str, Any] = {}
        for k, v in file_value.items():
            if not key and k in KEA_IGNORED_TOP:
                out[k] = _copy(v)
            elif k == "comment" and "comment" not in running:
                rc = (running.get("user-context") or {}).get("comment")
                if rc is not None:
                    out[k] = rc
            elif k == "control-socket" and k not in running and "control-sockets" in running:
                if not list(_kea_diff([v], running["control-sockets"], "", k)):
                    out[k] = _copy(v)
                else:
                    out["control-sockets"] = _copy(running["control-sockets"])
            elif k in running:
                out[k] = conform(v, running[k], k)
        return out
    if isinstance(file_value, list) and isinstance(running, list) and _identified(key, file_value, running):
        pairs, _, only_running = pair_items(key, file_value, running)
        kept = [conform(file_value[i], running[j], key) for i, j in pairs]
        return kept + [_copy(running[j]) for j in only_running]
    if isinstance(file_value, list) and isinstance(running, list) and len(file_value) == len(running):
        return [conform(a, b, key) for a, b in zip(file_value, running, strict=True)]
    if not isinstance(file_value, dict | list) and same_scalar(key, file_value, running):
        return _copy(file_value)
    return _copy(running)


def conform_root(file_config: dict[str, Any], running_body: dict[str, Any], root: str) -> dict[str, Any]:
    """`conform` on the root object (`{"Dhcp4": {...}}`), other top-level keys kept."""
    out = _copy(file_config)
    out[root] = conform(file_config.get(root) or {}, running_body)
    return out


def rebase_root(
    file_config: dict[str, Any], before_body: dict[str, Any], after_body: dict[str, Any], root: str
) -> dict[str, Any]:
    out = _copy(file_config)
    globals_ = {k: v for k, v in after_body.items() if not isinstance(v, dict | list)}
    for lifetime in ("valid-lifetime", "preferred-lifetime"):
        # Bounds a server does not set are derived from the lifetime and copied down by config-get.
        for bound in (f"min-{lifetime}", f"max-{lifetime}"):
            if lifetime in after_body and bound not in after_body:
                globals_[bound] = after_body[lifetime]
    out[root] = rebase(file_config.get(root) or {}, before_body, after_body, "", globals_)
    return out


# Secrets config-get hides --------------------------------------------------------------------------

# Siblings naming the object a secret belongs to (a TSIG key, an HA peer, a control socket user).
_SECRET_OWNER_KEYS = (*_ITEM_KEYS, "user")


def _secret_owner(obj: dict[str, Any]) -> str:
    for k in _SECRET_OWNER_KEYS:
        v = obj.get(k)
        if v is not None and not isinstance(v, dict | list) and not is_sensitive_kea_key(k):
            return f"{k}={v!r}"
    return ""


def _clear_secrets(value: Any, out: dict[tuple[str, str], set[str]]) -> None:
    if isinstance(value, list):
        for v in value:
            _clear_secrets(v, out)
    elif isinstance(value, dict):
        owner = _secret_owner(value)
        for k, v in value.items():
            if is_sensitive_kea_key(k) and isinstance(v, str):
                if v not in KEA_REDACTED:
                    out.setdefault((k, owner), set()).add(v)
            else:
                _clear_secrets(v, out)


def restore_secrets(target: Any, clear: list[Any], known: Any) -> list[str]:
    """Puts clear secrets back into `target` (in place), matched by key and owner (`name`, `user`...).

    `clear` holds what was just applied (a plan's values): it wins wherever it names the owner.
    `known` (the file) only fills values config-get masked. Returns the paths still masked: writing
    them would replace a real secret with `*****`.
    """
    applied: dict[tuple[str, str], set[str]] = {}
    for value in clear:
        _clear_secrets(value, applied)
    filed: dict[tuple[str, str], set[str]] = {}
    _clear_secrets(known, filed)
    missing: list[str] = []

    def walk(value: Any, path: str) -> None:
        if isinstance(value, list):
            for i, v in enumerate(value):
                walk(v, f"{path}[{i}]")
            return
        if not isinstance(value, dict):
            return
        owner = _secret_owner(value)
        for k, v in value.items():
            if not (is_sensitive_kea_key(k) and isinstance(v, str)):
                walk(v, f"{path}/{k}")
                continue
            for source, only_masked in ((applied, False), (filed, True)):
                found = source.get((k, owner), set())
                # Ownerless secrets are only ever filled in, never replaced: the match is too loose.
                if len(found) == 1 and (v in KEA_REDACTED or not (only_masked or owner == "")):
                    value[k] = v = next(iter(found))
                    break
            if v in KEA_REDACTED:
                missing.append(f"{path}/{k}")

    walk(target, "")
    return missing
