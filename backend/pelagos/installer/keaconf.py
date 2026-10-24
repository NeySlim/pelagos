# SPDX-License-Identifier: Apache-2.0
"""Kea configuration files and control sockets as the installer sees them.

Kea accepts comments (`//`, `#`, `/* */`) and `<?include?>` in its JSON files;
`config-get` is the authoritative view when a daemon runs (section 9). The
installer only needs to read a file, add a control socket or a TSIG key, and
write it back as canonical JSON, which is what `config-write` would do anyway.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
from pathlib import Path
from typing import Any

DAEMON_KEYS: dict[str, str] = {
    "kea-dhcp4": "Dhcp4",
    "kea-dhcp6": "Dhcp6",
    "kea-dhcp-ddns": "DhcpDdns",
    "kea-ctrl-agent": "Control-agent",
}
ENGINE_DAEMONS: dict[str, str] = {"kea4": "kea-dhcp4", "kea6": "kea-dhcp6", "d2": "kea-dhcp-ddns"}
WEAK_TSIG = frozenset({"hmac-md5", "hmac-sha1"})

_INCLUDE_RE = re.compile(r"<\?include\s+\"([^\"]+)\"\s*\?>")


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
    return bool(_INCLUDE_RE.search(text))


def loads(text: str, path: str | None = None) -> dict[str, Any]:
    """Parses a Kea config file; `<?include?>` directives are refused (the daemon resolves them)."""
    if has_include(text):
        raise KeaConfigError(f"{path or 'config'} uses <?include?>, which the installer does not rewrite")
    try:
        data = json.loads(strip_trailing_commas(strip_comments(text)))
    except json.JSONDecodeError as exc:
        raise KeaConfigError(f"{path or 'config'}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise KeaConfigError(f"{path or 'config'}: top level is not an object")
    return data


def dumps(config: dict[str, Any]) -> str:
    return json.dumps(config, indent=2) + "\n"


def root_key(config: dict[str, Any]) -> str:
    for key in DAEMON_KEYS.values():
        if key in config:
            return key
    raise KeaConfigError(f"no Dhcp4/Dhcp6/DhcpDdns/Control-agent object (keys: {sorted(config)})")


def version_tuple(version: str | None) -> tuple[int, ...]:
    if not version:
        return (0,)
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version)
    if not m:
        return (0,)
    return tuple(int(g) for g in m.groups() if g is not None)


def supports_control_sockets(version: str | None) -> bool:
    """`control-sockets` (list) exists since Kea 2.7.2; 3.3.1 drops the singular form."""
    return version_tuple(version) >= (2, 7, 2)


def supports_secret_file(version: str | None) -> bool:
    """D2 `secret-file` arrived in Kea 2.7; 3.x refuses a clear `secret`."""
    return version_tuple(version) >= (2, 7, 0)


def control_socket_path(config: dict[str, Any], default_dir: Path) -> Path | None:
    """The Unix control socket a daemon config declares, resolved against the socket directory."""
    body = config[root_key(config)]
    entries: list[dict[str, Any]] = []
    single = body.get("control-socket")
    if isinstance(single, dict):
        entries.append(single)
    many = body.get("control-sockets")
    if isinstance(many, list):
        entries.extend(e for e in many if isinstance(e, dict))
    for e in entries:
        if e.get("socket-type", "unix") == "unix" and e.get("socket-name"):
            name = Path(str(e["socket-name"]))
            return name if name.is_absolute() else default_dir / name
    return None


def http_listeners(config: dict[str, Any]) -> list[dict[str, Any]]:
    """HTTP/HTTPS control sockets (2.7.2+) and the Control Agent listener, as plain dicts."""
    body = config[root_key(config)]
    out: list[dict[str, Any]] = []
    if root_key(config) == "Control-agent":
        out.append(
            {
                "socket-type": "https" if body.get("cert-file") else "http",
                "socket-address": body.get("http-host", "127.0.0.1"),
                "socket-port": body.get("http-port", 8000),
                "trust-anchor": body.get("trust-anchor"),
                "cert-required": body.get("cert-required", True),
                "authentication": body.get("authentication"),
            }
        )
    for e in body.get("control-sockets", []) or []:
        if isinstance(e, dict) and e.get("socket-type") in ("http", "https"):
            out.append(dict(e))
    return out


def set_control_socket(config: dict[str, Any], socket_path: Path, version: str | None) -> dict[str, Any]:
    """Returns a copy with a Unix control socket, in the form the running version prefers."""
    new = json.loads(json.dumps(config))
    body = new[root_key(new)]
    entry = {"socket-type": "unix", "socket-name": str(socket_path)}
    if supports_control_sockets(version):
        existing = body.get("control-sockets")
        if isinstance(existing, list):
            body["control-sockets"] = [e for e in existing if e.get("socket-type") != "unix"] + [entry]
        else:
            body["control-sockets"] = [entry]
        body.pop("control-socket", None)
    else:
        body["control-socket"] = entry
    return new


def tsig_keys(d2_config: dict[str, Any]) -> list[dict[str, Any]]:
    return list(d2_config.get("DhcpDdns", {}).get("tsig-keys", []) or [])


def domains_using_key(d2_config: dict[str, Any], key_name: str) -> list[tuple[str, str]]:
    """(direction, domain) pairs whose `key-name` is `key_name`, server-level keys included."""
    body = d2_config.get("DhcpDdns", {})
    out: list[tuple[str, str]] = []
    for direction in ("forward-ddns", "reverse-ddns"):
        for dom in (body.get(direction) or {}).get("ddns-domains", []) or []:
            if dom.get("key-name") == key_name or any(
                s.get("key-name") == key_name for s in dom.get("dns-servers", []) or []
            ):
                out.append((direction, dom.get("name", "")))
    return out


def rename_key(d2_config: dict[str, Any], old: str, new_entry: dict[str, Any]) -> dict[str, Any]:
    """Copy with the old tsig-key replaced by `new_entry` and every `key-name` reference updated."""
    cfg = json.loads(json.dumps(d2_config))
    body = cfg["DhcpDdns"]
    body["tsig-keys"] = [k for k in body.get("tsig-keys", []) if k.get("name") != old] + [new_entry]
    new = new_entry["name"]
    for direction in ("forward-ddns", "reverse-ddns"):
        for dom in (body.get(direction) or {}).get("ddns-domains", []) or []:
            if dom.get("key-name") == old:
                dom["key-name"] = new
            for s in dom.get("dns-servers", []) or []:
                if s.get("key-name") == old:
                    s["key-name"] = new
    return cfg


def send_command(
    sock_path: Path, command: str, arguments: dict[str, Any] | None = None, timeout: float = 10.0
) -> dict[str, Any]:
    """One request, one response over the Unix control socket."""
    payload: dict[str, Any] = {"command": command}
    if arguments is not None:
        payload["arguments"] = arguments
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(sock_path))
        s.sendall(json.dumps(payload).encode())
        buf = bytearray()
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf.extend(chunk)
            try:
                return json.loads(buf.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
    return json.loads(buf.decode())


def socket_alive(sock_path: Path) -> bool:
    try:
        return send_command(sock_path, "status-get").get("result") == 0
    except (OSError, ValueError):
        return False


def daemon_version_from_text(text: str) -> str | None:
    """First x.y.z in `-v` output ("3.2.1", "BIND 9.20.30-1~deb13u1-Debian ...")."""
    m = re.search(r"(\d+\.\d+\.\d+)", text or "")
    return m.group(1) if m else None


def daemon_version(binary: str, timeout: float = 10.0) -> str | None:
    try:
        out = subprocess.run([binary, "-v"], capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return daemon_version_from_text((out.stdout or out.stderr).strip())


def hooks_available(hooks_dir: Path) -> list[str]:
    """Hook names (lease_cmds, ha, ...) present in the compiled-in hooks directory."""
    if not hooks_dir.is_dir():
        return []
    return sorted(p.name[len("libdhcp_") : -3] for p in hooks_dir.glob("libdhcp_*.so"))
