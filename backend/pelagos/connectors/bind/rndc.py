# SPDX-License-Identifier: Apache-2.0
"""rndc client: runs the rndc binary with an explicit configuration, never through a shell."""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorDenied, ConnectorError, ConnectorTimeout, ConnectorUnavailable
from pelagos.domain.dns import ZoneKind, ZoneStatus, normalize_name

SBIN_DIRS = ("/usr/sbin", "/usr/local/sbin")
DEFAULT_VIEW = "_default"


class RndcNotFound(ConnectorError):
    """rndc answered but the zone (or view) does not exist."""


def find_binary(name: str) -> str | None:
    """PATH first, then the sbin directories a non-root user usually lacks."""
    found = shutil.which(name)
    if found:
        return found
    for d in SBIN_DIRS:
        candidate = Path(d) / name
        if candidate.is_file():
            return str(candidate)
    return None


def zone_args(zone: str, view: str | None = None) -> list[str]:
    """`zone [class [view]]` as rndc wants it; the default view needs no view argument."""
    name = normalize_name(zone).rstrip(".") or "."
    if view and view != DEFAULT_VIEW:
        return [name, "IN", view]
    return [name]


class RndcClient:
    def __init__(
        self,
        conf_path: Path | None,
        server: str = "127.0.0.1",
        port: int = 953,
        binary: str | None = None,
        timeout: float = 15.0,
        key_path: Path | None = None,
    ) -> None:
        self.conf_path = conf_path
        self.key_path = key_path
        self.server = server
        self.port = port
        self.binary = binary or find_binary("rndc")
        self.timeout = timeout

    def _auth_args(self) -> list[str]:
        # Our own rndc.conf when it exists, else the server's rndc.key (section 10).
        if self.conf_path is not None and self.conf_path.exists():
            return ["-c", str(self.conf_path)]
        if self.key_path is not None:
            return ["-k", str(self.key_path)]
        return ["-c", str(self.conf_path)] if self.conf_path is not None else []

    def run(self, *args: str) -> str:
        if not self.binary:
            raise ConnectorUnavailable("rndc binary not found")
        cmd = [self.binary, *self._auth_args(), "-s", self.server, "-p", str(self.port), *args]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ConnectorTimeout(f"rndc {' '.join(args)} timed out") from exc
        if proc.returncode != 0:
            err = (proc.stderr + proc.stdout).strip()
            low = err.lower()
            if "connection refused" in low or "connect failed" in low or "timed out" in low:
                raise ConnectorUnavailable(err)
            if "permission denied" in low or "no matching key" in low or "bad auth" in low:
                raise ConnectorDenied(err)
            if "not found" in low or "no matching zone" in low or "no matching view" in low:
                raise RndcNotFound(err)
            raise ConnectorError(err or f"rndc exited {proc.returncode}")
        return proc.stdout

    def status(self) -> dict[str, str]:
        return parse_kv(self.run("status"))

    def zonestatus(self, zone: str, view: str | None = None) -> dict[str, str]:
        return parse_kv(self.run("zonestatus", *zone_args(zone, view)))

    def dnssec_status(self, zone: str, view: str | None = None) -> str:
        return self.run("dnssec", "-status", *zone_args(zone, view))


def parse_kv(text: str) -> dict[str, str]:
    """`key: value` lines of rndc status / zonestatus; repeated keys are joined with newlines."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        out[key] = (out[key] + "\n" + value) if key in out else value
    return out


def parse_rndc_time(value: str | None) -> datetime | None:
    """`Sat, 24 Oct 2026 12:29:37 GMT` (rndc status/zonestatus) as aware UTC."""
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)


def _yes(value: str | None) -> bool | None:
    return None if value is None else value.strip().lower() == "yes"


def zone_status_from(zone: str, view: str | None, node_id: str, raw: dict[str, str]) -> ZoneStatus:
    kind: ZoneKind | None
    try:
        kind = ZoneKind.from_bind(raw["type"]) if raw.get("type") else None
    except ValueError:
        kind = None
    serial = raw.get("serial")
    return ZoneStatus(
        zone=normalize_name(zone),
        view=view or DEFAULT_VIEW,
        node_id=node_id,
        kind=kind,
        config_serial=int(serial) if serial and serial.isdigit() else None,
        dynamic=_yes(raw.get("dynamic")),
        signed=_yes(raw.get("secure")),
        files=[f for f in raw.get("files", "").split() if f],
        next_refresh=parse_rndc_time(raw.get("next refresh")),
        expires=parse_rndc_time(raw.get("expires")),
        last_loaded=parse_rndc_time(raw.get("last loaded")),
        raw=raw,
    )


_KEY_LINE = re.compile(r"^key:\s*(\d+)\s*\(([^)]+)\),\s*(.+)$")


def parse_dnssec_status(text: str) -> dict[str, Any]:
    """`rndc dnssec -status` output: policy, current time, keys with their states and rollover lines."""
    out: dict[str, Any] = {"policy": None, "signed": False, "current_time": None, "keys": [], "raw": text}
    if "does not have dnssec-policy" in text:
        return out
    key: dict[str, Any] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("dnssec-policy:"):
            out["policy"] = stripped.partition(":")[2].strip()
            out["signed"] = True
            continue
        if stripped.startswith("current time:"):
            out["current_time"] = stripped.partition(":")[2].strip()
            continue
        m = _KEY_LINE.match(stripped)
        if m:
            key = {
                "id": int(m.group(1)),
                "algorithm": m.group(2).strip(),
                "roles": [r.strip() for r in m.group(3).split(",")],
                "states": {},
                "notes": [],
            }
            out["keys"].append(key)
            continue
        if key is None:
            continue
        body = stripped.lstrip("- ").strip()
        if ":" in body:
            name, _, value = body.partition(":")
            key["states"][name.strip()] = value.strip()
        else:
            key["notes"].append(body)
    return out
