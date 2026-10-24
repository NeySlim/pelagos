# SPDX-License-Identifier: Apache-2.0
"""Detect installed engines, versions, services and configuration files (GET /install/detect)."""

from __future__ import annotations

import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pelagos.platform import Distro, PlatformPaths, detect_distro, find_binary, platform_paths


@dataclass(slots=True)
class EngineDetection:
    installed: bool = False
    binary: str | None = None
    version: str | None = None
    service: str | None = None
    running: bool | None = None
    config: str | None = None
    config_exists: bool = False
    paths: dict[str, str] = field(default_factory=dict)


def _version(binary: str, flag: str) -> str | None:
    try:
        out = subprocess.run([binary, flag], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    text = (out.stdout or out.stderr).strip()
    m = re.search(r"(\d+\.\d+\.\d+)", text)
    return m.group(1) if m else text.splitlines()[0] if text else None


def _service_active(unit: str) -> bool | None:
    systemctl = find_binary("systemctl")
    if not systemctl:
        return None
    try:
        out = subprocess.run(
            [systemctl, "is-active", unit], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() == "active"


def detect_bind(paths: PlatformPaths) -> EngineDetection:
    binary = find_binary("named")
    det = EngineDetection(installed=binary is not None, binary=binary, service=paths.bind_service)
    if binary:
        det.version = _version(binary, "-v")
        det.running = _service_active(paths.bind_service)
    det.config = str(paths.named_conf)
    det.config_exists = paths.named_conf.exists()
    det.paths = {
        "zone_dir": str(paths.zone_dir),
        "rndc_key": str(paths.rndc_key),
        "include_dir": str(paths.bind_include_dir),
        "user": paths.bind_user,
        "group": paths.bind_group,
    }
    return det


def detect_kea(paths: PlatformPaths, daemon: str) -> EngineDetection:
    binary = find_binary(daemon)
    key = {"kea-dhcp4": "kea4", "kea-dhcp6": "kea6", "kea-dhcp-ddns": "d2"}[daemon]
    conf = paths.kea_conf_dir / f"{daemon}.conf"
    isc = Path("/etc/apt/sources.list.d").glob("isc-kea*") if Path("/etc/apt/sources.list.d").exists() else []
    service = paths.kea_services_isc[key] if any(True for _ in isc) else paths.kea_services_distro[key]
    det = EngineDetection(installed=binary is not None, binary=binary, service=service)
    if binary:
        det.version = _version(binary, "-v")
        det.running = _service_active(service)
    det.config = str(conf)
    det.config_exists = conf.exists()
    det.paths = {
        "socket_dir": str(paths.kea_socket_dir),
        "hooks_dir": str(paths.kea_hooks_dir),
        "lease_dir": str(paths.kea_lease_dir),
        "user": paths.kea_user,
        "group": paths.kea_group,
    }
    return det


def detect_all(distro: Distro | None = None) -> dict[str, Any]:
    distro = distro or detect_distro()
    paths = platform_paths(distro)
    return {
        "distro": asdict(distro),
        "engines": {
            "bind": asdict(detect_bind(paths)),
            "kea4": asdict(detect_kea(paths, "kea-dhcp4")),
            "kea6": asdict(detect_kea(paths, "kea-dhcp6")),
            "d2": asdict(detect_kea(paths, "kea-dhcp-ddns")),
        },
        "pelagos": {"include_present": None, "sockets_ok": None, "keys_present": None},  # WP-INSTALLER
    }
