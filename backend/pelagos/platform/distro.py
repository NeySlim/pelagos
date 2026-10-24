# SPDX-License-Identifier: Apache-2.0
"""Distro detection and engine paths (section 3). Pure functions over /etc/os-release and the filesystem."""

from __future__ import annotations

import platform as _platform
import shutil
from dataclasses import dataclass
from pathlib import Path

DEBIAN_LIKE = {"debian", "ubuntu", "linuxmint", "pop", "raspbian"}
RHEL_LIKE = {"rhel", "rocky", "almalinux", "centos", "fedora", "ol"}
ARCH_LIKE = {"arch", "garuda", "cachyos", "manjaro", "endeavouros"}

SBIN_DIRS = ("/usr/sbin", "/usr/local/sbin", "/sbin")


@dataclass(slots=True, frozen=True)
class Distro:
    id: str
    like: str  # "debian" | "rhel" | "arch" | "unknown"
    version_id: str
    pretty_name: str

    @property
    def is_debian(self) -> bool:
        return self.like == "debian"

    @property
    def is_rhel(self) -> bool:
        return self.like == "rhel"


def detect_distro(os_release: Path = Path("/etc/os-release")) -> Distro:
    fields: dict[str, str] = {}
    if os_release.exists():
        for line in os_release.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                key, _, value = line.partition("=")
                fields[key.strip()] = value.strip().strip('"')
    distro_id = fields.get("ID", "unknown").lower()
    like_ids = {distro_id, *fields.get("ID_LIKE", "").lower().split()}
    if like_ids & DEBIAN_LIKE:
        like = "debian"
    elif like_ids & RHEL_LIKE:
        like = "rhel"
    elif like_ids & ARCH_LIKE:
        like = "arch"
    else:
        like = "unknown"
    return Distro(distro_id, like, fields.get("VERSION_ID", ""), fields.get("PRETTY_NAME", distro_id))


@dataclass(slots=True, frozen=True)
class PlatformPaths:
    """Reference engine paths for one distro family (table in section 3)."""

    bind_packages: tuple[str, ...]
    bind_service: str
    bind_user: str
    bind_group: str
    named_conf: Path
    zone_dir: Path
    rndc_key: Path
    bind_include_dir: Path
    bind_zone_dir_pelagos: Path
    kea_packages_distro: tuple[str, ...]
    kea_packages_isc: tuple[str, ...]
    kea_services_distro: dict[str, str]
    kea_services_isc: dict[str, str]
    kea_user: str
    kea_group: str
    kea_conf_dir: Path
    kea_socket_dir: Path
    kea_hooks_dir: Path
    kea_lease_dir: Path
    kea_log_dir: Path


def _hooks_dir(like: str) -> Path:
    machine = _platform.machine() or "x86_64"
    if like == "rhel":
        return Path("/usr/lib64/kea/hooks")
    if like == "debian":
        return Path(f"/usr/lib/{machine}-linux-gnu/kea/hooks")
    return Path("/usr/lib/kea/hooks")


def platform_paths(distro: Distro) -> PlatformPaths:
    isc_services = {
        "kea4": "isc-kea-dhcp4-server.service",
        "kea6": "isc-kea-dhcp6-server.service",
        "d2": "isc-kea-dhcp-ddns-server.service",
    }
    isc_packages = ("isc-kea-dhcp4", "isc-kea-dhcp6", "isc-kea-dhcp-ddns", "isc-kea-hooks")
    if distro.is_rhel:
        return PlatformPaths(
            bind_packages=("bind", "bind-utils"),
            bind_service="named.service",
            bind_user="named",
            bind_group="named",
            named_conf=Path("/etc/named.conf"),
            zone_dir=Path("/var/named"),
            rndc_key=Path("/etc/rndc.key"),
            bind_include_dir=Path("/etc/named/pelagos"),
            bind_zone_dir_pelagos=Path("/var/named/pelagos"),
            kea_packages_distro=("kea",),
            kea_packages_isc=isc_packages,
            kea_services_distro={
                "kea4": "kea-dhcp4.service",
                "kea6": "kea-dhcp6.service",
                "d2": "kea-dhcp-ddns.service",
            },
            kea_services_isc=isc_services,
            kea_user="kea",
            kea_group="kea",
            kea_conf_dir=Path("/etc/kea"),
            kea_socket_dir=Path("/run/kea"),
            kea_hooks_dir=_hooks_dir("rhel"),
            kea_lease_dir=Path("/var/lib/kea"),
            kea_log_dir=Path("/var/log/kea"),
        )
    if distro.is_debian:
        return PlatformPaths(
            bind_packages=("bind9", "bind9-utils", "bind9-dnsutils"),
            bind_service="named.service",
            bind_user="bind",
            bind_group="bind",
            named_conf=Path("/etc/bind/named.conf"),
            zone_dir=Path("/var/cache/bind"),
            rndc_key=Path("/etc/bind/rndc.key"),
            bind_include_dir=Path("/etc/bind/pelagos"),
            bind_zone_dir_pelagos=Path("/var/cache/bind/pelagos"),
            kea_packages_distro=("kea-dhcp4-server", "kea-dhcp6-server", "kea-dhcp-ddns-server", "kea-admin"),
            kea_packages_isc=isc_packages,
            kea_services_distro={
                "kea4": "kea-dhcp4-server.service",
                "kea6": "kea-dhcp6-server.service",
                "d2": "kea-dhcp-ddns-server.service",
            },
            kea_services_isc=isc_services,
            kea_user="_kea",
            kea_group="_kea",
            kea_conf_dir=Path("/etc/kea"),
            kea_socket_dir=Path("/run/kea"),
            kea_hooks_dir=_hooks_dir("debian"),
            kea_lease_dir=Path("/var/lib/kea"),
            kea_log_dir=Path("/var/log/kea"),
        )
    # Arch and unknown: used for development hosts only.
    return PlatformPaths(
        bind_packages=("bind",),
        bind_service="named.service",
        bind_user="named",
        bind_group="named",
        named_conf=Path("/etc/named.conf"),
        zone_dir=Path("/var/named"),
        rndc_key=Path("/etc/rndc.key"),
        bind_include_dir=Path("/etc/named/pelagos"),
        bind_zone_dir_pelagos=Path("/var/named/pelagos"),
        kea_packages_distro=("kea",),
        kea_packages_isc=isc_packages,
        kea_services_distro={
            "kea4": "kea-dhcp4.service",
            "kea6": "kea-dhcp6.service",
            "d2": "kea-dhcp-ddns.service",
        },
        kea_services_isc=isc_services,
        kea_user="kea",
        kea_group="kea",
        kea_conf_dir=Path("/etc/kea"),
        kea_socket_dir=Path("/run/kea"),
        kea_hooks_dir=_hooks_dir("arch"),
        kea_lease_dir=Path("/var/lib/kea"),
        kea_log_dir=Path("/var/log/kea"),
    )


def find_binary(name: str) -> str | None:
    """PATH first, then the sbin directories a non-root PATH usually lacks."""
    found = shutil.which(name)
    if found:
        return found
    for d in SBIN_DIRS:
        candidate = Path(d) / name
        if candidate.is_file():
            return str(candidate)
    return None


def find_kea_hooks_dir() -> Path | None:
    """The compiled-in hooks directory, from `kea-dhcp4 -W`, falling back to the distro default."""
    import subprocess

    binary = find_binary("kea-dhcp4")
    if binary:
        try:
            out = subprocess.run(
                [binary, "-W"], capture_output=True, text=True, timeout=10, check=False
            ).stdout
            for line in out.splitlines():
                if "Hooks directory:" in line:
                    path = Path(line.split(":", 1)[1].strip())
                    if path.is_dir():
                        return path
        except (OSError, subprocess.SubprocessError):
            pass
    for candidate in (_hooks_dir("debian"), _hooks_dir("rhel"), _hooks_dir("arch")):
        if candidate.is_dir():
            return candidate
    return None
