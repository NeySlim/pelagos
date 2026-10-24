# SPDX-License-Identifier: Apache-2.0
"""Distro detection and engine paths (section 3). Pure functions over /etc/os-release and the filesystem."""

from __future__ import annotations

import platform as _platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEBIAN_LIKE = {"debian", "ubuntu", "linuxmint", "pop", "raspbian"}
RHEL_LIKE = {"rhel", "rocky", "almalinux", "centos", "fedora", "ol"}
ARCH_LIKE = {"arch", "garuda", "cachyos", "manjaro", "endeavouros"}

SBIN_DIRS = ("/usr/sbin", "/usr/local/sbin", "/sbin")

# Ubuntu codenames the ISC Cloudsmith repositories publish, by VERSION_ID.
_UBUNTU_CODENAMES = {"20.04": "focal", "22.04": "jammy", "24.04": "noble", "26.04": "resolute"}
_DEBIAN_CODENAMES = {"11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}


@dataclass(slots=True, frozen=True)
class Distro:
    id: str
    like: str  # "debian" | "rhel" | "arch" | "unknown"
    version_id: str
    pretty_name: str
    codename: str = ""

    @property
    def is_debian(self) -> bool:
        return self.like == "debian"

    @property
    def is_rhel(self) -> bool:
        return self.like == "rhel"

    @property
    def major(self) -> str:
        return self.version_id.split(".")[0]

    @property
    def package_manager(self) -> str:
        if self.is_debian:
            return "apt"
        if self.is_rhel:
            return "dnf"
        return "unknown"

    @property
    def cloudsmith_distro(self) -> tuple[str, str]:
        """(distro, codename) query values of the ISC Cloudsmith config endpoints."""
        if self.is_debian:
            name = "ubuntu" if self.id == "ubuntu" else "debian"
            return name, self.codename
        if self.id == "fedora":
            return "fedora", self.major
        return "el", self.major


def parse_os_release(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip().strip('"').strip("'")
    return fields


def distro_from_fields(fields: dict[str, str]) -> Distro:
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
    version_id = fields.get("VERSION_ID", "")
    codename = fields.get("VERSION_CODENAME", "") or fields.get("UBUNTU_CODENAME", "")
    if not codename and like == "debian":
        table = _UBUNTU_CODENAMES if distro_id == "ubuntu" else _DEBIAN_CODENAMES
        codename = table.get(version_id, "")
    return Distro(distro_id, like, version_id, fields.get("PRETTY_NAME", distro_id), codename)


def detect_distro(os_release: Path = Path("/etc/os-release")) -> Distro:
    text = os_release.read_text() if os_release.exists() else ""
    return distro_from_fields(parse_os_release(text))


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
    # Port of the statistics-channel Pelagos adds: 8953 on RHEL is already labelled
    # rndc_port_t for SELinux, 8053 is the usual choice elsewhere.
    bind_stats_port: int = 8053
    bind_checkconf: str = "named-checkconf"
    selinux: bool = False
    systemd_dir: Path = Path("/etc/systemd/system")

    @property
    def rndc_conf_pelagos(self) -> Path:
        return self.bind_include_dir / "rndc-pelagos.conf"

    @property
    def pelagos_conf(self) -> Path:
        return self.bind_include_dir / "pelagos.conf"

    @property
    def options_conf(self) -> Path:
        return self.bind_include_dir / "options.conf"

    @property
    def keys_conf(self) -> Path:
        return self.bind_include_dir / "keys.conf"

    @property
    def stats_url(self) -> str:
        return f"http://127.0.0.1:{self.bind_stats_port}/json/v1"

    def kea_conf(self, daemon: str) -> Path:
        """`daemon` is kea-dhcp4, kea-dhcp6, kea-dhcp-ddns or kea-ctrl-agent."""
        return self.kea_conf_dir / f"{daemon}.conf"

    def kea_socket(self, engine: str) -> Path:
        name = {"kea4": "kea4-ctrl-socket", "kea6": "kea6-ctrl-socket", "d2": "kea-ddns-ctrl-socket"}[engine]
        return self.kea_socket_dir / name

    def kea_service(self, engine: str, isc: bool) -> str:
        return (self.kea_services_isc if isc else self.kea_services_distro)[engine]

    def kea_service_candidates(self, engine: str) -> list[str]:
        """Unit names a Kea daemon may have here, most likely first; detection picks the one that exists."""
        names = [self.kea_services_isc[engine], self.kea_services_distro[engine]]
        short = {"kea4": "kea-dhcp4", "kea6": "kea-dhcp6", "d2": "kea-dhcp-ddns"}[engine]
        for extra in (f"isc-{short}.service", f"{short}.service", f"{short}-server.service"):
            if extra not in names:
                names.append(extra)
        return names

    def kea_packages_for(self, engines: list[str], isc: bool) -> list[str]:
        """Packages providing the requested Kea daemons (and the hooks Pelagos loads)."""
        kea = [e for e in engines if e in KEA_DAEMONS]
        if not kea:
            return []
        if isc:
            names = {"kea4": "isc-kea-dhcp4", "kea6": "isc-kea-dhcp6", "d2": "isc-kea-dhcp-ddns"}
            return [names[e] for e in kea] + ["isc-kea-hooks"]
        if "kea-dhcp4-server" in self.kea_packages_distro:
            names = {"kea4": "kea-dhcp4-server", "kea6": "kea-dhcp6-server", "d2": "kea-dhcp-ddns-server"}
            return [names[e] for e in kea]
        return list(self.kea_packages_distro)


KEA_DAEMONS: dict[str, str] = {"kea4": "kea-dhcp4", "kea6": "kea-dhcp6", "d2": "kea-dhcp-ddns"}
ENGINES: tuple[str, ...] = ("bind", "kea4", "kea6", "d2")


def _hooks_dir(like: str) -> Path:
    machine = _platform.machine() or "x86_64"
    if like == "rhel":
        return Path("/usr/lib64/kea/hooks")
    if like == "debian":
        return Path(f"/usr/lib/{machine}-linux-gnu/kea/hooks")
    return Path("/usr/lib/kea/hooks")


def selinux_enforcing() -> bool:
    try:
        return Path("/sys/fs/selinux/enforce").read_text().strip() == "1"
    except OSError:
        return False


def platform_paths(distro: Distro, selinux: bool | None = None) -> PlatformPaths:
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
            kea_packages_distro=("kea", "kea-hooks"),
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
            bind_stats_port=8953,
            selinux=selinux_enforcing() if selinux is None else selinux,
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
            bind_stats_port=8053,
            selinux=False if selinux is None else selinux,
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
        bind_stats_port=8053,
        selinux=False if selinux is None else selinux,
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
