# SPDX-License-Identifier: Apache-2.0
"""Package managers (apt, dnf) and the ISC Cloudsmith Kea repositories."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pelagos.platform.distro import Distro

CLOUDSMITH = "https://dl.cloudsmith.io/public/isc"
ISC_SERIES_DEFAULT = "3.2"
_SERIES_RE = re.compile(r"^\d+\.\d+$")


def isc_repo_name(series: str) -> str:
    """Cloudsmith repository of one Kea series: "3.2" -> "kea-3-2"."""
    if not _SERIES_RE.match(series):
        raise ValueError(f"invalid Kea series {series!r}, expected MAJOR.MINOR such as 3.2")
    return "kea-" + series.replace(".", "-")


@dataclass(slots=True, frozen=True)
class RepoFile:
    """A file to lay down for a repository: either literal content or a URL fetched at apply time."""

    path: Path
    content: str | None = None
    url: str | None = None
    mode: int = 0o644


def isc_repo_files(distro: Distro, series: str) -> list[RepoFile]:
    """The keyring and source list (apt) or the .repo file (dnf) of the ISC Kea repository."""
    repo = isc_repo_name(series)
    base = f"{CLOUDSMITH}/{repo}"
    name, codename = distro.cloudsmith_distro
    if distro.is_debian:
        if not codename:
            raise ValueError(f"no release codename known for {distro.pretty_name}")
        keyring = Path(f"/etc/apt/keyrings/isc-{repo}.asc")
        line = f"deb [signed-by={keyring}] {base}/deb/{name} {codename} main\n"
        return [
            RepoFile(keyring, url=f"{base}/gpg.key"),
            RepoFile(
                Path(f"/etc/apt/sources.list.d/isc-{repo}.list"),
                content="# pelagos:managed v1 (ISC Kea packages)\n" + line,
            ),
        ]
    if distro.is_rhel:
        sections = []
        for suffix, arch in (("", "$basearch"), ("-noarch", "noarch")):
            sections.append(
                f"[isc-{repo}{suffix}]\n"
                f"name=isc-{repo}{suffix}\n"
                f"baseurl={base}/rpm/{name}/{codename}/{arch}\n"
                "repo_gpgcheck=1\n"
                "enabled=1\n"
                f"gpgkey={base}/gpg.key\n"
                "gpgcheck=1\n"
                "sslverify=1\n"
                "metadata_expire=300\n"
                "type=rpm-md\n"
            )
        return [
            RepoFile(
                Path(f"/etc/yum.repos.d/isc-{repo}.repo"),
                content="# pelagos:managed v1 (ISC Kea packages)\n" + "\n".join(sections),
            )
        ]
    raise ValueError(
        f"ISC repositories are published for Debian, Ubuntu and RHEL-like systems only, not {distro.id}"
    )


class PackageManager:
    """apt-get / dnf behind one interface; every mutation goes through the runner (sudo, dry-run)."""

    def __init__(self, distro: Distro, runner: Any) -> None:
        self.distro = distro
        self.runner = runner

    @property
    def kind(self) -> str:
        return self.distro.package_manager

    def refresh(self) -> str:
        if self.kind == "apt":
            return self.runner.run(["apt-get", "update", "-q"], privileged=True, timeout=600).output
        if self.kind == "dnf":
            return self.runner.run(["dnf", "-q", "makecache"], privileged=True, timeout=600).output
        raise RuntimeError(f"no package manager for {self.distro.id}")

    def install(self, packages: list[str], replace: bool = False) -> str:
        """`replace`: conflicting packages may be removed (apt does it with -y, dnf needs --allowerasing)."""
        if not packages:
            return "nothing to install"
        if self.kind == "apt":
            argv = ["apt-get", "install", "-y", "-q", "-o", "Dpkg::Options::=--force-confold", *packages]
        elif self.kind == "dnf":
            argv = ["dnf", "install", "-y", "-q", *(["--allowerasing"] if replace else []), *packages]
        else:
            raise RuntimeError(f"no package manager for {self.distro.id}")
        return (
            self.runner.run(argv, privileged=True, timeout=1800).output or f"installed {' '.join(packages)}"
        )

    def installed_version(self, package: str) -> str | None:
        if self.kind == "apt":
            argv = ["dpkg-query", "-W", "-f=${Status}|${Version}", package]
        elif self.kind == "dnf":
            argv = ["rpm", "-q", "--qf", "installed|%{VERSION}-%{RELEASE}", package]
        else:
            return None
        res = self.runner.run(argv, check=False, mutates=False, timeout=30)
        if not res.ok:
            return None
        status, _, version = res.stdout.strip().partition("|")
        if self.kind == "apt" and not status.endswith(" installed"):
            return None
        return version or None

    def is_installed(self, package: str) -> bool:
        return self.installed_version(package) is not None

    def available(self, package: str) -> bool:
        """Whether the configured repositories offer the package (read-only query)."""
        if self.kind == "apt":
            res = self.runner.run(["apt-cache", "show", package], check=False, mutates=False, timeout=60)
            return res.ok and "Package:" in res.stdout
        if self.kind == "dnf":
            res = self.runner.run(
                ["dnf", "-q", "list", "--available", package], check=False, mutates=False, timeout=300
            )
            return res.ok and package in res.stdout
        return False
