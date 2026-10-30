# SPDX-License-Identifier: Apache-2.0
"""Engine packages of section 29 (design 13.6, decision 9): BIND and Kea packages of the
distribution, updated within their series by a rollout of kind `engine_packages`.

Pure helpers shared by the web process (the `engines` rows and the plan of `/admin/updates`), the
collector (which packages of a rollout touch BIND or Kea) and the security advisories (the link
from `security_advisory`). A change of Kea series goes through the migration of 13.4, never here.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pelagos.collector.checks.versions import version_tuple

BIND = "bind"
KEA = "kea"
# Engines whose daemons a family of packages runs.
FAMILY_ENGINES = {BIND: ("bind",), KEA: ("kea4", "kea6", "d2")}


class EnginePackagesRefused(ValueError):
    """The selection cannot become an engine packages rollout (`400 validation_error`)."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


def family_of(package: str) -> str | None:
    """`bind` or `kea` for a BIND or Kea package name of any supported distribution."""
    name = package.lower()
    if "kea" in name:
        return KEA
    if name.startswith("bind"):
        return BIND
    return None


def families(packages: Iterable[str]) -> set[str]:
    return {f for f in (family_of(p) for p in packages) if f}


def upstream(version: str | None) -> tuple[int, ...] | None:
    """Upstream release of a deb or rpm version ("1:9.20.15-1~deb13u1", "32:9.18.33-1.el10")."""
    if not version:
        return None
    return version_tuple(version.split(":", 1)[-1])


def series(version: str | None) -> tuple[int, ...] | None:
    up = upstream(version)
    return up[:2] if up and len(up) >= 2 else None


def rpm_version(candidate: str, name: str) -> str:
    """`dnf updateinfo` names a package by NEVRA ("bind-32:9.18.33-1.el10.x86_64"): the
    `[epoch:]version-release` part, what `dnf upgrade name-<that>` takes."""
    text = candidate.removeprefix(f"{name}-")
    head, dot, arch = text.rpartition(".")
    if dot and arch in ("x86_64", "aarch64", "noarch", "i686", "ppc64le", "s390x"):
        text = head
    return text


def candidate_of(package: dict[str, Any] | None) -> str | None:
    """The candidate version a rollout installs for a `distro.Package` dict, None when the
    installed one is already the newest."""
    if not isinstance(package, dict):
        return None
    candidate, installed = package.get("candidate"), package.get("installed")
    if not candidate:
        return None
    if package.get("manager") == "rpm":
        candidate = rpm_version(str(candidate), str(package.get("name") or ""))
    return None if candidate == installed else str(candidate)


def engine_rows(node_id: str, snapshots: dict[str, Any]) -> list[dict[str, Any]]:
    """The `engines` rows of `GET /admin/updates` for one node, from its `advisories` snapshots
    ({engine: payload} as the collector writes them): installed, candidate, and the CVEs the
    candidate fixes (verdict `update`)."""
    rows = []
    for engine in ("bind", "kea4", "kea6"):
        payload = snapshots.get(engine)
        if not isinstance(payload, dict):
            continue
        pkg = payload.get("package")
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        cves = payload.get("cves") if isinstance(payload.get("cves"), dict) else {}
        rows.append(
            {
                "node_id": node_id,
                "engine": engine,
                "package": str(pkg["name"]),
                "installed": pkg.get("installed"),
                "candidate": candidate_of(pkg),
                "cves": sorted(c for c, status in cves.items() if status == "update"),
            }
        )
    return rows


def advisory_update(node_id: str, package: dict[str, Any] | None) -> dict[str, Any] | None:
    """`details.update` of a `security_advisory` alert whose fix is a candidate package: what the
    Updates screen preselects in its engine packages tab."""
    candidate = candidate_of(package)
    if candidate is None or not isinstance(package, dict):
        return None
    if series(candidate) != series(package.get("installed")):
        return None
    return {
        "kind": "engine_packages",
        "packages": [str(package["name"])],
        "node_ids": [node_id],
        "candidate": candidate,
    }


def rollout_packages(
    rows: list[dict[str, Any]], packages: Iterable[str], node_ids: Iterable[str] | None = None
) -> tuple[dict[str, str], list[str]]:
    """({package: version}, nodes) of an engine packages rollout over the selected `rows`.

    Refused: a package no selected node can update, two candidates of one package (nodes on
    different releases of the distribution: one rollout per release), a change of series."""
    wanted = list(dict.fromkeys(packages))
    if not wanted:
        raise EnginePackagesRefused("packages", "no package selected")
    nodes = set(node_ids) if node_ids is not None else None
    chosen: dict[str, str] = {}
    order: list[str] = []
    for name in wanted:
        if family_of(name) is None:
            raise EnginePackagesRefused("packages", f"{name} is not a BIND or Kea package")
        hits = [
            r
            for r in rows
            if r.get("package") == name and r.get("candidate") and (nodes is None or r["node_id"] in nodes)
        ]
        if not hits:
            raise EnginePackagesRefused("packages", f"no selected node has an update of {name}")
        versions = {str(r["candidate"]) for r in hits}
        if len(versions) > 1:
            raise EnginePackagesRefused(
                "packages",
                f"{name} has different candidates ({', '.join(sorted(versions))}): one rollout per"
                " release of the distribution",
            )
        version = versions.pop()
        for r in hits:
            if series(version) != series(r.get("installed")):
                raise EnginePackagesRefused(
                    "packages",
                    f"{name} {r.get('installed')} to {version} changes series: the Kea migration does that",
                )
            if r["node_id"] not in order:
                order.append(r["node_id"])
        chosen[name] = version
    return chosen, order


def summary(packages: dict[str, str]) -> str:
    return ", ".join(f"{n} {v}" for n, v in sorted(packages.items()))
