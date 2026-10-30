# SPDX-License-Identifier: Apache-2.0
"""Engine packages of section 29: rows from the advisories snapshots, the rollout's packages."""

from __future__ import annotations

import pytest

from pelagos.core import engine_packages as ep

pytestmark = pytest.mark.unit


def _snap(name: str, installed: str, candidate: str | None, manager: str = "deb", cves=None):
    return {
        "version": installed,
        "package": {"manager": manager, "name": name, "installed": installed, "candidate": candidate},
        "cves": cves or {},
    }


def test_rows_from_the_advisories_snapshots() -> None:
    rows = ep.engine_rows(
        "n1",
        {
            "bind": _snap(
                "bind9", "1:9.20.11-4", "1:9.20.15-1~deb13u1", cves={"CVE-1": "update", "CVE-2": "fixed"}
            ),
            "kea4": _snap("kea-dhcp4-server", "2.6.3-1", "2.6.3-1"),
            "kea6": {"package": None},
        },
    )
    assert rows == [
        {"node_id": "n1", "engine": "bind", "package": "bind9", "installed": "1:9.20.11-4",
         "candidate": "1:9.20.15-1~deb13u1", "cves": ["CVE-1"]},
        {"node_id": "n1", "engine": "kea4", "package": "kea-dhcp4-server", "installed": "2.6.3-1",
         "candidate": None, "cves": []},
    ]  # fmt: skip


def test_rpm_candidate_is_the_version_release_of_the_nevra() -> None:
    assert ep.rpm_version("bind-32:9.18.33-1.el10_0.x86_64", "bind") == "32:9.18.33-1.el10_0"
    snap = _snap("kea", "2.6.3-1.el10", "kea-2.6.4-1.el10.aarch64", manager="rpm")
    assert ep.candidate_of(snap["package"]) == "2.6.4-1.el10"


def test_rollout_packages_and_refusals() -> None:
    rows = [
        {"node_id": "n1", "package": "bind9", "installed": "1:9.20.11-4", "candidate": "1:9.20.15-1~deb13u1"},
        {"node_id": "n2", "package": "bind9", "installed": "1:9.20.11-4", "candidate": "1:9.20.15-1~deb13u1"},
        {"node_id": "n1", "package": "kea-dhcp4-server", "installed": "2.6.3-1", "candidate": "3.0.2-1"},
        {"node_id": "n3", "package": "bind9", "installed": "1:9.18.33-1", "candidate": "1:9.18.41-1"},
    ]
    assert ep.rollout_packages(rows, ["bind9"], ["n2", "n1"]) == (
        {"bind9": "1:9.20.15-1~deb13u1"},
        ["n1", "n2"],
    )
    with pytest.raises(ep.EnginePackagesRefused, match="different candidates"):
        ep.rollout_packages(rows, ["bind9"])
    with pytest.raises(ep.EnginePackagesRefused, match="Kea migration"):
        ep.rollout_packages(rows, ["kea-dhcp4-server"])
    with pytest.raises(ep.EnginePackagesRefused, match="not a BIND or Kea"):
        ep.rollout_packages(rows, ["openssh-server"])
    with pytest.raises(ep.EnginePackagesRefused, match="no selected node"):
        ep.rollout_packages(rows, ["kea-dhcp6-server"])


def test_families_and_advisory_link() -> None:
    assert ep.families(["bind9-libs", "isc-kea-dhcp4", "kea", "bind"]) == {"bind", "kea"}
    assert ep.family_of("openssh-server") is None
    pkg = {"manager": "deb", "name": "bind9", "installed": "1:9.20.11-4", "candidate": "1:9.22.0-1"}
    assert ep.advisory_update("n1", pkg) is None  # another series: not from here
    pkg["candidate"] = "1:9.20.15-1~deb13u1"
    assert ep.advisory_update("n1", pkg)["packages"] == ["bind9"]


def test_upstream_of_package_and_rndc_versions() -> None:
    assert ep.upstream("1:9.20.30-1~deb13u1") == (9, 20, 30)
    assert ep.upstream("32:9.18.33-15.el10_2.1") == (9, 18, 33)
    assert ep.upstream("9.20.30-1~deb13u1-Debian (Stable Release) <id:> (none)") == (9, 20, 30)
