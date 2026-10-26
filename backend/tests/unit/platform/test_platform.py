# SPDX-License-Identifier: Apache-2.0
"""Distro detection from captured os-release files, engine paths, ISC repositories, runner, packages."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.platform import (
    CommandResult,
    CommandRunner,
    FakeRunner,
    PackageManager,
    ServiceManager,
    detect_distro,
    distro_from_fields,
    isc_repo_files,
    isc_repo_name,
    parse_os_release,
    platform_paths,
)

pytestmark = pytest.mark.unit

DATA = Path(__file__).parents[1] / "installer" / "data" / "os-release"

UBUNTU_2404 = """PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.3 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=noble
"""

ALMA_9 = """NAME="AlmaLinux"
VERSION="9.6 (Sage Margay)"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.6"
PRETTY_NAME="AlmaLinux 9.6 (Sage Margay)"
"""


def test_debian13_detection():
    d = detect_distro(DATA / "debian13")
    assert (d.id, d.like, d.version_id, d.codename) == ("debian", "debian", "13", "trixie")
    assert d.is_debian and d.package_manager == "apt"
    assert d.cloudsmith_distro == ("debian", "trixie")


def test_rocky10_detection():
    d = detect_distro(DATA / "rocky10")
    assert (d.id, d.like, d.version_id, d.major) == ("rocky", "rhel", "10.2", "10")
    assert d.is_rhel and d.package_manager == "dnf"
    assert d.cloudsmith_distro == ("el", "10")


def test_ubuntu_and_alma_from_text():
    u = distro_from_fields(parse_os_release(UBUNTU_2404))
    assert u.is_debian and u.codename == "noble" and u.cloudsmith_distro == ("ubuntu", "noble")
    a = distro_from_fields(parse_os_release(ALMA_9))
    assert a.is_rhel and a.major == "9" and a.cloudsmith_distro == ("el", "9")


def test_missing_os_release_is_unknown(tmp_path):
    d = detect_distro(tmp_path / "absent")
    assert d.like == "unknown" and d.package_manager == "unknown"


@pytest.mark.parametrize(
    ("machine", "triplet"),
    [
        ("x86_64", "x86_64-linux-gnu"),
        ("aarch64", "aarch64-linux-gnu"),
        ("armv7l", "arm-linux-gnueabihf"),
        ("i686", "i386-linux-gnu"),
        ("ppc64le", "powerpc64le-linux-gnu"),
        ("riscv64", "riscv64-linux-gnu"),
    ],
)
def test_debian_multiarch(machine, triplet):
    from pelagos.platform.distro import debian_multiarch

    assert debian_multiarch(machine) == triplet


def test_debian_hooks_dir_follows_the_host_architecture(monkeypatch):
    import sysconfig

    from pelagos.platform import distro

    monkeypatch.setattr(sysconfig, "get_config_var", lambda name: None)
    monkeypatch.setattr(distro._platform, "machine", lambda: "aarch64")
    deb = platform_paths(detect_distro(DATA / "debian13"))
    assert deb.kea_hooks_dir == Path("/usr/lib/aarch64-linux-gnu/kea/hooks")
    monkeypatch.setattr(sysconfig, "get_config_var", lambda name: "arm-linux-gnueabihf")
    assert platform_paths(detect_distro(DATA / "debian13")).kea_hooks_dir == Path(
        "/usr/lib/arm-linux-gnueabihf/kea/hooks"
    )


def test_paths_per_family():
    deb = platform_paths(detect_distro(DATA / "debian13"))
    rpm = platform_paths(detect_distro(DATA / "rocky10"), selinux=True)
    assert deb.named_conf == Path("/etc/bind/named.conf")
    assert deb.bind_include_dir == Path("/etc/bind/pelagos")
    assert deb.pelagos_conf == Path("/etc/bind/pelagos/pelagos.conf")
    assert (deb.kea_user, deb.bind_group) == ("_kea", "bind")
    assert rpm.named_conf == Path("/etc/named.conf") and rpm.rndc_key == Path("/etc/rndc.key")
    assert rpm.bind_include_dir == Path("/etc/named/pelagos")
    assert (rpm.kea_user, rpm.bind_group) == ("kea", "named")
    assert rpm.kea_hooks_dir == Path("/usr/lib64/kea/hooks")
    # SELinux lets named bind 8953 (rndc_port_t); 8053 elsewhere.
    assert rpm.bind_stats_port == 8953 and deb.bind_stats_port == 8053
    assert rpm.selinux is True
    assert deb.kea_socket("kea4") == Path("/run/kea/kea4-ctrl-socket")
    assert deb.kea_socket("d2") == Path("/run/kea/kea-ddns-ctrl-socket")


def test_kea_packages_and_units():
    deb = platform_paths(detect_distro(DATA / "debian13"))
    rpm = platform_paths(detect_distro(DATA / "rocky10"))
    assert deb.kea_packages_for(["bind", "kea4", "d2"], isc=False) == [
        "kea-dhcp4-server",
        "kea-dhcp-ddns-server",
    ]
    assert deb.kea_packages_for(["kea4", "kea6"], isc=True) == [
        "isc-kea-dhcp4",
        "isc-kea-dhcp6",
        "isc-kea-hooks",
    ]
    assert rpm.kea_packages_for(["kea4"], isc=False) == ["kea", "kea-hooks"]
    assert deb.kea_packages_for(["bind"], isc=True) == []
    cands = deb.kea_service_candidates("kea4")
    assert cands[:2] == ["isc-kea-dhcp4-server.service", "kea-dhcp4-server.service"]
    assert "kea-dhcp4.service" in cands
    assert rpm.kea_service("d2", isc=False) == "kea-dhcp-ddns.service"


def test_isc_repo_debian():
    d = detect_distro(DATA / "debian13")
    files = isc_repo_files(d, "3.2")
    assert [str(f.path) for f in files] == [
        "/etc/apt/keyrings/isc-kea-3-2.asc",
        "/etc/apt/sources.list.d/isc-kea-3-2.list",
    ]
    assert files[0].url == "https://dl.cloudsmith.io/public/isc/kea-3-2/gpg.key"
    assert (
        "deb [signed-by=/etc/apt/keyrings/isc-kea-3-2.asc] "
        "https://dl.cloudsmith.io/public/isc/kea-3-2/deb/debian trixie main"
    ) in files[1].content


def test_isc_repo_rocky():
    d = detect_distro(DATA / "rocky10")
    (repo,) = isc_repo_files(d, "3.0")
    assert str(repo.path) == "/etc/yum.repos.d/isc-kea-3-0.repo"
    assert "baseurl=https://dl.cloudsmith.io/public/isc/kea-3-0/rpm/el/10/$basearch" in repo.content
    assert "[isc-kea-3-0-noarch]" in repo.content
    assert "gpgcheck=1" in repo.content


def test_isc_series_validation():
    assert isc_repo_name("3.2") == "kea-3-2"
    with pytest.raises(ValueError):
        isc_repo_name("3.2; rm -rf /")
    arch = distro_from_fields({"ID": "arch"})
    with pytest.raises(ValueError):
        isc_repo_files(arch, "3.2")


def test_runner_dry_run_and_sudo(monkeypatch):
    r = CommandRunner(dry_run=True)
    monkeypatch.setattr(CommandRunner, "is_root", property(lambda self: False))
    res = r.run(["apt-get", "install", "-y", "bind9"], privileged=True)
    assert res.skipped and res.argv == ["sudo", "-n", "apt-get", "install", "-y", "bind9"]
    # Read-only commands still run in dry-run mode.
    res = r.run(["true"], mutates=False)
    assert res.ok and not res.skipped


def test_runner_reports_failures():
    r = CommandRunner()
    res = r.run(["false"], check=False)
    assert res.returncode == 1
    with pytest.raises(Exception, match="exited 1"):
        r.run(["false"])


def test_package_manager_apt():
    runner = FakeRunner(
        responses={
            "dpkg-query -W -f=${Status}|${Version} bind9": "install ok installed|1:9.20.30-1~deb13u1",
            "dpkg-query -W -f=${Status}|${Version} kea-dhcp4-server": CommandResult([], 1, "", "no packages"),
        }
    )
    pm = PackageManager(detect_distro(DATA / "debian13"), runner)
    assert pm.installed_version("bind9") == "1:9.20.30-1~deb13u1"
    assert not pm.is_installed("kea-dhcp4-server")
    pm.install(["kea-dhcp4-server"])
    assert runner.commands("apt-get install") == [
        "apt-get install -y -q -o Dpkg::Options::=--force-confold kea-dhcp4-server"
    ]


def test_package_manager_dnf():
    runner = FakeRunner(responses={"rpm -q": "installed|3.0.3-1.el10_2"})
    pm = PackageManager(detect_distro(DATA / "rocky10"), runner)
    assert pm.installed_version("kea") == "3.0.3-1.el10_2"
    pm.refresh()
    pm.install(["bind", "bind-utils"])
    assert runner.commands("dnf") == ["dnf -y -q makecache", "dnf install -y -q bind bind-utils"]


def test_service_manager_queries():
    runner = FakeRunner(responses={"systemctl is-active named.service": "active\n"})
    sm = ServiceManager(runner)
    assert sm.is_active("named.service")
    assert not sm.is_active("kea-dhcp4-server.service")
    sm.enable_now("named.service")
    assert "systemctl enable --now named.service" in runner.commands("systemctl")


def test_give_tree_to_skips_links_and_listed_files(tmp_path, monkeypatch):
    import grp
    import os
    import pwd

    from pelagos.platform import give_tree_to

    me = pwd.getpwuid(os.getuid())
    other = next((g for g in os.getgroups() if g != me.pw_gid), None)
    if other is None:
        pytest.skip("the test user has no supplementary group to chown to")
    group = grp.getgrgid(other).gr_name
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "node.toml").write_text("x")
    (tmp_path / "etc" / "pelagos.env").write_text("x")
    (tmp_path / "var" / "pki").mkdir(parents=True)
    (tmp_path / "var" / "pki" / "node.key").write_text("k")
    os.symlink(tmp_path / "etc" / "node.toml", tmp_path / "var" / "link")
    assert give_tree_to(me.pw_name, [tmp_path / "etc"]) == 0  # not root: nothing happens
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    changed = give_tree_to(
        me.pw_name, [tmp_path / "etc", tmp_path / "var"], skip=[tmp_path / "etc" / "pelagos.env"], group=group
    )
    assert changed == 5
    assert (tmp_path / "var" / "pki" / "node.key").stat().st_gid == other
    assert (tmp_path / "etc" / "pelagos.env").stat().st_gid == me.pw_gid
    assert (tmp_path / "var" / "link").lstat().st_gid == me.pw_gid
    assert give_tree_to(me.pw_name, [tmp_path / "etc"], group=group) == 1  # pelagos.env, not skipped now
    assert give_tree_to("no-such-user-pelagos", [tmp_path]) == 0
