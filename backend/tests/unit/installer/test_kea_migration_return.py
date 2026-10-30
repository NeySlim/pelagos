# SPDX-License-Identifier: Apache-2.0
"""The return of a node to Kea 2.6 and the reconcile steps (section 28, item 82 of 0.3.0): every part
of the return runs and is reported even when one fails, AppArmor without securityfs, unit enable
states, files the prepare never saw moved aside, removed ISC packages purged without their purge
scripts, and kea-mig-check / kea-mig-cleanup (fake package tools, daemons and units)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pelagos.core import kea_migration as kmc
from pelagos.installer import kea_migration_switch as sw
from pelagos.platform import CommandResult
from tests.unit.installer.test_kea_migration_prepare import MID, host, not_really_root  # noqa: F401
from tests.unit.installer.test_kea_migration_switch import kea_files, node, switch_details  # noqa: F401

pytestmark = pytest.mark.unit


def test_a_failed_package_install_still_puts_every_file_back(node):  # noqa: F811
    env, pk = node
    before = kea_files(env)
    apparmor = env.paths.root / "etc/apparmor.d"
    apparmor.mkdir(parents=True)
    (apparmor / "usr.sbin.kea-dhcp4").write_text("profile")
    sw.install(env, switch_details(direction="target"))
    pk.fail = True
    with pytest.raises(sw.SwitchError) as err:
        sw.install(env, switch_details(direction="previous"))
    text = str(err.value)
    assert "packages: previous packages not installed" in text and "FAILED packages" in text
    # Files, AppArmor links and repository files came back although the packages did not.
    assert kea_files(env) == before
    assert not (apparmor / "disable/usr.sbin.kea-dhcp4").exists()
    assert not (env.paths.root / "etc/apt/sources.list.d/isc-kea-3-2.list").exists()
    pk.fail = False
    out = sw.install(env, switch_details(direction="previous"))  # run again: completes
    assert pk.installed["kea-dhcp4-server"] == "2.6.3-1+deb13u1" and out["direction"] == "previous"


def test_apparmor_without_securityfs_only_removes_the_links(host):  # noqa: F811
    env = host.env
    d = env.paths.root / "etc/apparmor.d"
    (d / "disable").mkdir(parents=True)
    (d / "usr.sbin.kea-dhcp4").write_text("profile")
    (d / "disable/usr.sbin.kea-dhcp4").symlink_to(d / "usr.sbin.kea-dhcp4")
    out = sw.reenable_apparmor(env, ["usr.sbin.kea-dhcp4"])
    assert not (d / "disable/usr.sbin.kea-dhcp4").exists()
    assert any("AppArmor is not active" in line for line in out)
    assert not env.runner.commands("apparmor_parser")
    (env.paths.root / "sys/kernel/security/apparmor").mkdir(parents=True)
    (d / "disable/usr.sbin.kea-dhcp4").symlink_to(d / "usr.sbin.kea-dhcp4")
    env.runner.responses["apparmor_parser"] = lambda argv: CommandResult(argv, 1, "", "no policy")
    out = sw.reenable_apparmor(env, ["usr.sbin.kea-dhcp4"])
    assert env.runner.commands("apparmor_parser -r") and any("apparmor_parser failed" in o for o in out)


def test_units_get_their_enable_state_back(host):  # noqa: F811
    env = host.env
    env.binaries["systemctl"] = "/usr/bin/systemctl"
    services = env.service_manager
    services.units |= {"kea-dhcp4-server.service", "kea-dhcp6-server.service"}
    services.enabled |= {"kea-dhcp6-server.service"}  # a package script enabled it again
    before = {
        "kea-dhcp4-server.service": {"active": True, "enabled": True, "enabled_state": "enabled"},
        "kea-dhcp6-server.service": {"active": False, "enabled": False, "enabled_state": "disabled"},
        "kea-ctrl-agent.service": {"active": False, "enabled": False, "enabled_state": "not-found"},
    }
    out = sw.restore_units(env, before)
    assert env.runner.commands("systemctl disable kea-dhcp6-server.service")
    assert env.runner.commands("systemctl enable kea-dhcp4-server.service")
    assert len(out) == 2 and not env.runner.commands("kea-ctrl-agent")


def test_files_the_prepare_never_saw_are_moved_aside(node):  # noqa: F811
    env, _pk = node
    before = kea_files(env)
    sw.install(env, switch_details(direction="target"))
    (env.paths.kea_conf_dir / "kea-ddns.tsig").write_text("secret")  # added under another name
    sw.install(env, switch_details(direction="previous"))
    assert kea_files(env) == before
    kept = kmc.state_dir(env.node_paths, MID) / "private/extra/kea-ddns.tsig"
    assert kept.read_text() == "secret"


def rc_packages(env, purged: list[list[str]]) -> None:
    listing = (
        "isc-kea-common\trc \t\n"
        "isc-kea-dhcp4\trc \t\n /etc/init.d/isc-kea-dhcp4-server 645\n /etc/kea/kea-dhcp4.conf 621\n"
        "kea-common\tii \t\n"
    )
    info = env.paths.root / "var/lib/dpkg/info"
    info.mkdir(parents=True)
    for name in ("isc-kea-common", "isc-kea-dhcp4"):
        (info / f"{name}.postrm").write_text("#!/bin/sh\nrm -rf /etc/kea\n")

    def purge(argv):
        purged.append(argv)
        env.paths.kea_conf("kea-dhcp4").unlink()  # dpkg drops a conffile the purged package listed
        return CommandResult(argv, 0, "", "")

    key = "dpkg-query -W -f=${Package}\t${db:Status-Abbrev}"
    answers = {key: lambda argv: CommandResult(argv, 0, listing, ""), "dpkg --purge": purge}
    env.runner.responses = {**answers, **env.runner.responses}  # first match wins


def test_removed_isc_packages_are_purged_without_their_purge_scripts(host):  # noqa: F811
    env = host.env
    before = kea_files(env)
    purged: list[list[str]] = []
    rc_packages(env, purged)
    out = sw.purge_leftovers(env)
    assert purged == [["dpkg", "--purge", "isc-kea-common", "isc-kea-dhcp4"]]
    info = env.paths.root / "var/lib/dpkg/info"
    assert all(
        "rm -rf" not in (info / f"{n}.postrm").read_text() for n in ("isc-kea-common", "isc-kea-dhcp4")
    )
    assert kea_files(env) == before  # the conffile dpkg dropped is put back
    assert any("put back after the purge" in o for o in out)
    assert env.runner.commands("update-rc.d -f isc-kea-dhcp4-server remove")


def test_check_and_cleanup_of_a_node_back_on_2_6(node):  # noqa: F811
    env, pk = node
    env.service_manager.units.add("kea-dhcp4-server.service")
    env.service_manager.active.add("kea-dhcp4-server.service")
    d = {"migration_id": MID, "engines": ["kea4"], "from_series": "2.6"}
    before = [{"name": "kea-dhcp4-server", "version": "2.6.3-1+deb13u1"}]
    out = sw.check(env, {**d, "packages_before": before})
    assert out["versions"]["kea4"].startswith("2.6.3")
    # A node still on 3.2, a version that differs, a stopped daemon: each one is named.
    with pytest.raises(sw.SwitchError, match=r"2\.6\.3-1\+deb13u1 instead of 2\.6\.2"):
        sw.check(env, {**d, "packages_before": [{"name": "kea-dhcp4-server", "version": "2.6.2"}]})
    env.service_manager.active.clear()
    with pytest.raises(sw.SwitchError, match="is not running"):
        sw.check(env, d)
    pk.installed["isc-kea-common"] = "3.2.1-isc1"
    with pytest.raises(sw.SwitchError, match="ISC packages installed: isc-kea-common"):
        sw.check(env, d)
    del pk.installed["isc-kea-common"]
    # The cleanup: root's and the service user's migration folders go, /etc/kea stays.
    files = kea_files(env)
    mdir = kmc.state_dir(env.node_paths, MID)
    public = kmc.migration_dir(env.node_paths.var, MID)
    public.mkdir(parents=True, exist_ok=True)
    out = sw.cleanup(env, d)
    assert not mdir.exists() and not public.exists() and kea_files(env) == files
    assert json.dumps(out)


def test_a_failed_purge_still_puts_etc_kea_back_and_keeps_the_copy(host):  # noqa: F811
    env = host.env
    before = kea_files(env)
    purged: list[list[str]] = []
    rc_packages(env, purged)

    def broken(argv):
        purged.append(argv)
        env.paths.kea_conf("kea-dhcp4").unlink()  # the first package's conffile is gone, then dpkg fails
        return CommandResult(argv, 1, "", "dpkg: error processing package isc-kea-dhcp4 (--purge)")

    env.runner.responses["dpkg --purge"] = broken
    with pytest.raises(sw.SwitchError, match=r"error processing package.*copy of .* kept in (\S+)") as err:
        sw.purge_leftovers(env)
    assert kea_files(env) == before
    kept = Path(str(err.value).rsplit(" kept in ", 1)[1].rstrip(")"))
    assert (kept / "kea-dhcp4.conf").is_file() and kept.is_relative_to(env.node_paths.kea_migration_state)


def test_cleanup_keeps_the_saved_files_when_etc_kea_differs(node):  # noqa: F811
    env, _pk = node
    mdir = kmc.state_dir(env.node_paths, MID)
    assert (mdir / "private/before").is_dir()
    env.paths.kea_conf("kea-dhcp4").write_text('{"Dhcp4": {}}')  # an imperfect manual repair
    out = sw.cleanup(env, {"migration_id": MID, "engines": ["kea4"], "from_series": "2.6"})
    assert not mdir.exists()
    [kept] = [p for p in mdir.parent.glob(f"before-{MID}-*")]
    assert (kept / "kea-dhcp4.conf").is_file()
    assert any("kept: /etc/kea differs" in line for line in out["log"])
