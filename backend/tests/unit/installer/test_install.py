# SPDX-License-Identifier: Apache-2.0
"""Install plans (distro and ISC, Debian and Rocky) and their Job, with fake packages and services."""

from __future__ import annotations

import json

import pytest

from pelagos.core.bootstrap import bootstrap_first_node
from pelagos.core.config_store import ConfigStore
from pelagos.core.secrets import SecretBox
from pelagos.domain import Job, JobState, PlanScope, PlanState
from pelagos.installer import bindconf, keaconf
from pelagos.installer.importer import build_import_plan
from pelagos.installer.install import build_install_plan
from pelagos.installer.jobs import JobRunner, Step, apply_plan
from tests.unit.installer.fakes import debian_tree, make_env

pytestmark = pytest.mark.unit


def test_distro_plan_on_debian(tmp_path):
    env = make_env(tmp_path)
    env.binaries.update({"named": None, "kea-dhcp4": None, "kea-dhcp-ddns": None})
    plan = build_install_plan(env, ["d2", "bind", "kea4"], "distro", created_by="admin")
    assert (
        plan.scope is PlanScope.INSTALL and plan.state is PlanState.VALIDATED and plan.requires_confirmation
    )
    assert [c.target for c in plan.changes] == [
        "install/packages",
        "install/user/pelagos",
        "install/service/bind",
        "install/bind/adopt",
        "install/kea4/config",
        "install/service/kea4",
        "install/d2/config",
        "install/service/d2",
        "install/node",
        "install/verify",
    ]
    assert plan.changes[0].after["install"] == [
        "bind9",
        "bind9-utils",
        "bind9-dnsutils",
        "kea-dhcp4-server",
        "kea-dhcp-ddns-server",
    ]
    assert plan.changes[1].after["groups"] == ["bind", "_kea"]
    assert plan.changes[3].after["keys"] == ["ddi-read", "ddi-admin", "kea-ddns"]
    assert plan.changes[4].after["mode"] == "minimal"
    assert plan.changes[6].after["tsig_key"] == "kea-ddns"
    assert all(c.node_ids == ["node-a"] for c in plan.changes)
    json.dumps(plan.to_dict())  # the plan travels as JSON (API, replication)


def test_isc_plan_on_rocky(tmp_path):
    env = make_env(tmp_path, distro="rocky10")
    env.binaries.update({"named": None, "kea-dhcp4": None})
    plan = build_install_plan(env, ["kea4"], "isc", "3.0")
    assert plan.changes[0].target == "install/repo/isc-kea-3-0"
    assert plan.changes[0].after["files"] == ["/etc/yum.repos.d/isc-kea-3-0.repo"]
    assert plan.changes[1].after["install"] == ["isc-kea-dhcp4", "isc-kea-hooks"]
    assert plan.summary == "install kea4 (ISC Kea 3.0)"


def test_plan_rejects_bad_input(tmp_path):
    env = make_env(tmp_path)
    with pytest.raises(ValueError):
        build_install_plan(env, ["dns"], "distro")
    with pytest.raises(ValueError):
        build_install_plan(env, ["bind"], "ppa")
    with pytest.raises(ValueError):
        build_install_plan(env, ["kea4"], "isc", "latest")


def test_installed_packages_are_skipped(tmp_path):
    env = debian_tree(tmp_path)
    env.packages.installed.update({"bind9", "bind9-utils", "bind9-dnsutils"})
    plan = build_install_plan(env, ["bind"], "distro")
    assert "install/packages" not in [c.target for c in plan.changes]


def test_install_job_bind_and_kea(tmp_path):
    env = debian_tree(tmp_path)
    env.tools.version = "2.6.3"
    env.binaries.update({"kea-dhcp4": None, "kea-dhcp-ddns": None})
    plan = build_install_plan(env, ["bind", "kea4", "d2"], "distro")
    env.binaries.update({"kea-dhcp4": "/usr/sbin/kea-dhcp4", "kea-dhcp-ddns": "/usr/sbin/kea-dhcp-ddns"})
    seen: list[int] = []
    job = apply_plan(plan, env, progress=lambda j: seen.append(j.progress))
    assert job.state is JobState.DONE, job.error
    assert seen[-1] == 100 and seen == sorted(seen)
    assert [s["state"] for s in job.steps] == ["done"] * len(job.steps)
    # Packages, services.
    assert env.packages.calls[0][0] == "install"
    assert ("enable_now", "named.service") in env.services.calls
    assert ("enable_now", "kea-dhcp4-server.service") in env.services.calls
    # BIND: kea-ddns in keys.conf with the same secret as the D2 secret.
    keys = {
        k.name: k
        for k in bindconf.keys(bindconf.parse((tmp_path / "etc/bind/pelagos/keys.conf").read_text()))
    }
    assert set(keys) == {"ddi-read", "ddi-admin", "kea-ddns"}
    d2 = keaconf.loads((tmp_path / "etc/kea/kea-dhcp-ddns.conf").read_text())["DhcpDdns"]
    # Kea 2.6: inline secret (no secret-file before 2.7), singular control-socket.
    assert d2["tsig-keys"] == [
        {"name": "kea-ddns", "algorithm": "HMAC-SHA256", "secret": keys["kea-ddns"].secret}
    ]
    assert (tmp_path / "etc/kea/kea-ddns.tsig").read_text().strip() == keys["kea-ddns"].secret
    d4 = keaconf.loads((tmp_path / "etc/kea/kea-dhcp4.conf").read_text())["Dhcp4"]
    assert d4["control-socket"] == {"socket-type": "unix", "socket-name": "kea4-ctrl-socket"}
    assert d4["interfaces-config"] == {"interfaces": []}
    dropin = tmp_path / "etc/systemd/system/kea-dhcp4-server.service.d/pelagos-socket.conf"
    assert "chmod g+w" in dropin.read_text()
    assert ("daemon_reload", "") in env.services.calls


def test_install_dry_run_writes_nothing(tmp_path):
    env = debian_tree(tmp_path)
    env.dry_run = True
    env.binaries.update({"kea-dhcp4": None})
    plan = build_install_plan(env, ["bind", "kea4"], "distro")
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    assert not (tmp_path / "etc/bind/pelagos").exists()
    assert not (tmp_path / "etc/kea/kea-dhcp4.conf").exists()


def test_job_runner_stops_at_first_failure():
    def boom() -> str:
        raise RuntimeError("no network")

    job = JobRunner(Job()).run([Step("a", lambda: "fine"), Step("b", boom), Step("c", lambda: "never")])
    assert job.state is JobState.FAILED and job.error == "b: no network"
    assert [s["name"] for s in job.steps] == ["a", "b"]
    assert job.steps[1]["state"] == "failed"


def test_switch_from_distro_kea_to_isc_keeps_configs(tmp_path):
    env = make_env(tmp_path)
    env.packages.installed.update({"kea-dhcp4-server", "kea-dhcp-ddns-server"})
    kea = tmp_path / "etc/kea"
    kea.mkdir(parents=True)
    d4 = (
        '// mine\n{"Dhcp4": {"control-socket": {"socket-type": "unix", "socket-name": "kea4-ctrl-socket"}}}\n'
    )
    (kea / "kea-dhcp4.conf").write_text(d4)
    secret_key = {"name": "kea-ddns", "algorithm": "HMAC-SHA256", "secret": "c2VjcmV0"}
    (kea / "kea-dhcp-ddns.conf").write_text(json.dumps({"DhcpDdns": {"tsig-keys": [secret_key]}}))
    profile = tmp_path / "etc/apparmor.d/usr.sbin.kea-dhcp4"
    profile.parent.mkdir(parents=True)
    profile.write_text("profile kea-dhcp4 {}\n")  # left behind by the removed Debian package
    plan = build_install_plan(env, ["kea4", "d2"], "isc", "3.2")
    pkgs = next(c for c in plan.changes if c.target == "install/packages").after
    assert pkgs["replaces"] == ["kea-dhcp4-server", "kea-dhcp-ddns-server"]
    assert [c.after["mode"] for c in plan.changes if c.target.endswith("/config")] == ["keep", "keep"]
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    assert env.packages.calls[-1][0] == "install-replace"
    assert (tmp_path / "etc/apparmor.d/disable/usr.sbin.kea-dhcp4").is_symlink()
    assert "apparmor_parser -R " + str(profile) in env.runner.commands("apparmor_parser")
    assert ("fetch", "https://dl.cloudsmith.io/public/isc/kea-3-2/gpg.key") in env.tools.calls
    sources = (tmp_path / "etc/apt/sources.list.d/isc-kea-3-2.list").read_text()
    assert "kea-3-2/deb/debian trixie main" in sources
    assert (kea / "kea-dhcp4.conf").read_text() == d4  # untouched, comments included
    key = keaconf.tsig_keys(keaconf.loads((kea / "kea-dhcp-ddns.conf").read_text()))[0]
    assert key == {"name": "kea-ddns", "algorithm": "HMAC-SHA256", "secret-file": str(kea / "kea-ddns.tsig")}
    assert (kea / "kea-ddns.tsig").read_text() == "c2VjcmV0"


def test_install_before_init_then_import_records_secrets(tmp_path):
    """Install on a node without cluster.toml, `pelagos init`, then import: nothing is lost."""
    env = debian_tree(tmp_path)
    env.binaries.update({"kea-dhcp4": None, "kea-dhcp-ddns": None})
    plan = build_install_plan(env, ["bind", "d2"], "distro")
    env.binaries.update({"kea-dhcp-ddns": "/usr/sbin/kea-dhcp-ddns"})
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    assert not env.node_initialized()
    keys = {
        k.name: k.secret
        for k in bindconf.keys(bindconf.parse((tmp_path / "etc/bind/pelagos/keys.conf").read_text()))
    }
    bootstrap_first_node(env.node_paths, name="ns1", admin_password="correct-horse", engines={"bind": True})
    env.node_id = env.local_node_id()
    job = apply_plan(build_import_plan(env, ["bind"]), env)
    assert job.state is JobState.DONE, job.error
    store = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml)
    cluster = store.load_cluster()
    box = SecretBox.from_file(env.node_paths.master_key)
    for name in ("ddi-read", "ddi-admin", "kea-ddns"):
        assert box.decrypt(f"tsig/{name}", cluster.secrets[f"tsig/{name}"]) == keys[name]
    assert store.load_node().engines["bind"]["include_dir"] == str(tmp_path / "etc/bind/pelagos")
    # A second import has nothing left to store.
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    assert (
        ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml).load_cluster().secrets
        == cluster.secrets
    )


def test_kept_d2_config_gets_no_new_bind_key(tmp_path):
    env = debian_tree(tmp_path)
    env.binaries.update({"kea-dhcp4": None})
    kea = tmp_path / "etc/kea"
    kea.mkdir(parents=True)
    (kea / "kea-dhcp-ddns.conf").write_text(json.dumps({"DhcpDdns": {"tsig-keys": []}}))
    plan = build_install_plan(env, ["bind", "d2"], "distro")
    adopt = next(c for c in plan.changes if c.target == "install/bind/adopt")
    assert adopt.after["keys"] == ["ddi-read", "ddi-admin"]
    assert next(c for c in plan.changes if c.target == "install/d2/config").after["mode"] == "keep"


def test_kea_reload_rejected_rolls_back(tmp_path):
    from pelagos.installer import keasetup

    env = make_env(tmp_path)
    kea = tmp_path / "etc/kea"
    kea.mkdir(parents=True)
    conf = kea / "kea-dhcp4.conf"
    old = '{"Dhcp4": {"control-socket": {"socket-type": "unix", "socket-name": "kea4-ctrl-socket"}}}\n'
    conf.write_text(old)
    unit = env.kea_unit("kea4")
    env.services.active.add(unit)
    sent: list[str] = []

    def command(sock, cmd, arguments=None):
        sent.append(cmd)
        return {"result": 1, "text": "bad subnet"} if conf.read_text() != old else {"result": 0}

    env.tools.kea_command = command
    with pytest.raises(RuntimeError, match="rejected the configuration: bad subnet"):
        keasetup.write_config(env, "kea4", conf, old + " ", "test", restart=False)
    assert conf.read_text() == old
    assert sent == ["config-reload", "config-reload"]  # the rejected one, then the restored file
