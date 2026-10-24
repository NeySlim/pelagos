# SPDX-License-Identifier: Apache-2.0
"""Install plans (distro and ISC, Debian and Rocky) and their Job, with fake packages and services."""

from __future__ import annotations

import json

import pytest

from pelagos.domain import Job, JobState, PlanScope, PlanState
from pelagos.installer import bindconf, keaconf
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
