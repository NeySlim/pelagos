# SPDX-License-Identifier: Apache-2.0
"""Kea migration prepare step on a node (section 28, batch K3): the plan the helper records, the 2.6
files and packages kept, the 3.x files written aside, the target packages downloaded; /etc/kea
untouched and nothing installed (fake package tools)."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from pelagos.core import kea_migration as kmc
from pelagos.domain import JobState, PlanScope
from pelagos.installer import helper
from pelagos.installer import kea_migration as km
from pelagos.installer import kea_migration_steps as kms
from pelagos.installer.jobs import apply_plan
from pelagos.platform import CommandResult, FakeRunner
from tests.unit.installer.fakes import make_env
from tests.unit.installer.test_kea_migration import ISC, KEA_DATA, FakeApt

pytestmark = pytest.mark.unit

MID = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"
NODE = {"name": "ns1", "role": "primary", "order": 2, "engines": ["kea4", "d2"]}


@pytest.fixture(autouse=True)
def not_really_root(monkeypatch):
    monkeypatch.setattr(km.os, "geteuid", lambda: 1000)


class Host:
    """FakeApt plus the node's own apt: `apt-get download` of the previous packages and
    `apt-get install --download-only` into the package cache."""

    def __init__(self, env, apt: FakeApt) -> None:
        self.env = env
        self.apt = apt
        self.cache = env.paths.root / kms.APT_ARCHIVES
        self.unavailable: set[str] = set()
        self.installs: list[list[str]] = []
        workspace_download = env.runner.responses["sh -c"]
        r = env.runner.responses

        def sh(argv: list[str]) -> CommandResult:
            if argv[2] != kms._SH_CD:
                return workspace_download(argv)
            dest = Path(argv[4])
            for spec in argv[argv.index("download") + 1 :]:
                name, version = spec.split("=", 1)
                if name not in self.unavailable:
                    (dest / f"{name}_{version.replace(':', '%3a')}_amd64.deb").write_text(name)
            return CommandResult(argv, 0, "", "")

        def apt_get(argv: list[str]) -> CommandResult:
            if "--download-only" in argv:
                opts = [argv[i + 1] for i, a in enumerate(argv) if a == "-o"]
                arch = [o.split("=", 1)[1] for o in opts if o.startswith("Dir::Cache::archives=")]
                cache = Path(arch[0]) if arch else self.cache
                assert (cache / "partial").is_dir()
                for spec in argv[argv.index("-q") + 1 :]:
                    if spec == "-o" or "::" in spec:
                        continue
                    name, version = spec.split("=", 1)
                    (cache / f"{name}_{version}_amd64.deb").write_text(name)
            elif "install" in argv:
                self.installs.append(argv)
            return CommandResult(argv, 0, "Reading package lists...", "")

        r["sh -c"] = sh
        r["apt-get"] = apt_get


@pytest.fixture
def host(tmp_path):
    env = make_env(tmp_path / "root")
    env.paths.root.mkdir(parents=True)
    env.runner = FakeRunner()
    etc = env.paths.kea_conf_dir
    etc.mkdir(parents=True)
    (etc / "kea-dhcp4.conf").write_text((KEA_DATA / "kea26-migration-dhcp4.json").read_text())
    (etc / "kea-dhcp-ddns.conf").write_text((KEA_DATA / "kea26-migration-d2.json").read_text())
    (etc / "kea-dhcp-ddns.conf").chmod(0o640)
    return Host(env, FakeApt(env.runner))


def details(**over) -> dict:
    return {
        "migration_id": MID,
        "phase": "prepare",
        "series": "3.2",
        "source": "isc",
        "target_version": "3.2.1",
        "node": NODE,
        **over,
    }


def snapshot(d: Path) -> dict[str, bytes]:
    return {str(p.relative_to(d)): p.read_bytes() for p in sorted(d.rglob("*")) if p.is_file()}


def test_prepare_keeps_the_2_6_side_and_writes_3_x_aside(host):
    env = host.env
    before = snapshot(env.paths.kea_conf_dir)
    out = kms.prepare(env, details())
    assert snapshot(env.paths.kea_conf_dir) == before  # nothing in /etc/kea changes
    assert host.installs == []  # nothing installed
    mdir = kmc.state_dir(env.node_paths, MID)
    assert stat.S_IMODE(mdir.stat().st_mode) == 0o700
    assert not mdir.is_relative_to(env.node_paths.var)  # outside the service user's tree
    assert stat.S_IMODE(mdir.parent.stat().st_mode) == 0o700
    public = kmc.migration_dir(env.node_paths.var, MID)
    assert public.is_dir() and not any(public.iterdir())
    private = mdir / kms.PRIVATE
    assert stat.S_IMODE(private.stat().st_mode) == 0o700
    # 2.6 files saved as they were, converted ones written aside with their TSIG secret file.
    assert (private / "before/kea-dhcp4.conf").read_bytes() == before["kea-dhcp4.conf"]
    assert stat.S_IMODE((private / "before/kea-dhcp-ddns.conf").stat().st_mode) == 0o640
    d2 = json.loads((private / "target/kea-dhcp-ddns.conf").read_text())
    keys = d2["DhcpDdns"]["tsig-keys"]
    assert keys and all("secret-file" in k and "secret" not in k for k in keys)
    manifest = json.loads((mdir / kms.MANIFEST).read_text())
    [secret] = manifest["converted"]["secrets"]
    assert secret["path"] == keys[0]["secret-file"]
    assert stat.S_IMODE((private / "target" / secret["file"]).stat().st_mode) == 0o600
    targets = {f["engine"]: f["path"] for f in manifest["converted"]["files"]}
    assert targets == {
        "kea4": str(env.paths.kea_conf("kea-dhcp4")),
        "d2": str(env.paths.kea_conf("kea-dhcp-ddns")),
    }
    # Exact versions on both sides; the previous packages kept as files, the target in apt's cache.
    assert {"name": "kea-dhcp4-server", "version": "2.6.3-1+deb13u1"} in out["packages_before"]
    assert {p["name"] for p in out["packages_target"]} >= {"isc-kea-dhcp4", "isc-kea-hooks"}
    assert all(p["version"] == ISC for p in out["packages_target"])
    previous = sorted(p.name for p in (mdir / "packages/previous").iterdir())
    assert "kea-dhcp4-server_2.6.3-1+deb13u1_amd64.deb" in previous
    target = mdir / "packages/target"
    assert (target / f"isc-kea-dhcp4_{ISC}_amd64.deb").is_file() and not host.cache.exists()
    assert {f["file"] for f in manifest["target_files"]} >= {f"isc-kea-dhcp4_{ISC}_amd64.deb"}
    assert all("/" not in p["file"] for p in manifest["packages_target"] + manifest["packages_before"])
    assert {p["name"] for p in out["packages_remove"]} >= {"kea-dhcp4-server", "kea-common"}
    assert out["rollback_ready"] is True and out["target_version"] == "3.2.1"
    assert out["from_version"] == "2.6.3"
    assert out["validation"] == {"kea4": "dry_run", "d2": "dry_run"}
    # The ISC repository sits next to the node's own, noted for the return.
    assert out["repo_files_added"] == [
        "/etc/apt/keyrings/isc-kea-3-2.asc",
        "/etc/apt/sources.list.d/isc-kea-3-2.list",
    ]
    assert "kea-3-2" in (env.paths.root / "etc/apt/sources.list.d/isc-kea-3-2.list").read_text()
    assert json.loads((private / kms.SOURCES).read_text()) == out["repo_files_added"]


def test_cached_previous_package_is_copied_not_downloaded(host):
    host.cache.mkdir(parents=True)
    (host.cache / "kea-common_2.6.3-1+deb13u1_amd64.deb").write_text("cached")
    kms.prepare(host.env, details())
    previous = kmc.state_dir(host.env.node_paths, MID) / "packages/previous"
    assert (previous / "kea-common_2.6.3-1+deb13u1_amd64.deb").read_text() == "cached"
    [download] = [c for c in host.env.runner.commands("sh -c") if "APT::Sandbox::User=root download" in c]
    assert "kea-common=" not in download and "kea-dhcp4-server=2.6.3-1+deb13u1" in download


def test_a_previous_package_gone_from_the_archive_fails_the_prepare(host):
    host.unavailable.add("kea-dhcp4-server")
    with pytest.raises(kms.PrepareError, match="would be impossible"):
        kms.prepare(host.env, details())


def test_refused_configuration_fails_before_anything_is_written(host):
    host.apt.verdicts["kea4"] = (1, "ERROR [kea-dhcp4.dhcp4] DHCP4_CONFIG_LOAD_FAIL bad\n")
    with pytest.raises(kms.PrepareError, match="blocking findings"):
        kms.prepare(host.env, details())
    assert not (host.env.paths.root / "etc/apt/sources.list.d").exists()
    assert not host.cache.exists()


def test_download_failure_and_a_newer_target_fail(host):
    with pytest.raises(kms.PrepareError, match="analyze again"):
        kms.prepare(host.env, details(target_version="3.2.0"))
    host.apt.missing.add("isc-kea-dhcp4")
    with pytest.raises(kms.PrepareError, match="target packages"):
        kms.prepare(host.env, details())


def test_a_failed_prepare_removes_the_repository_it_added(host):
    sources = host.env.paths.root / "etc/apt/sources.list.d/isc-kea-3-2.list"
    host.unavailable.add("kea-dhcp4-server")
    with pytest.raises(kms.PrepareError, match="would be impossible"):
        kms.prepare(host.env, details())
    assert not sources.exists()
    assert not (host.env.paths.root / "etc/apt/keyrings/isc-kea-3-2.asc").exists()
    # A run stopped half way (no cleanup) is still known to the next prepare of the migration.
    host.unavailable.clear()
    real = kms.keep_previous
    kms.keep_previous = lambda *a: (_ for _ in ()).throw(KeyboardInterrupt())
    try:
        with pytest.raises(KeyboardInterrupt):
            kms.prepare(host.env, details())
    finally:
        kms.keep_previous = real
    assert not sources.exists()
    private = kmc.state_dir(host.env.node_paths, MID) / kms.PRIVATE
    private.mkdir(parents=True, exist_ok=True)
    sources.parent.mkdir(parents=True, exist_ok=True)
    sources.write_text("# pelagos:managed v1 (ISC Kea packages)\n")
    (private / kms.SOURCES).write_text(json.dumps(["/etc/apt/sources.list.d/isc-kea-3-2.list"]))
    out = kms.prepare(host.env, details())
    assert "/etc/apt/sources.list.d/isc-kea-3-2.list" in out["repo_files_added"]


def test_build_plan_archive_then_prepare_on_each_node(host):
    env = host.env
    request = {
        **details(),
        "nodes": [
            {"node_id": "node-b", "name": "ns2", "role": "standby", "order": 1, "engines": ["kea4"]},
            {"node_id": env.node_id, **NODE},
        ],
    }
    plan = kms.build_plan(env, request, "admin")
    assert plan.scope is PlanScope.KEA_MIGRATION and plan.requires_confirmation
    assert [c.target for c in plan.changes] == [
        kmc.target(kmc.D_ARCHIVE, "node-b"),
        kmc.target(kmc.D_ARCHIVE, env.node_id),
        kmc.target(kmc.H_PREPARE, "node-b"),
        kmc.target(kmc.H_PREPARE, env.node_id),
    ]
    d = plan.changes[3].after["details"]
    assert (
        d["migration_id"] == MID and d["node"]["role"] == "primary" and d["node"]["engines"] == ["kea4", "d2"]
    )
    assert plan.summary_message["key"] == "plan.kea_migration.prepare"
    for bad in (
        {"phase": "nope"},
        {"options": {"auto_rollback": "yes"}},
        {"migration_id": "x"},
        {"series": "2.6"},
        {"nodes": []},
    ):
        with pytest.raises(ValueError):
            kms.build_plan(env, {**request, **bad})


def test_helper_records_the_plan_and_runs_only_this_nodes_prepare(host, tmp_path, monkeypatch):
    env = host.env
    monkeypatch.setenv(helper.PLANS_ENV, str(tmp_path / "plans"))
    request = {**details(), "nodes": [{"node_id": env.node_id, **NODE}]}
    data = helper.handle(
        {"op": "plan_kea_migration", "created_by": "admin", "request": request}, lambda: env, lambda _: None
    )
    from pelagos.domain import Plan

    plan = Plan.from_dict(data)
    helper.authorize(plan, env)  # recorded by this helper
    prepare = [c for c in plan.changes if c.after["step"] == kmc.H_PREPARE]
    part = Plan.from_dict(plan.to_dict())
    part.changes = prepare
    job = apply_plan(part, env)
    assert job.state is JobState.DONE, job.error
    result = kms.result_of(job.steps[-1]["output"])
    assert result["rollback_ready"] is True
    # A driver step never runs in a helper.
    part.changes = [c for c in plan.changes if c.after["step"] == kmc.D_ARCHIVE]
    assert apply_plan(part, env).state is JobState.FAILED
