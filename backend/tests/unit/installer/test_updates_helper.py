# SPDX-License-Identifier: Apache-2.0
"""Root side of the updates from the UI (installer.updates, section 29): verify, start, status,
journal, apply, against fake package tools and a release built and signed in a temp folder."""

from __future__ import annotations

import hashlib
import json
import os
import tarfile
from pathlib import Path
from typing import Any

import pytest

from pelagos.core import release as rel
from pelagos.core.config_store import ConfigStore
from pelagos.domain.updates import CHECKSUMS, SIGNATURE, Rollout, RolloutNode
from pelagos.installer import helper, updates
from pelagos.platform import CommandResult
from tests.unit.installer.fakes import join_cluster, make_env

RID = "01JB0000000000000000000000"


class Pkg:
    """Fake package tools: a .deb is a text file of control fields; dpkg-query answers `installed`."""

    def __init__(self, installed: str | None = "0.2.5-1") -> None:
        self.installed = installed
        self.engines: dict[str, str] = {}
        self.install_ok = True
        self.installs: list[list[str]] = []

    def responses(self) -> dict[str, Any]:
        return {
            "dpkg --print-architecture": "amd64\n",
            "dpkg-query -W": self.query,
            "dpkg-deb -f": self.fields,
            "apt-get install": self.install,
            "systemctl list-units": "",
        }

    def query(self, argv: list[str]) -> CommandResult:
        name = argv[-1]
        version = self.installed if name == "pelagos" else self.engines.get(name)
        if version is None:
            return CommandResult(argv, 1, "", "no packages found")
        return CommandResult(argv, 0, f"install ok installed|{version}", "")

    def fields(self, argv: list[str]) -> CommandResult:
        return CommandResult(argv, 0, Path(argv[2]).read_text(), "")

    def install(self, argv: list[str]) -> CommandResult:
        self.installs.append(argv)
        if not self.install_ok:
            return CommandResult(argv, 100, "", "dpkg: error processing archive")
        target = argv[-1]
        if target.endswith(".deb"):
            fields = dict(line.split(": ", 1) for line in Path(target).read_text().splitlines())
            self.installed = fields["Version"]
        else:
            for spec in argv[argv.index("DPkg::Lock::Timeout=300") + 1 :]:
                name, _, version = spec.partition("=")
                self.engines[name] = version
        return CommandResult(argv, 0, "Setting up", "")


def deb(name: str = "pelagos", version: str = "0.3.0-1", arch: str = "amd64") -> str:
    return f"Package: {name}\nVersion: {version}\nArchitecture: {arch}\n"


def build_release(
    folder: Path,
    version: str = "0.3.0",
    key: Path | None = None,
    control: str | None = None,
    manifest: bool = True,
) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    pkg_version = f"{version}-1"
    (folder / f"pelagos_{pkg_version}_amd64.deb").write_text(control or deb(version=pkg_version))
    (folder / f"pelagos_{pkg_version}_arm64.deb").write_text(deb(version=pkg_version, arch="arm64"))
    (folder / "NOTES.md").write_text(f"# Pelagos {version}\n")
    if manifest:
        rel.write_manifest(folder, rel.build_manifest(folder, version))
    sums = "".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
        for p in sorted(folder.iterdir())
        if p.is_file()
    )
    (folder / CHECKSUMS).write_text(sums)
    if key is not None:
        rel.sign_release(folder, key)
    return folder


@pytest.fixture
def keys(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    private = tmp_path / "keys" / "release.key"
    rel.generate_key(private)
    return private, rel.load_public_keys(private.parent)


@pytest.fixture
def node(tmp_path: Path) -> tuple[Any, Pkg]:
    env = make_env(tmp_path)
    pkg = Pkg()
    env.runner.responses.update(pkg.responses())
    join_cluster(env)
    return env, pkg


def set_rollout(env: Any, **fields: Any) -> Rollout:
    r = Rollout(
        id=fields.pop("id", RID),
        kind=fields.pop("kind", "pelagos"),
        version=fields.pop("version", "0.3.0"),
        order=[env.node_id],
        nodes={env.node_id: RolloutNode(env.node_id)},
        **fields,
    )
    store = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml)
    store.update_cluster(lambda c: c.settings.setdefault("updates", {}).update(rollout=r.to_toml()), "test")
    return r


def incoming(env: Any, version: str = "0.3.0") -> Path:
    return env.node_paths.upgrade_incoming / version


# Version order ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "sign"),
    [
        ("0.3.0-1", "0.2.5-1", 1),
        ("0.3.0~rc1-1", "0.3.0-1", -1),
        ("0.3.0~dev0+git20261030.abc-1", "0.3.0~dev0+git20261029.abc-1", 1),
        ("1:0.1-1", "9.9-1", 1),
        ("0.2.10-1", "0.2.9-1", 1),
        ("1.0-1", "1.0-1", 0),
        ("1.0a-1", "1.0-1", 1),
        ("9.20.15-1~deb13u1", "9.20.15-1", -1),
    ],
)
def test_deb_order_matches_dpkg(a: str, b: str, sign: int) -> None:
    from pelagos.platform import versions

    assert versions.compare("deb", a, b) == sign
    if Path("/usr/bin/dpkg").exists():
        import subprocess

        op = {1: "gt", 0: "eq", -1: "lt"}[sign]
        assert subprocess.run(["dpkg", "--compare-versions", a, op, b], check=False).returncode == 0


@pytest.mark.parametrize(
    ("a", "b", "sign"),
    [
        ("0.3.0-1.el10", "0.2.5-1.el10", 1),
        ("0.3.0~rc1-1", "0.3.0-1", -1),
        ("0.3.0~dev0^git2-1", "0.3.0~dev0^git1-1", 1),
        ("0.3.0^git1-1", "0.3.0-1", 1),
        ("1.0a-1", "1.0-1", 1),
        ("1.010-1", "1.9-1", 1),
        ("2.6.3-1", "2.6.3", 0),
        ("1:1.0-1", "2.0-1", 1),
    ],
)
def test_rpm_order(a: str, b: str, sign: int) -> None:
    from pelagos.platform import versions

    assert versions.compare("rpm", a, b) == sign


# update_verify ----------------------------------------------------------------------------------------


def test_verify_copies_a_signed_release_and_answers(node: Any, keys: Any) -> None:
    env, _ = node
    private, public = keys
    build_release(incoming(env), key=private)
    out = updates.verify(env, "0.3.0", False, public).answer()
    assert out["signature"] == "valid" and out["key_id"] in public
    assert out["package"] == "pelagos_0.3.0-1_amd64.deb" and out["package_version"] == "0.3.0-1"
    assert out["direction"] == "upgrade" and out["installed"] == "0.2.5-1" and out["state_schema"] == 1
    lay = updates.layout(env)
    copy = lay.packages("0.3.0")
    assert (copy / out["package"]).is_file() and (copy / SIGNATURE).is_file()
    assert not incoming(env).exists()
    assert oct(copy.stat().st_mode & 0o777) == "0o750"
    assert oct((copy / out["package"]).stat().st_mode & 0o777) == "0o640"
    # Verified again from the kept copy once the upload is gone.
    assert updates.verify(env, "0.3.0", False, public).sha256 == out["sha256"]


def test_verify_refusals(node: Any, keys: Any, tmp_path: Path) -> None:
    env, pkg = node
    private, public = keys

    def refused(reason: str, version: str = "0.3.0", allow: bool = False) -> None:
        with pytest.raises(updates.UpdateRefused) as exc:
            updates.verify(env, version, allow, public)
        assert exc.value.reason == reason, str(exc.value)
        assert str(exc.value).startswith(reason)

    refused("version", version="../etc")
    refused("missing")
    build_release(incoming(env))
    refused("unsigned_not_accepted")
    assert updates.verify(env, "0.3.0", True, public).check.signature.value == "unsigned"
    # A signature that does not verify: the release was altered.
    folder = build_release(incoming(env, "0.3.1"), "0.3.1", key=private)
    (folder / CHECKSUMS).write_text((folder / CHECKSUMS).read_text() + "0" * 64 + "  extra\n")
    refused("signature_invalid", "0.3.1")
    folder = build_release(incoming(env, "0.3.2"), "0.3.2", key=private)
    (folder / "NOTES.md").write_text("changed\n")
    refused("checksum", "0.3.2")
    build_release(incoming(env, "0.3.3"), "0.3.3", key=private, control=deb(name="evil", version="0.3.3-1"))
    refused("name", "0.3.3")
    build_release(incoming(env, "0.3.4"), "0.3.4", key=private, control=deb(version="0.3.4-1", arch="arm64"))
    refused("arch", "0.3.4")
    build_release(incoming(env, "0.3.5"), "0.3.5", key=private, control=deb(version="0.3.9-1"))
    refused("manifest", "0.3.5")
    build_release(incoming(env, "0.2.4"), "0.2.4", key=private)
    refused("version", "0.2.4")
    pkg.installed = "0.3.0-1"
    refused("version", "0.3.0", allow=True)  # the installed version again is not an update


def test_verify_reads_the_upload_without_following_links(node: Any, keys: Any, tmp_path: Path) -> None:
    env, _ = node
    private, public = keys
    folder = build_release(tmp_path / "elsewhere", key=private)
    incoming(env).parent.mkdir(parents=True)
    incoming(env).symlink_to(folder)
    with pytest.raises(updates.UpdateRefused, match=r"^missing"):
        updates.verify(env, "0.3.0", False, public)
    incoming(env).unlink()
    real = build_release(incoming(env), key=private)
    deb_file = real / "pelagos_0.3.0-1_amd64.deb"
    deb_file.unlink()
    deb_file.symlink_to(folder / "pelagos_0.3.0-1_amd64.deb")
    with pytest.raises(updates.UpdateRefused, match=r"^missing"):
        updates.verify(env, "0.3.0", False, public)
    assert not any(p.name.startswith(".") for p in updates.layout(env).packages_root.iterdir())


def test_min_upgrade_from_and_release_without_manifest(node: Any, keys: Any) -> None:
    env, pkg = node
    private, public = keys
    folder = build_release(incoming(env), key=private)
    data = json.loads((folder / "release.json").read_text())
    data["min_upgrade_from"] = "0.2.6"
    (folder / "release.json").write_text(json.dumps(data))
    build_release(folder, key=private, manifest=False)  # sums and signature over the new manifest
    with pytest.raises(updates.UpdateRefused, match=r"^version: 0.3.0 needs at least 0.2.6"):
        updates.verify(env, "0.3.0", False, public)
    pkg.installed = "0.2.6-1"
    assert updates.verify(env, "0.3.0", False, public).direction == "upgrade"
    # A 0.2.x release (no release.json): the package is found by its name, schema unknown.
    pkg.installed = "0.2.4-1"
    build_release(incoming(env, "0.2.5"), "0.2.5", manifest=False)
    v = updates.verify(env, "0.2.5", True, public)
    assert v.file == "pelagos_0.2.5-1_amd64.deb" and v.answer()["state_schema"] is None
    assert v.check.warnings


# update_start and apply -------------------------------------------------------------------------------


def test_start_runs_the_transient_unit_and_apply_installs(node: Any, keys: Any) -> None:
    env, pkg = node
    private, public = keys
    set_rollout(env)
    build_release(incoming(env), key=private)
    (env.node_paths.var / "series.sqlite").write_text("cache")
    out = updates.start(env, {"rollout_id": RID, "kind": "pelagos", "version": "0.3.0"}, public)
    assert out["unit"] == f"pelagos-upgrade-{RID}.service"
    run = env.runner.commands("systemd-run")[0]
    assert f"--unit=pelagos-upgrade-{RID}" in run and run.endswith(f"upgrade apply --rollout {RID}")
    lay = updates.layout(env)
    record = json.loads(lay.request(RID).read_text())
    assert record["sha256"] and record["from_version"] == "0.2.5-1" and record["package_version"] == "0.3.0-1"
    assert oct(lay.request(RID).stat().st_mode & 0o777) == "0o600"

    assert updates.apply(env, RID) == 0
    progress = json.loads(Path(out["progress"]).read_text())
    assert progress["result"] == "installed" and progress["error"] is None
    assert [s["step"] for s in progress["steps"]] == ["backup", "install", "version"]
    assert all(s["state"] == "done" for s in progress["steps"])
    assert pkg.installed == "0.3.0-1"
    stop = env.runner.commands("systemctl stop")
    assert stop == ["systemctl stop pelagos.service pelagos-collector.service"]
    assert env.runner.commands("systemctl start")
    backup = Path(progress["backup"])
    assert backup.name.endswith("-0.2.5-1.tar.gz") and oct(backup.stat().st_mode & 0o777) == "0o600"
    with tarfile.open(backup) as tar:
        names = tar.getnames()
    assert any(n.endswith("cluster.toml") for n in names) and any(n.endswith("master.key") for n in names)
    assert not any(n.endswith("series.sqlite") for n in names)
    assert json.loads(lay.previous.read_text()) == {"package_version": "0.2.5-1", "release": None}
    assert json.loads(lay.installed.read_text()) == {"package_version": "0.3.0-1", "release": "0.3.0"}
    assert (env.node_paths.var / "series.sqlite").exists()  # only a rollback drops the cache

    status = updates.status(env, {"rollout_id": RID})
    assert status["progress"]["result"] == "installed" and status["package_audit"] is None


def test_start_refusals(node: Any, keys: Any) -> None:
    env, _ = node
    _, public = keys
    build_release(incoming(env))

    def refused(reason: str, request: dict[str, Any]) -> None:
        with pytest.raises(updates.UpdateRefused) as exc:
            updates.start(env, {"rollout_id": RID, "kind": "pelagos", "version": "0.3.0", **request}, public)
        assert exc.value.reason == reason, str(exc.value)

    refused("rollout", {"rollout_id": "x"})
    refused("rollout", {})  # no rollout in cluster.toml
    set_rollout(env, version="0.3.1")
    refused("version", {})
    set_rollout(env, state="done")
    refused("rollout", {})
    set_rollout(env)
    refused("unsigned_not_accepted", {})  # allow_unsigned missing
    refused("unsigned_not_accepted", {"allow_unsigned": True})  # the rollout records no acceptance
    set_rollout(env, signature="unsigned", unsigned_accepted_by="admin")
    env.runner.responses["systemctl list-units"] = (
        f"pelagos-upgrade-{'0' * 26}.service loaded active running x\n"
    )
    refused("busy", {"allow_unsigned": True})
    env.runner.responses["systemctl list-units"] = ""
    assert updates.start(
        env, {"rollout_id": RID, "kind": "pelagos", "version": "0.3.0", "allow_unsigned": True}, public
    )
    assert env.runner.commands(f"systemctl reset-failed pelagos-upgrade-{RID}")


def test_failed_install_restarts_the_previous_release(node: Any, keys: Any) -> None:
    env, pkg = node
    private, public = keys
    set_rollout(env)
    build_release(incoming(env), key=private)
    updates.start(env, {"rollout_id": RID, "kind": "pelagos", "version": "0.3.0"}, public)
    pkg.install_ok = False
    assert updates.apply(env, RID) == 1
    progress = json.loads(updates.layout(env).progress(RID, env.node_id).read_text())
    assert progress["result"] == "failed" and "previous package left in place" in progress["error"]
    assert [(s["step"], s["state"]) for s in progress["steps"]] == [("backup", "done"), ("install", "failed")]
    assert pkg.installed == "0.2.5-1"
    assert env.runner.commands("systemctl start")


def test_apply_refuses_a_package_changed_after_verification(node: Any, keys: Any) -> None:
    env, pkg = node
    private, public = keys
    set_rollout(env)
    build_release(incoming(env), key=private)
    updates.start(env, {"rollout_id": RID, "kind": "pelagos", "version": "0.3.0"}, public)
    record = json.loads(updates.layout(env).request(RID).read_text())
    Path(record["package"]).write_text(deb(version="0.3.0-1") + "X-Evil: yes\n")
    assert updates.apply(env, RID) == 1
    assert pkg.installs == [] and not env.runner.commands("systemctl stop")


def test_rollback_to_the_kept_previous_release(node: Any, keys: Any) -> None:
    env, pkg = node
    private, public = keys
    # 0.2.5 was installed by hand: its release is uploaded after the upgrade to 0.3.0.
    set_rollout(env)
    build_release(incoming(env), key=private)
    updates.start(env, {"rollout_id": RID, "kind": "pelagos", "version": "0.3.0"}, public)
    assert updates.apply(env, RID) == 0
    (env.node_paths.var / "series.sqlite").write_text("cache")
    build_release(incoming(env, "0.2.5"), "0.2.5", manifest=False)
    with pytest.raises(updates.UpdateRefused, match=r"^unsigned_not_accepted"):
        updates.start(env, {"rollout_id": RID, "kind": "rollback", "version": "0.2.5"}, public)
    with pytest.raises(updates.UpdateRefused, match=r"^version: 0.3.0-1 is neither newer"):
        updates.start(env, {"rollout_id": RID, "kind": "rollback", "version": "0.3.0"}, public)
    out = updates.start(
        env, {"rollout_id": RID, "kind": "rollback", "version": "0.2.5", "allow_unsigned": True}, public
    )
    assert updates.apply(env, RID) == 0
    progress = json.loads(Path(out["progress"]).read_text())
    assert [s["step"] for s in progress["steps"]] == ["backup", "rollback", "version"]
    assert pkg.installed == "0.2.5-1" and "--allow-downgrades" in pkg.installs[-1]
    assert not (env.node_paths.var / "series.sqlite").exists()
    # Another version older than the installed one is never accepted.
    build_release(incoming(env, "0.2.4"), "0.2.4", manifest=False)
    with pytest.raises(updates.UpdateRefused, match=r"^version"):
        updates.verify(env, "0.2.4", True, public)


def test_engine_packages(node: Any, keys: Any) -> None:
    env, pkg = node
    _, public = keys
    pkg.engines = {"bind9": "1:9.20.11-4", "kea-dhcp4-server": "2.6.3-1"}
    set_rollout(env, kind="engine_packages", version=None, packages={"bind9": "1:9.20.15-1~deb13u1"})
    with pytest.raises(updates.UpdateRefused, match=r"^name: openssh-server"):
        updates.start(
            env, {"rollout_id": RID, "kind": "engine_packages", "packages": {"openssh-server": "1"}}, public
        )
    with pytest.raises(updates.UpdateRefused, match=r"^version: packages differ"):
        updates.start(
            env, {"rollout_id": RID, "kind": "engine_packages", "packages": {"bind9": "1:9.20.16-1"}}, public
        )
    updates.start(
        env,
        {"rollout_id": RID, "kind": "engine_packages", "packages": {"bind9": "1:9.20.15-1~deb13u1"}},
        public,
    )
    assert updates.apply(env, RID) == 0
    assert pkg.engines["bind9"] == "1:9.20.15-1~deb13u1"
    assert "--only-upgrade" in pkg.installs[-1] and not env.runner.commands("systemctl stop")
    record = json.loads(updates.layout(env).request(RID).read_text())
    assert record["from_versions"] == {"bind9": "1:9.20.11-4"}


def test_purge_keeps_the_newest_and_the_pinned(node: Any) -> None:
    env, _ = node
    lay = updates.ensure_layout(env)
    for i, v in enumerate(("0.2.5", "0.3.0", "0.3.1", "0.3.2")):
        (lay.packages(v)).mkdir()
        os.utime(lay.packages(v), (1000 + i, 1000 + i))
        b = lay.backups / f"pelagos-state-2026{i}-{v}.tar.gz"
        b.write_text("x")
        os.utime(b, (1000 + i, 1000 + i))
    lay.previous.write_text(json.dumps({"release": "0.2.5", "package_version": "0.2.5-1"}))
    removed = updates.purge(lay, 2)
    assert sorted(p.name for p in lay.packages_root.iterdir()) == ["0.2.5", "0.3.1", "0.3.2"]
    assert len(list(lay.backups.iterdir())) == 2 and len(removed) == 3


# update_status, journal_errors, helper ------------------------------------------------------------------


def test_status_of_an_unfinished_progress_without_its_unit(node: Any) -> None:
    env, _ = node
    lay = updates.ensure_layout(env)
    lay.rollout_dir(RID).mkdir()
    lay.progress(RID, env.node_id).write_text(json.dumps({"result": "running", "steps": []}))
    env.runner.responses["systemctl show"] = "LoadState=not-found\nActiveState=inactive\n"
    env.runner.responses["dpkg --audit"] = "The following packages are only half configured:\n pelagos\n"
    out = updates.status(env, {"rollout_id": RID})
    assert out["unit_state"] == "gone" and out["package_audit"]["ok"] is False
    assert out["installed"] == "0.2.5-1"
    env.runner.responses["systemctl show"] = "LoadState=loaded\nActiveState=active\n"
    out = updates.status(env, {"rollout_id": RID})
    assert out["unit_state"] == "active" and out["package_audit"] is None
    env.runner.responses["systemctl show"] = "LoadState=loaded\nActiveState=failed\n"
    assert updates.status(env, {"rollout_id": RID})["unit_state"] == "failed"


def test_journal_errors(node: Any) -> None:
    env, _ = node

    def entry(msg: str, prio: int = 6, unit: str = "pelagos.service") -> str:
        return json.dumps(
            {
                "MESSAGE": msg,
                "PRIORITY": str(prio),
                "_SYSTEMD_UNIT": unit,
                "_SYSTEMD_INVOCATION_ID": "abc",
                "__REALTIME_TIMESTAMP": "1793318400000000",
            }
        )

    env.runner.responses["journalctl"] = "\n".join(
        [
            entry("2026-10-30 10:00:00,000 INFO pelagos.app: started"),
            entry("2026-10-30 10:00:01,000 ERROR pelagos.collector: boom"),
            entry("segfault", 2, "pelagos-collector.service"),
            "not json",
        ]
    )
    out = updates.journal_errors(env, {"since": "2026-10-30T09:00:00Z"})
    assert out["count"] == 2 and [line["priority"] for line in out["lines"]] == [6, 2]
    assert out["lines"][0]["invocation_id"] == "abc" and out["lines"][0]["time"].startswith("2026-10-30")
    argv = env.runner.log[-1]
    assert argv[argv.index("--since") + 1] == "@1793350800"
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "-u"] == [
        "pelagos.service",
        "pelagos-collector.service",
        "pelagos-helper@*.service",
    ]
    for bad in (None, True, "yesterday", -5):
        with pytest.raises(updates.UpdateRefused, match=r"^since"):
            updates.journal_errors(env, {"since": bad})


def test_helper_routes_update_operations(node: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    env, _ = node
    with pytest.raises(helper.HelperError) as exc:
        helper.handle({"op": "update_verify", "version": "0.3.0"}, lambda: env, lambda _: None)
    assert exc.value.kind == "value" and str(exc.value).startswith("missing")
    env.runner.responses["journalctl"] = ""
    assert helper.handle({"op": "journal_errors", "since": 1}, lambda: env, lambda _: None)["count"] == 0


def test_cli_parser_has_upgrade_apply() -> None:
    from pelagos.cli import build_parser

    args = build_parser().parse_args(["upgrade", "apply", "--rollout", RID])
    assert args.func is updates.cmd_upgrade and args.rollout == RID
