# SPDX-License-Identifier: Apache-2.0
"""Modes and owners of the BIND files, and version.bind, in the security audit; their remediation."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from pelagos.domain import JobState, Severity
from pelagos.installer import bind_files, bindconf
from pelagos.installer.jobs import apply_plan
from pelagos.installer.security_audit import build_security_plan, run_audit
from tests.unit.installer.fakes import debian_tree, make_env

pytestmark = pytest.mark.unit


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def _files(env) -> dict:
    return {f.id: f for f in run_audit(env) if f.kind == "bind_file_mode"}


def _fix(env, ids):
    job = apply_plan(build_security_plan(env, ids), env)
    assert job.state is JobState.DONE, job.error
    return job


def _with_zone_and_log(tmp: Path) -> None:
    etc = tmp / "etc/bind"
    zone = tmp / "var/cache/bind/db.example.lan"
    zone.write_text("$TTL 60\n@ SOA ns1 h 1 60 60 60 60\n@ NS ns1\nns1 A 192.0.2.1\n")
    zone.chmod(0o644)
    log = tmp / "var/log/named/query.log"
    log.parent.mkdir(parents=True)
    log.write_text("")
    log.chmod(0o644)
    (etc / "named.conf.local").write_text(
        f'zone "example.lan" {{\n\ttype primary;\n\tfile "{zone}";\n}};\n'
        f'logging {{\n\tchannel q {{\n\t\tfile "{log}";\n\t}};\n}};\n'
    )


def test_package_modes_give_no_finding(tmp_path):
    env = debian_tree(tmp_path)
    _with_zone_and_log(tmp_path)
    assert _files(env) == {}


def test_world_writable_config_dir_back_to_debian_default(tmp_path):
    env = debian_tree(tmp_path)
    etc = tmp_path / "etc/bind"
    etc.chmod(0o777)
    found = _files(env)
    f = found["bind:bind_file_mode:config_dir"]
    assert f.severity is Severity.CRITICAL
    assert f"{etc} (0777" in f.description and "writable by everyone" in f.description
    assert f"chmod 2755 {etc}" in f.proposal
    _fix(env, [f.id])
    assert _mode(etc) == 0o2755
    assert _files(env) == {}


def test_rpm_default_for_the_config_dir(tmp_path):
    env = make_env(tmp_path, distro="rocky10")
    named = tmp_path / "etc/named"
    named.mkdir(parents=True)
    named.chmod(0o777)
    issues = bind_files.issues(env, {bind_files.CONFIG_DIR: {named}})
    assert [(i.path, f"{i.target_mode:04o}") for i in issues] == [(str(named), "0750")]


def test_keys_readable_by_everyone_are_critical(tmp_path):
    env = debian_tree(tmp_path)
    key = tmp_path / "etc/bind/rndc.key"
    key.chmod(0o644)
    f = _files(env)["bind:bind_file_mode:key_file"]
    assert f.severity is Severity.CRITICAL and "readable by everyone" in f.description
    _fix(env, [f.id])
    assert _mode(key) == 0o640


def test_zone_and_log_files_lose_world_write_only(tmp_path):
    env = debian_tree(tmp_path)
    _with_zone_and_log(tmp_path)
    zone = tmp_path / "var/cache/bind/db.example.lan"
    log = tmp_path / "var/log/named/query.log"
    zone.chmod(0o666)
    log.chmod(0o666)
    found = _files(env)
    assert set(found) == {"bind:bind_file_mode:zone_file", "bind:bind_file_mode:log_file"}
    _fix(env, list(found))
    assert _mode(zone) == 0o664 and _mode(log) == 0o664


def test_group_write_counts_for_another_group_only(tmp_path, monkeypatch):
    env = debian_tree(tmp_path)
    conf = tmp_path / "etc/bind/named.conf"
    conf.chmod(0o664)
    assert _files(env) == {}  # the caller's own group (root's on a real node)
    if os.getuid() == 0:
        os.chown(conf, -1, 4242)  # any group but root's
    else:
        monkeypatch.setattr(bind_files.os, "getgid", lambda: 4242)
    f = _files(env)["bind:bind_file_mode:config_file"]
    assert f.severity is Severity.WARNING and "writable by its group" in f.description


def test_foreign_owner_is_reported_with_chown(tmp_path, monkeypatch):
    if os.getuid() == 0:
        pytest.skip("root owns the tree, and root is always trusted")
    env = debian_tree(tmp_path)
    monkeypatch.setattr(bind_files.os, "getuid", lambda: 4242)
    f = _files(env)["bind:bind_file_mode:config_dir"]
    assert "owned by another user" in f.description and "chown root:" in f.proposal


def test_service_account_owner_is_trusted(tmp_path, monkeypatch):
    if os.getuid() == 0:
        pytest.skip("root owns the tree, and root is always trusted")
    env = debian_tree(tmp_path)
    owner = os.getuid()
    monkeypatch.setattr(bind_files.os, "getuid", lambda: 4242)
    monkeypatch.setattr(bind_files, "_uid", lambda n: owner if n == "pelagos" else None)
    assert "bind:bind_file_mode:config_dir" not in _files(env)


def test_failed_access_check_restores_every_change(tmp_path, monkeypatch):
    env = debian_tree(tmp_path)
    etc = tmp_path / "etc/bind"
    key = etc / "rndc.key"
    etc.chmod(0o777)
    key.chmod(0o644)
    calls = []

    def check(env, item):
        calls.append(item["path"])
        return "bind cannot -r it any more" if item["path"] == str(key) else None

    monkeypatch.setattr(bind_files, "access_check", check)
    items = [i.to_dict() for i in bind_files.issues(env, {"config_dir": {etc}, "key_file": {key}})]
    with pytest.raises(RuntimeError, match="restored"):
        bind_files.apply(env, items)
    assert calls == [str(etc), str(key)]
    assert _mode(etc) == 0o777 and _mode(key) == 0o644


def test_version_bind(tmp_path):
    env = debian_tree(tmp_path)
    ids = {f.id for f in run_audit(env)}
    assert "bind:version_disclosed:options" in ids
    f = next(f for f in run_audit(env) if f.kind == "version_disclosed")
    assert "9.20.30" in f.description and f.proposal == 'version "none";'
    _fix(env, [f.id])
    options = (tmp_path / "etc/bind/named.conf.options").read_text()
    assert 'version "none";' in options
    assert "version_disclosed" not in {f.kind for f in run_audit(env)}


@pytest.mark.parametrize(
    ("value", "flagged"), [('"9.20.30-1~deb13u1-Debian"', True), ('"hidden"', False), ("none", False)]
)
def test_version_set_by_hand(tmp_path, value, flagged):
    env = debian_tree(tmp_path)
    opts = tmp_path / "etc/bind/named.conf.options"
    opts.write_text(opts.read_text().replace("};", f"\tversion {value};\n}};"))
    bindconf.load_files(env.paths.named_conf)  # still parses
    assert ("version_disclosed" in {f.kind for f in run_audit(env)}) is flagged
