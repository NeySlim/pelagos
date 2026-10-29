# SPDX-License-Identifier: Apache-2.0
"""Folders the services need, fixed as root (installer.path_access): the security finding, its
narrow remediation with rollback, and the postinst's `ensure` that never touches an existing folder."""

# ruff: noqa: S103

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from pelagos.installer import path_access, security_audit
from tests.unit.installer.fakes import make_env

pytestmark = pytest.mark.unit
as_user = pytest.mark.skipif(os.geteuid() == 0, reason="the checks are made for a non-root service account")


def bind_tree(tmp_path: Path) -> object:
    env = make_env(tmp_path)
    etc = env.paths.named_conf.parent
    etc.mkdir(parents=True, exist_ok=True)
    cache = etc / "cache"
    cache.mkdir()
    env.paths.bind_include_dir.mkdir(parents=True, exist_ok=True)
    env.paths.named_conf.write_text(f'options {{\n\tdirectory "{cache}";\n}};\n')
    return env


@pytest.fixture
def ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """Owner and group names resolve to this process (no bind account needed), chown is a no-op."""
    me = SimpleNamespace(pw_uid=os.getuid(), gr_gid=os.getgid(), pw_name="me", gr_name="me")
    monkeypatch.setattr(path_access.pwd, "getpwnam", lambda _n: me)
    monkeypatch.setattr(path_access.grp, "getgrnam", lambda _n: me)
    monkeypatch.setattr(path_access.os, "chown", lambda *_a, **_k: None)


@as_user
def test_unwritable_directory_gives_a_create_finding(tmp_path: Path) -> None:
    env = bind_tree(tmp_path)
    cache = env.paths.named_conf.parent / "cache"
    os.chmod(cache, 0o555)
    try:
        fixes = path_access.fixes(env)
        findings = [f for f in security_audit._path_findings(env)]
    finally:
        os.chmod(cache, 0o755)
    (fix,) = [f for f in fixes if f.purpose == "zone_dir"]
    assert fix.action == "create_dir" and fix.path == cache / "pelagos" and fix.mode == 0o2775
    assert fix.command() == f"install -d -o bind -g bind -m 2775 {cache / 'pelagos'}"
    (finding,) = [f for f in findings if f.subject == str(cache / "pelagos")]
    assert finding.id == f"bind:path_access:{cache / 'pelagos'}" and finding.kind == "path_access"
    assert finding.details["remediation"] == "path_access"
    assert "(absent -> 2775 bind:bind)" in finding.proposal


def test_writable_parent_needs_no_fix(tmp_path: Path) -> None:
    env = bind_tree(tmp_path)
    assert [f for f in path_access.fixes(env) if f.purpose == "zone_dir"] == []


def test_allowed_only_under_the_engine_trees_without_links(tmp_path: Path) -> None:
    env = bind_tree(tmp_path)
    cache = env.paths.named_conf.parent / "cache"
    assert path_access.allowed(env, cache / "pelagos")
    assert not path_access.allowed(env, cache)  # named's directory itself is never changed
    assert not path_access.allowed(env, tmp_path / "home" / "x")
    (tmp_path / "elsewhere").mkdir()
    (cache / "link").symlink_to(tmp_path / "elsewhere")
    assert not path_access.allowed(env, cache / "link" / "pelagos")


@as_user
def test_apply_creates_the_folder_and_undoes_on_failure(
    tmp_path: Path, ids: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = bind_tree(tmp_path)
    cache = env.paths.named_conf.parent / "cache"
    os.chmod(cache, 0o755)
    # The service account cannot write `cache` in the audit's eyes; the test process (root-like) can.
    monkeypatch.setattr(path_access, "_writable", lambda st, uid, groups: False)
    items = [f.to_dict() for f in path_access.fixes(env) if f.purpose == "zone_dir"]
    assert items and items[0]["action"] == "create_dir"
    out = path_access.apply(env, items)
    assert f"{cache / 'pelagos'}: absent -> 2775" in out
    assert stat.S_IMODE((cache / "pelagos").stat().st_mode) == 0o2775
    (cache / "pelagos").rmdir()

    def broken(*_a: object) -> None:
        raise PermissionError("chmod refused")

    monkeypatch.setattr(os, "chmod", broken)
    with pytest.raises(RuntimeError, match="restored"):
        path_access.apply(env, items)
    assert not (cache / "pelagos").exists()


def test_apply_skips_what_is_not_a_fix_any_more(tmp_path: Path) -> None:
    env = bind_tree(tmp_path)
    out = path_access.apply(env, [{"action": "create_dir", "path": str(tmp_path / "etc" / "passwd.d")}])
    assert "nothing to do any more" in out


def test_ensure_creates_missing_folders_only_and_is_idempotent(tmp_path: Path, ids: None) -> None:
    env = bind_tree(tmp_path)
    cache = env.paths.named_conf.parent / "cache"
    os.chmod(cache, 0o755)
    env.dry_run = True
    assert path_access.ensure(env) == [f"dry run: install -d -o bind -g bind -m 2775 {cache / 'pelagos'}"]
    env.dry_run = False
    first = path_access.ensure(env)
    assert first == [f"created {cache / 'pelagos'}: absent -> {path_access._describe(cache / 'pelagos')}"]
    assert stat.S_IMODE(cache.stat().st_mode) == 0o755  # named's directory itself untouched
    assert path_access.ensure(env) == []
