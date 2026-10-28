# SPDX-License-Identifier: Apache-2.0
"""Helper operation bind_user_write: only an included user file, same content as read, no symlink."""

from __future__ import annotations

import hashlib
import os

import pytest

from pelagos.installer import helper
from tests.unit.installer.fakes import debian_tree

pytestmark = pytest.mark.unit


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def env(tmp_path):
    return debian_tree(tmp_path / "host")


def _call(env, path, content, sha):
    return helper.handle(
        {"op": "bind_user_write", "path": str(path), "content": content, "sha256": sha},
        lambda: env,
        lambda _m: None,
    )


def test_writes_an_included_user_file_and_keeps_its_mode(env):
    local = env.paths.named_conf.parent / "named.conf.local"
    local.chmod(0o644)
    before = os.stat(local)
    out = _call(env, local, "# moved to zones.conf by Pelagos\n", _sha(local.read_bytes()))
    assert local.read_text() == "# moved to zones.conf by Pelagos\n"
    after = os.stat(local)
    assert out["sha256"] == _sha(local.read_bytes())
    assert (after.st_mode, after.st_uid, after.st_gid) == (before.st_mode, before.st_uid, before.st_gid)
    assert sorted(p.name for p in local.parent.iterdir() if "pelagos-helper" in p.name) == []


def test_refuses_a_changed_file(env):
    local = env.paths.named_conf.parent / "named.conf.local"
    old = local.read_text()
    with pytest.raises(helper.HelperError, match="changed since it was read"):
        _call(env, local, "x;\n", _sha(b"something else"))
    assert local.read_text() == old


def test_refuses_files_named_conf_does_not_include(env):
    other = env.paths.named_conf.parent / "rndc.key"
    with pytest.raises(helper.HelperError, match="not a BIND configuration file"):
        _call(env, other, "", _sha(other.read_bytes()))
    with pytest.raises(helper.HelperError, match="absolute"):
        _call(env, "named.conf.local", "", "")


def test_refuses_the_rndc_key_even_when_included(env):
    key = env.paths.rndc_key
    with env.paths.named_conf.open("a") as fh:
        fh.write(f'include "{key}";\n')
    with pytest.raises(helper.HelperError, match="not a BIND configuration file"):
        _call(env, key, "", _sha(key.read_bytes()))


def test_refuses_the_pelagos_include_dir(env):
    inc = env.paths.bind_include_dir
    inc.mkdir(parents=True, exist_ok=True)
    managed = inc / "pelagos.conf"
    managed.write_text("")
    with env.paths.named_conf.open("a") as fh:
        fh.write(f'include "{managed}";\n')
    with pytest.raises(helper.HelperError, match="not a BIND configuration file"):
        _call(env, managed, "x;\n", _sha(b""))


def test_refuses_symlinks_and_hard_links(env, tmp_path):
    conf_dir = env.paths.named_conf.parent
    local = conf_dir / "named.conf.local"
    elsewhere = tmp_path / "victim"
    elsewhere.write_text("keep\n")
    local.unlink()
    local.symlink_to(elsewhere)
    with pytest.raises(helper.HelperError, match="symlink"):
        _call(env, local, "x;\n", _sha(b"keep\n"))
    assert elsewhere.read_text() == "keep\n"

    local.unlink()
    os.link(elsewhere, local)
    with pytest.raises(helper.HelperError, match="hard links"):
        _call(env, local, "x;\n", _sha(b"keep\n"))
    assert elsewhere.read_text() == "keep\n"


def test_operation_is_listed():
    assert "bind_user_write" in helper.OPERATIONS
