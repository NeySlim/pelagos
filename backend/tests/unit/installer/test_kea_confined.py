# SPDX-License-Identifier: Apache-2.0
"""Root touches only Kea files: includes outside the Kea directory or through symlinks are refused."""

import grp
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from pelagos.installer import keasetup

pytestmark = pytest.mark.unit


def _group() -> str:
    gids = os.getgroups()
    for name in ("_kea", "kea"):
        try:
            if grp.getgrnam(name).gr_gid in gids:
                return name
        except KeyError:
            continue
    return grp.getgrgid(os.getgid()).gr_name


def _env(conf_dir: Path):
    return SimpleNamespace(
        paths=SimpleNamespace(kea_conf_dir=conf_dir, kea_user="root", kea_group=_group()),
        dry_run=False,
        relabel=lambda paths: None,
    )


def _tree(tmp_path: Path):
    kea = tmp_path / "etc/kea"
    kea.mkdir(parents=True)
    outside = tmp_path / "var/lib/pelagos/evil.json"
    outside.parent.mkdir(parents=True)
    outside.write_text('{"a": 1}')
    victim = tmp_path / "shadow"
    victim.write_text('{"b": 2}')
    link = kea / "link.json"
    link.symlink_to(victim)
    conf = kea / "kea-dhcp4.conf"
    conf.write_text(
        '{"Dhcp4": {"user-context": {"x": <?include "' + str(outside) + '"?>, '
        '"y": <?include "' + str(link) + '"?>}}}'
    )
    for f in (outside, victim, conf):
        os.chmod(f, 0o600)
    return conf, outside, victim, link


def test_includes_outside_or_through_links_keep_their_mode(tmp_path):
    conf, outside, victim, link = _tree(tmp_path)
    out = keasetup.ensure_config_writable(_env(conf.parent), conf)
    assert f"{outside} lies outside the Kea configuration directory" in out
    assert f"{link} lies outside" in out or f"{link} is a symlink" in out
    assert outside.stat().st_mode & 0o777 == 0o600 and victim.stat().st_mode & 0o777 == 0o600
    assert conf.stat().st_mode & 0o060 == 0o060


def test_write_files_refuses_foreign_paths(tmp_path):
    conf, outside, victim, link = _tree(tmp_path)
    env = _env(conf.parent)
    for target in (outside, link):
        with pytest.raises(RuntimeError, match="outside|symlink"):
            keasetup.write_files(env, "kea4", conf, {conf: "{}", target: "{}"}, "t", restart=False)
    assert outside.read_text() == '{"a": 1}' and victim.read_text() == '{"b": 2}'


def test_confined_accepts_kea_files(tmp_path):
    conf, *_ = _tree(tmp_path)
    env = _env(conf.parent)
    assert keasetup.confined(env, conf, conf) is None
    assert keasetup.confined(env, conf, conf.parent / "new.json") is None
    assert keasetup.confined(env, conf, conf.parent / ".." / "x.json") is not None
