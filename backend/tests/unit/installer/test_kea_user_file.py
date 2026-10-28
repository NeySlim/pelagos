# SPDX-License-Identifier: Apache-2.0
"""Helper operation kea_file_write: only the host's Kea files and their includes, checked and atomic."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from pelagos.installer import helper, kea_user_file


def layout(tmp_path: Path) -> SimpleNamespace:
    kea = tmp_path / "kea"
    kea.mkdir()
    (kea / "tsig-keys.json").write_text('"tsig-keys": [],\n')
    (kea / "kea-dhcp-ddns.conf").write_text(
        f'{{"DhcpDdns": {{\n<?include "{kea}/tsig-keys.json"?>\n"ip-address": "127.0.0.1"}}}}\n'
    )
    (kea / "other.json").write_text("{}")
    return SimpleNamespace(kea_conf=lambda daemon: kea / f"{daemon}.conf", kea_conf_dir=kea)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_includes_are_allowed_other_files_are_not(tmp_path):
    paths = layout(tmp_path)
    kea = paths.kea_conf_dir
    assert kea_user_file.allowed_files(paths) == {kea / "kea-dhcp-ddns.conf", kea / "tsig-keys.json"}
    env = SimpleNamespace(paths=paths)
    target = kea / "tsig-keys.json"
    target.chmod(0o640)
    out = kea_user_file.write(env, str(target), '"tsig-keys": [1],\n', sha(target))
    assert target.read_text() == '"tsig-keys": [1],\n' and out["sha256"] == sha(target)
    assert target.stat().st_mode & 0o777 == 0o640
    with pytest.raises(ValueError, match="not a Kea configuration file"):
        kea_user_file.write(env, str(kea / "other.json"), "{}", sha(kea / "other.json"))
    with pytest.raises(ValueError, match="changed since it was read"):
        kea_user_file.write(env, str(target), "x", "0" * 64)


def test_dry_run_checks_and_writes_nothing(tmp_path):
    paths = layout(tmp_path)
    target = paths.kea_conf_dir / "kea-dhcp-ddns.conf"
    before = target.read_text()
    out = helper.handle(
        {
            "op": "kea_file_write",
            "path": str(target),
            "content": "{}",
            "sha256": sha(target),
            "dry_run": True,
        },
        lambda: SimpleNamespace(paths=paths),
        lambda _m: None,
    )
    assert out["dry_run"] and target.read_text() == before
