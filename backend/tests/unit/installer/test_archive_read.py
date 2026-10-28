# SPDX-License-Identifier: Apache-2.0
"""Helper operation `archive_read`: only regular files under the layout's BIND and Kea folders."""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace

import pytest

from pelagos.installer import archive_read, helper

pytestmark = pytest.mark.unit


def layout(root: Path) -> SimpleNamespace:
    etc_bind = root / "etc" / "bind"
    return SimpleNamespace(
        named_conf=etc_bind / "named.conf",
        bind_include_dir=etc_bind / "pelagos",
        zone_dir=root / "var" / "cache" / "bind",
        bind_zone_dir_pelagos=root / "var" / "cache" / "bind" / "pelagos",
        kea_conf_dir=root / "etc" / "kea",
        kea_lease_dir=root / "var" / "lib" / "kea",
        rndc_key=etc_bind / "rndc.key",
        rndc_conf_pelagos=etc_bind / "pelagos" / "rndc-pelagos.conf",
    )


@pytest.fixture
def tree(tmp_path: Path) -> SimpleNamespace:
    paths = layout(tmp_path)
    for d in (paths.bind_include_dir, paths.zone_dir, paths.kea_conf_dir, paths.kea_lease_dir):
        d.mkdir(parents=True)
    paths.named_conf.write_text("options {};\n")
    (paths.zone_dir / "Kexample.lan.+013+12345.private").write_text("Private-key-format: v1.3\n")
    (paths.zone_dir / "Kexample.lan.+013+12345.key").write_text("example.lan. DNSKEY\n")
    (paths.zone_dir / "db.other").write_text("x")
    (paths.kea_conf_dir / "kea-dhcp4.conf").write_text("{}")
    (tmp_path / "secret").write_text("outside")
    return paths


def test_reads_layout_files_with_mode_and_owner(tree: SimpleNamespace) -> None:
    out = archive_read.read(
        {"paths": [str(tree.named_conf), str(tree.kea_conf_dir / "kea-dhcp4.conf")]}, tree
    )
    assert [f["path"] for f in out["files"]] == [
        str(tree.named_conf),
        str(tree.kea_conf_dir / "kea-dhcp4.conf"),
    ]
    first = out["files"][0]
    assert base64.b64decode(first["data"]) == b"options {};\n"
    assert isinstance(first["mode"], int) and ":" in first["owner"]
    assert out["unreadable"] == []


def test_refuses_paths_outside_the_layout(tree: SimpleNamespace, tmp_path: Path) -> None:
    link = tree.kea_conf_dir / "escape.conf"
    link.symlink_to(tmp_path / "secret")
    asked = [
        str(tmp_path / "secret"),
        str(link),
        str(tree.kea_conf_dir / ".." / ".." / "secret"),
        "relative/file",
        str(tree.kea_conf_dir),
        "/etc/shadow",
    ]
    out = archive_read.read({"paths": asked}, tree)
    assert out["files"] == []
    assert out["unreadable"] == asked
    # A missing file is neither returned nor reported.
    assert archive_read.read({"paths": [str(tree.kea_lease_dir / "none.csv")]}, tree) == {
        "files": [],
        "unreadable": [],
    }


def test_patterns_expand_inside_the_layout_only(tree: SimpleNamespace, tmp_path: Path) -> None:
    out = archive_read.read(
        {
            "patterns": [
                {"dir": str(tree.zone_dir), "glob": "Kexample.lan.+*"},
                {"dir": str(tmp_path), "glob": "*"},
                {"dir": str(tree.zone_dir), "glob": "../*"},
            ]
        },
        tree,
    )
    assert sorted(Path(f["path"]).name for f in out["files"]) == [
        "Kexample.lan.+013+12345.key",
        "Kexample.lan.+013+12345.private",
    ]


def test_broad_roots_are_dropped() -> None:
    paths = layout(Path("/"))
    paths.named_conf = Path("/etc/named.conf")
    paths.bind_include_dir = Path("/etc/named/pelagos")
    roots, _files = archive_read.allowed_roots(paths)
    assert Path("/etc") not in roots and Path("/") not in roots
    assert Path("/etc/named") in roots


def test_dispatched_by_the_helper(tree: SimpleNamespace) -> None:
    assert "archive_read" in helper.OPERATIONS
    out = helper.handle(
        {"op": "archive_read", "paths": [str(tree.named_conf)]},
        lambda: SimpleNamespace(paths=tree),
        lambda _msg: None,
    )
    assert len(out["files"]) == 1
