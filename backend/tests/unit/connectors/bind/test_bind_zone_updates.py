# SPDX-License-Identifier: Apache-2.0
"""Zone mode: which update rules make a primary zone dynamic, inheritance included."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.connectors.bind.namedconf.resolve import ConfigFiles, build_tree, inherited_zone_lists
from pelagos.domain import zone_updates
from pelagos.domain.dns import Zone, ZoneKind
from pelagos.services.dns_extras import zone_mode

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("elements", "expected"),
    [
        (None, False),
        ([], False),
        (["none"], False),
        (['"none"'], False),
        (["! any"], False),
        (["!any", "key x"], False),
        (["none", "key x"], True),
        (["key ddi-admin"], True),
        (["192.0.2.1"], True),
    ],
)
def test_allow_update_permits(elements, expected):
    assert zone_updates.allow_update_permits(elements) is expected


def test_effective_allow_update_and_policy():
    assert zone_updates.effective_allow_update(None, ["none"], ["key x"]) == ["none"]
    assert zone_updates.effective_allow_update(None, None) is None
    assert zone_updates.takes_updates(True, ["none"])
    assert not zone_updates.takes_updates(False, None)


def _modes(tmp_path: Path, text: str) -> dict[tuple[str, str], str]:
    (tmp_path / "named.conf").write_text(text)
    tree = build_tree(ConfigFiles.load(tmp_path / "named.conf"), "n1")
    return {(z.view, z.name): zone_mode(z) for z in tree.zones}


def test_zone_mode_with_inherited_rules(tmp_path: Path):
    modes = _modes(
        tmp_path,
        'options { directory "/tmp"; allow-update { key ddi-admin; }; };\n'
        'zone "inherit.lan" { type primary; file "a"; };\n'
        'zone "none.lan" { type primary; file "b"; allow-update { none; }; };\n'
        'zone "local.lan" { type primary; file "c"; update-policy local; };\n',
    )
    assert modes == {
        ("_default", "inherit.lan."): "dynamic",
        ("_default", "none.lan."): "static",
        ("_default", "local.lan."): "dynamic",
    }
    modes = _modes(
        tmp_path,
        'options { directory "/tmp"; };\n'
        'view "a" { allow-update { key k; }; zone "x.lan" { type primary; file "a"; }; };\n'
        'view "b" { zone "x.lan" { type primary; file "b"; allow-update { !any; }; }; '
        'zone "y.lan" { type primary; file "c"; }; };\n',
    )
    assert modes == {("a", "x.lan."): "dynamic", ("b", "x.lan."): "static", ("b", "y.lan."): "static"}
    assert zone_mode(Zone(name="s.lan.", kind=ZoneKind.SECONDARY)) != "static"


def test_also_notify_and_allow_transfer_inherit_from_view_then_options(tmp_path: Path):
    (tmp_path / "named.conf").write_text(
        "options { also-notify { 192.0.2.5; }; allow-transfer { key ddi-read; }; };\n"
        'view "inside" { allow-transfer { 192.0.2.2; }; zone "a.lan" { type primary; file "a"; }; };\n'
        'view "outside" { also-notify { 192.0.2.99; }; zone "a.lan" { type primary; file "b"; }; };\n'
    )
    found = inherited_zone_lists(ConfigFiles.load(tmp_path / "named.conf"))
    assert found[None] == {"also_notify": ["192.0.2.5"], "allow_transfer": ["key ddi-read"]}
    assert found["inside"] == {"also_notify": ["192.0.2.5"], "allow_transfer": ["192.0.2.2"]}
    assert found["outside"] == {"also_notify": ["192.0.2.99"], "allow_transfer": ["key ddi-read"]}
