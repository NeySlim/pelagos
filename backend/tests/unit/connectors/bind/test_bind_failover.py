# SPDX-License-Identifier: Apache-2.0
"""Promotion of a copy (DDNS failover, batch D3): the copy's content written as text to a new file,
the zone declared primary with the recorded policy, validated by named-checkconf and named-checkzone."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.connectors.bind import failover
from pelagos.connectors.bind.configplan import ConfigPlanner, validate_render
from pelagos.connectors.bind.rndc import find_binary
from pelagos.domain import RRset, Zone, ZoneKind, ZoneSource
from pelagos.domain.plan import Change, ChangeOp

pytestmark = pytest.mark.unit

POLICY = ["grant ddi-admin zonesub ANY", "grant kea-ddns zonesub A AAAA DHCID"]
SECRET = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTI="
COPY = [
    RRset("ddns.lan.", "SOA", 300, ["ns1.example.net. hostmaster.ddns.lan. 7 3600 900 1209600 300"]),
    RRset("ddns.lan.", "NS", 300, ["ns1.example.net."]),
    RRset("h1.ddns.lan.", "A", 60, ["192.0.2.161"]),
    RRset("h1.ddns.lan.", "DHCID", 60, ["AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="]),
]


def make_tree(root: Path) -> tuple[Path, Path, Path]:
    etc = root / "etc"
    inc = etc / "pelagos"
    inc.mkdir(parents=True)
    zone_dir = root / "var" / "pelagos"
    zone_dir.mkdir(parents=True)
    (etc / "named.conf").write_text(
        f'options {{\n\tdirectory "{root}/var";\n\trecursion no;\n}};\ninclude "{inc}/pelagos.conf";\n'
    )
    keys = ("ddi-read", "ddi-admin", "kea-ddns")
    (inc / "keys.conf").write_text(
        "# pelagos:managed v1\n"
        + "".join(f'key "{k}" {{ algorithm hmac-sha256; secret "{SECRET}"; }};\n' for k in keys)
    )
    (inc / "acls.conf").write_text("# pelagos:managed v1\n")
    (inc / "zones.conf").write_text(
        "# pelagos:managed v1\n"
        f'zone "ddns.lan" {{ type secondary; file "{zone_dir}/ddns.lan.db"; masterfile-format raw;'
        " primaries { 192.0.2.1 port 5353 key ddi-read; }; allow-transfer { key ddi-read; }; };\n"
    )
    (inc / "pelagos.conf").write_text(
        "# pelagos:managed v1\n" + "".join(f'include "{inc}/{n}.conf";\n' for n in ("keys", "acls", "zones"))
    )
    return etc / "named.conf", inc, zone_dir


def copy_zone(zone_dir: Path) -> Zone:
    return Zone(
        name="ddns.lan.",
        kind=ZoneKind.SECONDARY,
        file=str(zone_dir / "ddns.lan.db"),
        primaries=["192.0.2.1 port 5353 key ddi-read"],
        allow_transfer=["key ddi-read"],
        source=ZoneSource.PELAGOS,
        extra={"masterfile-format": "raw"},
    )


def promote_change(zone_dir: Path, epoch: int = 2) -> Change:
    options = {"allow-transfer": ["key ddi-read"], "also-notify": ["192.0.2.3"]}
    after = failover.promoted_after(copy_zone(zone_dir), POLICY, options, {"from": "n1", "epoch": epoch})
    return Change(ChangeOp.REPLACE, "_default/ddns.lan.", after=after)


def render(conf: Path, inc: Path, zone_dir: Path, change: Change, reader=lambda z, v: COPY):
    planner = ConfigPlanner(conf, inc, "n2", zone_dir=zone_dir)
    planner.zone_reader = reader
    planner.zone_change(change)
    return planner, planner.finish()


def test_zone_text_puts_the_soa_first():
    text = failover.zone_text("ddns.lan", list(reversed(COPY)))
    lines = text.splitlines()
    assert lines[1].startswith("ddns.lan. 300 IN SOA ns1.example.net.")
    assert "h1.ddns.lan. 60 IN A 192.0.2.161" in lines
    with pytest.raises(ValueError, match="no SOA"):
        failover.zone_text("ddns.lan", COPY[1:])


def test_promoted_after_recopies_the_policy_and_drops_copy_settings(tmp_path):
    after = failover.promoted_after(copy_zone(tmp_path), POLICY, {}, {"from": "n1", "epoch": 3})
    assert after["kind"] == "primary" and after["primaries"] == [] and after["file"] is None
    assert after["update_policy"] == POLICY and after["allow_update"] == []
    assert after["allow_transfer"] == ["key ddi-read"] and after["extra"] == {}
    assert after["promote"] == {"from": "n1", "epoch": 3} and "source" not in after
    legacy = failover.promoted_after(copy_zone(tmp_path), [], {"allow-update": ["key kea-ddns"]}, {})
    assert legacy["update_policy"] == [] and legacy["allow_update"] == ["key kea-ddns"]


def test_promotion_writes_the_copy_as_text_and_declares_a_primary(tmp_root):
    conf, inc, zone_dir = make_tree(tmp_root)
    planner, result = render(conf, inc, zone_dir, promote_change(zone_dir))
    assert result.errors == []
    path = zone_dir / "ddns.lan.e2.db"
    assert result.zone_files[path] == failover.zone_text("ddns.lan.", COPY)
    zones = " ".join(result.texts[inc / "zones.conf"].split())
    assert "type primary;" in zones and f'file "{path}";' in zones
    assert "grant kea-ddns zonesub A AAAA DHCID;" in zones and "masterfile-format" not in zones
    assert "primaries" not in zones and "also-notify { 192.0.2.3; };" in zones
    assert result.requires_confirmation
    [change] = result.changes
    assert change.before["kind"] == "secondary" and change.after["promote"]["epoch"] == 2
    if find_binary("named-checkconf") is None:
        pytest.fail("named-checkconf is required by the unit tier")
    checks = validate_render(planner, find_binary("named-checkconf"), find_binary("named-checkzone"))
    assert all(v.ok for v in checks), [v.output for v in checks]


def test_promotion_replayed_after_apply_writes_nothing_new(tmp_root):
    conf, inc, zone_dir = make_tree(tmp_root)
    _planner, result = render(conf, inc, zone_dir, promote_change(zone_dir))
    for path, text in result.texts.items():
        path.write_text(text)

    def unreadable(zone, view):
        raise AssertionError("the copy is not read again")

    _planner, again = render(conf, inc, zone_dir, promote_change(zone_dir), unreadable)
    assert again.errors == [] and again.zone_files == {} and again.changed_paths() == []


def test_promotion_refusals(tmp_root):
    conf, inc, zone_dir = make_tree(tmp_root)

    def down(zone, view):
        raise OSError("connection refused")

    _p, result = render(conf, inc, zone_dir, promote_change(zone_dir), down)
    assert "cannot read the copy of ddns.lan.: connection refused" in result.errors[0]
    _p, result = render(conf, inc, zone_dir, promote_change(zone_dir), lambda z, v: COPY[1:])
    assert "no SOA" in result.errors[0]
    added = promote_change(zone_dir)
    added.op = ChangeOp.ADD
    _p, result = render(conf, inc, zone_dir, added)
    assert result.errors  # a promotion replaces an existing copy
    # Already promoted at another epoch: nothing to promote.
    _p, first = render(conf, inc, zone_dir, promote_change(zone_dir))
    for path, text in first.texts.items():
        path.write_text(text)
    _p, result = render(conf, inc, zone_dir, promote_change(zone_dir, epoch=3))
    assert "not a copy here (primary)" in result.errors[0]


def primary_tree(root: Path, file: str) -> tuple[Path, Path, Path]:
    conf, inc, zone_dir = make_tree(root)
    (inc / "zones.conf").write_text(
        "# pelagos:managed v1\n"
        f'zone "ddns.lan" {{ type primary; file "{file}"; allow-transfer {{ key ddi-read; }};'
        " update-policy { grant kea-ddns zonesub A AAAA DHCID; }; };\n"
    )
    return conf, inc, zone_dir


def demote_change(epoch: int = 2) -> Change:
    zone = Zone(name="ddns.lan.", kind=ZoneKind.PRIMARY, allow_transfer=["key ddi-read"])
    after = failover.demoted_after(zone, ["192.0.2.2 key ddi-read"], {"to": "n2", "epoch": epoch})
    return Change(ChangeOp.REPLACE, "_default/ddns.lan.", after=after)


def test_file_epoch_and_copy_path(tmp_path):
    assert failover.file_epoch("/z/ddns.lan.e12.db") == 12
    assert failover.file_epoch("/z/ddns.lan.db") is None and failover.file_epoch(None) is None
    assert failover.copy_path(tmp_path, "ddns.lan.", 3) == tmp_path / "ddns.lan.e3.copy"


def test_demotion_declares_a_copy_and_moves_the_zone_files_out(tmp_root):
    zone_file = tmp_root / "var" / "ddns.lan.db"
    conf, inc, zone_dir = primary_tree(tmp_root, "ddns.lan.db")  # relative to `directory`
    zone_file.write_text("stale\n")
    Path(f"{zone_file}.jnl").write_text("journal\n")
    planner, result = render(conf, inc, zone_dir, demote_change())
    assert result.errors == []
    assert result.removed == [zone_file, Path(f"{zone_file}.jnl")]
    zones = " ".join(result.texts[inc / "zones.conf"].split())
    assert "type secondary;" in zones and f'file "{zone_dir}/ddns.lan.e2.copy";' in zones
    assert "primaries { 192.0.2.2 key ddi-read; };" in zones and "update-policy" not in zones
    assert result.requires_confirmation and "+++ /dev/null (moved to the plan backup)" in result.diff()
    [change] = result.changes
    assert change.before["kind"] == "primary" and change.after["demote"] == {"to": "n2", "epoch": 2}
    checks = validate_render(planner, find_binary("named-checkconf"), find_binary("named-checkzone"))
    assert all(v.ok for v in checks), [v.output for v in checks]
    # Applied: a replay finds nothing more to change; a primary is required otherwise.
    for path, text in result.texts.items():
        path.write_text(text)
    _p, again = render(conf, inc, zone_dir, demote_change())
    assert again.errors == [] and again.changed_paths() == [] and again.removed == []
    _p, other = render(conf, inc, zone_dir, demote_change(epoch=3))
    assert "not a primary here (secondary)" in other.errors[0]
