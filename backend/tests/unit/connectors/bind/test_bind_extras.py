# SPDX-License-Identifier: Apache-2.0
"""Pure parts of the BIND extras: operation targets, catalog content, DNSSEC policies and status,
added zones, view targets and the per-node rendering of a zone plan sent to peers."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.connectors.bind import addzone, catalog, dnssec, ops
from pelagos.connectors.bind import rrset as rr
from pelagos.connectors.bind.configplan import ConfigPlanner
from pelagos.connectors.bind.namedconf.resolve import ConfigFiles
from pelagos.connectors.bind.rndc import parse_dnssec_status
from pelagos.domain.dns import RRset, Zone, ZoneKind, ZoneSource
from pelagos.domain.plan import Change, ChangeOp

pytestmark = pytest.mark.unit

STATUS = """dnssec-policy: fast
current time:  Sat Oct 24 18:32:13 2026

key: 51011 (ECDSAP256SHA256), CSK
  published:      yes - since Sat Oct 24 18:32:10 2026
  key signing:    yes - since Sat Oct 24 18:32:10 2026
  zone signing:   yes - since Sat Oct 24 18:32:10 2026

  Next rollover scheduled on Mon Nov 23 18:32:10 2026
  - goal:           omnipresent
  - dnskey:         rumoured
  - ds:             hidden
  - zone rrsig:     rumoured
  - key rrsig:      rumoured
"""
DNSKEY = "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="


def test_operation_targets_and_arguments():
    assert ops.target("rollover", "example.lan", None) == "op:rollover/_default/example.lan."
    assert ops.parse_target("op:notify/inside/example.lan.") == ("notify", "inside", "example.lan.")
    assert ops.rndc_args("notify", "example.lan.", "inside", {}) == ["notify", "example.lan", "IN", "inside"]
    assert ops.rndc_args("dnssec-rollover", "example.lan", None, {"key_id": "12", "when": "now"}) == [
        "dnssec", "-rollover", "-key", "12", "-when", "now", "example.lan",
    ]  # fmt: skip
    assert ops.rndc_args("dnssec-checkds", "example.lan", None, {"state": "withdrawn"}) == [
        "dnssec", "-checkds", "withdrawn", "example.lan",
    ]  # fmt: skip
    assert ops.rndc_args("sync", "example.lan", None, {"clean": True}) == ["sync", "-clean", "example.lan"]
    assert ops.rndc_args("sync", "example.lan", "inside", {}) == ["sync", "example.lan", "IN", "inside"]
    for bad in (
        lambda: ops.parse_target("op:rm/_default/x."),
        lambda: ops.parse_target("zones/x"),
        lambda: ops.check_args("notify", {"key_id": 1}),
        lambda: ops.check_args("dnssec-rollover", {}),
        lambda: ops.check_args("dnssec-rollover", {"key_id": 70000}),
        lambda: ops.check_args("dnssec-rollover", {"key_id": 1, "when": "tomorrow; rm"}),
        lambda: ops.check_args("dnssec-checkds", {"state": "maybe"}),
    ):
        with pytest.raises(ops.OpError):
            bad()


def test_catalog_members_and_changes():
    label = catalog.member_label("member1.lan")
    assert label == catalog.member_label("MEMBER1.LAN.") and len(label) == 40
    rrsets = [
        RRset("cat.lan.", "SOA", 0, ["invalid. invalid. 1 3600 900 1209600 0"]),
        RRset("version.cat.lan.", "TXT", 0, ['"2"']),
        RRset(f"{label}.zones.cat.lan.", "PTR", 0, ["member1.lan."]),
        RRset(f"group.{label}.zones.cat.lan.", "TXT", 0, ['"lab"']),
    ]
    members, version = catalog.members("cat.lan", rrsets)
    assert version == "2" and members == [
        {"zone": "member1.lan.", "label": label, "group": "lab", "coo": None}
    ]
    assert catalog.is_catalog(['"2"']) and not catalog.is_catalog(['"x"']) and not catalog.is_catalog(None)
    add = catalog.member_changes("cat.lan", ChangeOp.ADD, "member2.lan", rrsets)
    assert [c.target for c in add] == [f"cat.lan./{catalog.member_label('member2.lan')}.zones.cat.lan./PTR"]
    with pytest.raises(ValueError, match="already a member"):
        catalog.member_changes("cat.lan", ChangeOp.ADD, "member1.lan", rrsets)
    delete = catalog.member_changes("cat.lan", ChangeOp.DELETE, "member1.lan", rrsets)
    assert [c.op for c in delete] == [ChangeOp.DELETE, ChangeOp.DELETE] and "group." in delete[1].target


def test_consumed_catalogs_in_options_and_views(tmp_path: Path):
    conf = tmp_path / "named.conf"
    conf.write_text(
        'options { catalog-zones { zone "cat.lan" default-primaries port 5300 { 192.0.2.1 key k; }'
        ' in-memory no; }; };\nview "inside" { catalog-zones { zone "c2.lan" zone-directory "c2"; }; };\n'
    )
    found = catalog.consumed_catalogs(ConfigFiles.load(conf))
    assert [(c.view, c.zone) for c in found] == [("_default", "cat.lan."), ("inside", "c2.lan.")]
    assert found[0].default_primaries == ["192.0.2.1 key k"] and found[0].options == {"in-memory": "no"}
    assert found[1].options == {"zone-directory": "c2"}


def test_dnssec_status_policy_and_ds():
    status = dnssec.enrich_status(parse_dnssec_status(STATUS))
    key = status["keys"][0]
    assert key["tag"] == 51011 and key["role"] == "CSK" and key["state"] == "rumoured"
    assert (
        key["published"] == "2026-10-24T18:32:10+00:00"
        and key["next_rollover"] == "2026-11-23T18:32:10+00:00"
    )
    ds = dnssec.ds_records("example.lan.", [DNSKEY, DNSKEY.replace("257", "256", 1)])
    assert len(ds) == 1
    tag, text = next(iter(ds.items()))
    assert text.startswith(f"{tag} 13 2 ")
    key["tag"] = tag
    assert dnssec.ds_guidance(status, ds) == [
        {"key_id": tag, "action": "publish", "ds": text, "checkds": "published"}
    ]
    text = dnssec.render_policy(
        "fast", [{"name": "keys", "value": "{ csk lifetime unlimited algorithm ecdsap256sha256; }"}]
    )
    assert text.startswith('dnssec-policy "fast" {') and "keys {" in text
    for name, statements in (("default", []), ("bad name!", []), ("x", [{"name": "nope", "value": "1"}])):
        with pytest.raises(dnssec.PolicyError):
            dnssec.render_policy(name, statements)
    # A value may not close the block or carry a second statement into policies.conf.
    for value in (
        '1d; }; options { recursion yes; }; dnssec-policy "z" { max-zone-ttl 1d',
        "1d; signatures-validity 5d",
        "1d; }",
        "{ 1d",
    ):
        with pytest.raises(dnssec.PolicyError):
            dnssec.render_policy("x", [{"name": "max-zone-ttl", "value": value}])


def test_added_zones_from_showzone_and_stats(tmp_path: Path):
    zone = addzone.zone_from_showzone(
        'zone "added.lan" { type primary; file "added.lan.db"; allow-update { key "ddi-admin"; }; };\n',
        "_default",
        "/var/cache/bind/_default.nzd",
    )
    assert zone.source is ZoneSource.ADDZONE and zone.dynamic and zone.config_path.endswith(".nzd")
    stats = {
        "views": {
            "_default": {"zones": [{"name": "a.lan", "class": "IN", "type": "primary"}]},
            "_bind": {"zones": [{"name": "version.bind", "class": "CH"}]},
        }
    }
    assert addzone.loaded_zones(stats) == [("_default", "a.lan.", "primary")]
    (tmp_path / "inside.nzf").write_text(
        'zone "n.lan" { type secondary; primaries { 192.0.2.1; }; file "n.db"; };\n'
    )
    found = addzone.nzf_zones(tmp_path, ["inside"])
    assert [(z.view, z.name, z.kind) for z in found] == [("inside", "n.lan.", ZoneKind.SECONDARY)]
    block = addzone.config_block(zone, 'zone "added.lan" {\n\ttype primary;\n};\n')
    assert block == "{\n\ttype primary;\n};"
    assert addzone.where(Zone(name="x.lan.", kind=ZoneKind.PRIMARY, view="inside")) == '"x.lan" IN inside'


def test_view_targets():
    rc = rr.RRsetChange(
        ChangeOp.ADD, "pc.split.lan.", "A", None, RRset("pc.split.lan.", "A", 60, ["192.0.2.3"])
    )
    change = rr.to_change("split.lan", rc, "inside")
    assert change.target == "inside/split.lan./pc.split.lan./A"
    assert rr.target_view(change.target) == "inside" and rr.target_zone(change.target) == "split.lan."
    assert rr.parse_target(change.target, "split.lan") == ("pc.split.lan.", "A")
    assert rr.target_view("split.lan./pc.split.lan./A") is None
    assert rr.preconditions([rc], "n1", "inside")[0].subject == "inside/pc.split.lan./A"


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    inc = tmp_path / "pelagos"
    inc.mkdir()
    conf = tmp_path / "named.conf"
    conf.write_text(f'options {{ directory "{tmp_path}"; }};\ninclude "{inc}/pelagos.conf";\n')
    (inc / "pelagos.conf").write_text(f'# pelagos:managed v1\ninclude "{inc}/zones.conf";\n')
    (inc / "zones.conf").write_text("# pelagos:managed v1\n")
    return conf, inc


def test_zone_plan_renders_a_secondary_on_peers(tmp_path: Path):
    conf, inc = _tree(tmp_path)
    after = {
        "kind": "primary",
        "ns": ["ns1.example.lan."],
        "secondary": {"origin": "n1", "primaries": ["192.0.2.1 key ddi-read"]},
    }
    change = Change(ChangeOp.ADD, "_default/new.lan", after=after)
    here = ConfigPlanner(conf, inc, "n1")
    here.zone_change(change)
    texts = here.finish().texts
    assert "type primary;" in texts[inc / "zones.conf"] and here.result.zone_files
    normalized = here.result.changes[0]
    assert normalized.after["secondary"]["origin"] == "n1"
    peer = ConfigPlanner(conf, inc, "n2")
    peer.zone_change(normalized)
    text = peer.finish().texts[inc / "zones.conf"]
    assert "type secondary;" in text and "192.0.2.1 key ddi-read;" in text and not peer.result.zone_files


def test_policy_plan_adds_policies_conf_to_pelagos_conf(tmp_path: Path):
    conf, inc = _tree(tmp_path)
    planner = ConfigPlanner(conf, inc, "n1")
    statements = [{"name": "keys", "value": "{ csk lifetime unlimited algorithm ecdsap256sha256; }"}]
    planner.apply_change(Change(ChangeOp.ADD, "dnssec-policy/fast", after={"statements": statements}))
    result = planner.finish()
    assert not result.errors, result.errors
    assert f'include "{inc}/policies.conf";' in result.texts[inc / "pelagos.conf"]
    assert 'dnssec-policy "fast"' in result.texts[inc / "policies.conf"]
    again = ConfigPlanner(conf, inc, "n1")
    again.apply_change(Change(ChangeOp.ADD, "dnssec-policy/default", after={"statements": statements}))
    assert again.finish().errors
