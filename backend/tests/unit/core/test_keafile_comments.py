# SPDX-License-Identifier: Apache-2.0
"""Comments of a Kea file: the include tree that keeps them in place, and the copy into
user-context.pelagos.comment before a config-write drops them (section 9)."""

import copy
import json
from pathlib import Path

import pytest

from pelagos.core.keadoc import KeaDocument, KeaEditError
from pelagos.core.keafile import copy_comments

pytestmark = pytest.mark.unit

CONF = """// Lab DHCPv4 server
{
  "Dhcp4": { // main body
    // where we listen
    "interfaces-config": { "interfaces": [ "eth0" ] },
    "valid-lifetime": 3600, // one hour
    "subnet4": [
      // office LAN
      {
        "id": 1,
        "subnet": "192.0.2.0/24",
        "pools": [ { "pool": "192.0.2.10 - 192.0.2.20" } ],
        "reservations": [
          { "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "192.0.2.5" } // printer
        ],
        "option-data": [
          # gateway of the office
          { "name": "routers", "data": "192.0.2.1" }
        ]
      }
    ]
    /* ---------- */
  }
}
"""


def write(tmp_path: Path, text: str = CONF) -> Path:
    path = tmp_path / "kea-dhcp4.conf"
    path.write_text(text)
    return path


def materialize(tree: dict[Path, str]) -> None:
    for path, text in tree.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def test_comment_notes_go_to_the_nearest_object():
    notes = KeaDocument.from_text(CONF, "/etc/kea/kea-dhcp4.conf").comment_notes("Dhcp4")
    assert notes == [
        (["Dhcp4"], "Lab DHCPv4 server"),
        (["Dhcp4"], "main body"),
        (["Dhcp4"], "where we listen"),
        (["Dhcp4"], "one hour"),
        (["Dhcp4", "subnet4", 0], "office LAN"),
        (["Dhcp4", "subnet4", 0, "reservations", 0], "printer"),
        (["Dhcp4", "subnet4", 0, "option-data", 0], "gateway of the office"),
    ]


def test_include_tree_splits_sections_and_keeps_every_comment(tmp_path):
    conf = write(tmp_path)
    doc = KeaDocument(conf)
    tree = doc.include_tree("Dhcp4", tmp_path / "kea4.d")
    assert set(tree) == {conf, tmp_path / "kea4.d/interfaces-config.json", tmp_path / "kea4.d/subnet4.json"}
    top = tree[conf]
    assert top.startswith("// Lab DHCPv4 server") and '"valid-lifetime": 3600, // one hour' in top
    assert f'<?include "{tmp_path}/kea4.d/subnet4.json"?>' in top and "/* ---------- */" in top
    assert tree[tmp_path / "kea4.d/interfaces-config.json"].startswith("// where we listen\n")
    sub = tree[tmp_path / "kea4.d/subnet4.json"]
    assert sub.startswith('"subnet4": [\n  // office LAN') and "// printer" in sub
    materialize(tree)
    again = KeaDocument(conf)
    assert again.has_includes and again.value == doc.value
    every = " ".join(c.text for c in again.comments)
    assert all(c.text in every for c in doc.comments)


def test_include_tree_is_refused_on_a_tree(tmp_path):
    conf = write(tmp_path)
    tree = KeaDocument(conf).include_tree("Dhcp4", tmp_path / "kea4.d")
    materialize(tree)
    with pytest.raises(KeaEditError, match="already uses"):
        KeaDocument(conf).include_tree("Dhcp4", tmp_path / "kea4.d")


def test_compact_file_splits_too(tmp_path):
    conf = write(tmp_path, '{"Dhcp4":{"valid-lifetime":10,"subnet4":[{"id":1,"subnet":"192.0.2.0/24"}]}}')
    doc = KeaDocument(conf)
    tree = doc.include_tree("Dhcp4", tmp_path / "d")
    materialize(tree)
    assert KeaDocument(conf).value == doc.value


def test_after_the_split_new_sections_stay_in_the_top_file(tmp_path):
    conf = write(tmp_path)
    materialize(KeaDocument(conf).include_tree("Dhcp4", tmp_path / "kea4.d"))
    doc = KeaDocument(conf)
    new = copy.deepcopy(doc.value)
    new["Dhcp4"]["renew-timer"] = 900
    new["Dhcp4"]["client-classes"] = [{"name": "voip"}]
    new["Dhcp4"]["subnet4"][0]["reservations"].append({"hw-address": "11:22:33:44:55:66"})
    changed = doc.patch(new)
    assert set(changed) == {conf, tmp_path / "kea4.d/subnet4.json"}
    assert '"renew-timer": 900' in changed[conf] and '"client-classes"' in changed[conf]
    assert "11:22:33:44:55:66" in changed[tmp_path / "kea4.d/subnet4.json"]
    assert "// printer" in changed[tmp_path / "kea4.d/subnet4.json"]
    materialize(changed)
    assert KeaDocument(conf).value == new


def test_copy_into_user_context_is_idempotent():
    doc = KeaDocument.from_text(CONF, "/etc/kea/kea-dhcp4.conf")
    running = copy.deepcopy(doc.value["Dhcp4"])
    running["subnet4"][0]["pools"][0]["pool"] = "192.0.2.10-192.0.2.20"  # as config-get spells it
    notes = doc.comment_notes("Dhcp4")
    body, added = copy_comments(doc.value, notes, running, "Dhcp4")
    assert added == 7
    assert body["user-context"]["pelagos"]["comment"].splitlines() == [
        "Lab DHCPv4 server",
        "main body",
        "where we listen",
        "one hour",
    ]
    subnet = body["subnet4"][0]
    assert subnet["user-context"] == {"pelagos": {"comment": "office LAN"}}
    assert subnet["reservations"][0]["user-context"]["pelagos"]["comment"] == "printer"
    assert subnet["option-data"][0]["user-context"]["pelagos"]["comment"] == "gateway of the office"
    assert "user-context" not in running  # the input is not changed
    again, more = copy_comments(doc.value, notes, body, "Dhcp4")
    assert more == 0 and json.dumps(again, sort_keys=True) == json.dumps(body, sort_keys=True)


def test_copy_follows_identity_and_falls_back_to_the_parent():
    doc = KeaDocument.from_text(CONF, "/etc/kea/kea-dhcp4.conf")
    running = copy.deepcopy(doc.value["Dhcp4"])
    # A plan added a subnet before it and removed the printer.
    running["subnet4"].insert(0, {"id": 9, "subnet": "198.51.100.0/24"})
    running["subnet4"][1]["reservations"] = []
    running["subnet4"][1]["user-context"] = {"site": "hq", "pelagos": {"comment": "office LAN"}}
    body, added = copy_comments(doc.value, doc.comment_notes("Dhcp4"), running, "Dhcp4")
    assert "user-context" not in body["subnet4"][0]
    office = body["subnet4"][1]
    assert office["user-context"]["site"] == "hq"
    assert office["user-context"]["pelagos"]["comment"] == "office LAN\nprinter"
    assert added == 6
