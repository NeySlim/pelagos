# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path

import pytest

from pelagos.core.keadoc import KeaDocument, KeaEditError, patch_text

pytestmark = pytest.mark.unit

CONF = """// Kea DHCPv4 server, lab
{
  "Dhcp4": {
    # interfaces
    "interfaces-config": { "interfaces": [ "eth0" ] },
    "valid-lifetime": 4000, // seconds
    /* the subnets */
    "subnet4": [
      {
        "id": 1,
        "subnet": "192.0.2.0/24",
        "pools": [ { "pool": "192.0.2.10 - 192.0.2.20" } ],
      },
      {
        "id": 2,
        "subnet": "198.51.100.0/24"
      }
    ],
    "option-data": []
  }
}
"""


def doc(text=CONF):
    return KeaDocument.from_text(text, "/etc/kea/kea-dhcp4.conf")


def edited(new, text=CONF):
    return patch_text(text, new, "/etc/kea/kea-dhcp4.conf")


def test_parse_reads_comments_and_trailing_commas():
    d = doc()
    body = d.value["Dhcp4"]
    assert body["valid-lifetime"] == 4000
    assert body["subnet4"][0]["pools"][0]["pool"] == "192.0.2.10 - 192.0.2.20"
    assert not d.has_includes


def test_no_change_keeps_text():
    d = doc()
    assert d.patch(copy.deepcopy(d.value)) == {}


def test_scalar_change_keeps_everything_else():
    new = copy.deepcopy(doc().value)
    new["Dhcp4"]["valid-lifetime"] = 7200
    out = edited(new)
    assert out == CONF.replace('"valid-lifetime": 4000,', '"valid-lifetime": 7200,')


def test_add_key_appends_with_file_indentation():
    new = copy.deepcopy(doc().value)
    new["Dhcp4"]["renew-timer"] = 900
    out = edited(new)
    assert '    "option-data": [],\n    "renew-timer": 900\n  }' in out
    assert "# interfaces" in out and "/* the subnets */" in out
    assert json.loads(json.dumps(KeaDocument.from_text(out).value)) == new


def test_remove_key_and_last_key():
    new = copy.deepcopy(doc().value)
    del new["Dhcp4"]["valid-lifetime"]
    out = edited(new)
    assert "valid-lifetime" not in out
    # The comment on the removed line goes with it; the others stay.
    assert "// seconds" not in out and "/* the subnets */" in out
    new2 = copy.deepcopy(doc().value)
    del new2["Dhcp4"]["option-data"]
    out2 = edited(new2)
    assert '"subnet4": [' in out2 and "option-data" not in out2
    assert KeaDocument.from_text(out2).value == new2


def test_list_items_follow_identity():
    d = doc()
    new = copy.deepcopy(d.value)
    new["Dhcp4"]["subnet4"].insert(1, {"id": 3, "subnet": "203.0.113.0/24"})
    new["Dhcp4"]["subnet4"][2]["subnet"] = "198.51.100.0/25"
    out = edited(new)
    assert KeaDocument.from_text(out).value == new
    assert '"pools": [ { "pool": "192.0.2.10 - 192.0.2.20" } ],' in out


def test_remove_list_items():
    new = copy.deepcopy(doc().value)
    new["Dhcp4"]["subnet4"] = new["Dhcp4"]["subnet4"][:1]
    out = edited(new)
    assert KeaDocument.from_text(out).value == new
    assert "198.51.100.0" not in out
    new["Dhcp4"]["subnet4"] = []
    out = edited(new)
    assert KeaDocument.from_text(out).value == new


def test_add_to_empty_and_inline_containers():
    new = copy.deepcopy(doc().value)
    new["Dhcp4"]["option-data"] = [{"name": "domain-name-servers", "data": "192.0.2.1"}]
    new["Dhcp4"]["interfaces-config"]["interfaces"].append("eth1")
    out = edited(new)
    assert '"interfaces": [ "eth0", "eth1" ]' in out
    assert KeaDocument.from_text(out).value == new


def test_replace_type_change():
    new = copy.deepcopy(doc().value)
    new["Dhcp4"]["valid-lifetime"] = {"x": 1}
    assert KeaDocument.from_text(edited(new)).value == new


def test_comment_after_last_member_stays_on_its_line():
    text = '{\n  "Dhcp4": {\n    "a": 1 // one\n  }\n}\n'
    out = patch_text(text, {"Dhcp4": {"a": 1, "b": 2}})
    assert out == '{\n  "Dhcp4": {\n    "a": 1, // one\n    "b": 2\n  }\n}\n'


def test_last_member_swapped_for_a_new_one():
    text = '{\n  "k": {\n    "name": "a",\n    "algorithm": "HMAC-MD5",\n    "secret": "x"\n  }\n}\n'
    new = {"k": {"name": "b", "algorithm": "HMAC-SHA256", "secret-file": "/x"}}
    out = patch_text(text, new)
    assert (
        out
        == '{\n  "k": {\n    "name": "b",\n    "algorithm": "HMAC-SHA256",\n    "secret-file": "/x"\n  }\n}\n'
    )


def test_parse_errors():
    with pytest.raises(KeaEditError):
        KeaDocument.from_text('{ "a": }')
    with pytest.raises(KeaEditError):
        KeaDocument.from_text('{ "a": 1 } x')
    with pytest.raises(KeaEditError):
        KeaDocument.from_text('{ "a": 1 /* open')


def write(path: Path, text: str) -> Path:
    path.write_text(text)
    return path


def test_includes_are_read_and_edits_land_in_the_defining_file(tmp_path):
    subnets = write(
        tmp_path / "subnets.json",
        '// shared subnets\n{ "id": 1, "subnet": "192.0.2.0/24" },\n'
        '{ "id": 2, "subnet": "198.51.100.0/24" }\n',
    )
    main = write(
        tmp_path / "kea-dhcp4.conf",
        '{\n  "Dhcp4": {\n    // main\n    "subnet4": [\n      <?include "'
        + str(subnets)
        + '"?>\n    ],\n    "valid-lifetime": 4000\n  }\n}\n',
    )
    d = KeaDocument(main)
    assert d.has_includes
    assert [s["id"] for s in d.value["Dhcp4"]["subnet4"]] == [1, 2]
    assert d.defining_file(["Dhcp4", "subnet4", 1]) == subnets
    new = copy.deepcopy(d.value)
    new["Dhcp4"]["subnet4"][1]["subnet"] = "198.51.100.0/25"
    new["Dhcp4"]["valid-lifetime"] = 3600
    changed = d.patch(new)
    assert set(changed) == {subnets, main}
    assert "<?include" in changed[main] and '"valid-lifetime": 3600' in changed[main]
    assert "// shared subnets" in changed[subnets] and "198.51.100.0/25" in changed[subnets]
    # A new item goes after the last one, in the included file.
    new2 = copy.deepcopy(d.value)
    new2["Dhcp4"]["subnet4"].append({"id": 3, "subnet": "203.0.113.0/24"})
    changed2 = d.patch(new2)
    assert set(changed2) == {subnets}
    for path, text in changed2.items():
        path.write_text(text)
    assert KeaDocument(main).value == new2


def test_relative_include_resolves_against_cwd_then_folder(tmp_path):
    write(tmp_path / "part.json", '"valid-lifetime": 10,')
    main = write(tmp_path / "main.conf", '{ "Dhcp4": { <?include "part.json"?> "renew-timer": 5 } }')
    d = KeaDocument(main, cwd=tmp_path / "nowhere")
    assert d.value == {"Dhcp4": {"valid-lifetime": 10, "renew-timer": 5}}


def test_edit_across_files_is_refused(tmp_path):
    part = write(tmp_path / "part.json", '{ "id": 1, "subnet": "192.0.2.0/24" }')
    main = write(tmp_path / "main.conf", '{ "Dhcp4": { "subnet4": [ <?include "' + str(part) + '"?> ] } }')
    d = KeaDocument(main)
    new = {"Dhcp4": {"subnet4": "none"}}
    with pytest.raises(KeaEditError, match="several files"):
        d.patch(new)


def test_include_loop_is_refused(tmp_path):
    a = tmp_path / "a.json"
    a.write_text('{ "x": [ <?include "' + str(a) + '"?> ] }')
    with pytest.raises(KeaEditError, match="loop"):
        KeaDocument(a)


def test_missing_include_is_reported(tmp_path):
    main = write(tmp_path / "main.conf", '{ "Dhcp4": { <?include "/nonexistent/x.json"?> } }')
    with pytest.raises(KeaEditError, match="cannot read"):
        KeaDocument(main)


def test_syntax_warnings_name_each_extra_comma_with_line_and_column(tmp_path):
    text = (
        "{\n"
        '  "Dhcp4": {\n'
        '    "interfaces-config": { "interfaces": [ "*" ], }, // trailing\n'
        '    "subnet4": [ { "id": 1, "subnet": "192.0.2.0/24", }, ],\n'
        '    "note": "a, }",\n'
        "  }\n"
        "}\n"
    )
    found = KeaDocument.from_text(text).syntax_warnings()
    assert [(w["line"], w["column"]) for w in found] == [(3, 49), (4, 53), (4, 56), (5, 19)]
    assert all(w["message"].startswith("Extraneous comma") for w in found)


def test_syntax_warnings_follow_includes_and_stay_empty_on_clean_files(tmp_path):
    (tmp_path / "sub.json").write_text('{ "id": 1, "subnet": "192.0.2.0/24",\n}')
    main = tmp_path / "kea.conf"
    main.write_text('{ "Dhcp4": { "subnet4": [ <?include "sub.json"?> ] } }')
    found = KeaDocument(main, cwd=tmp_path).syntax_warnings()
    assert [(Path(w["path"]).name, w["line"], w["column"]) for w in found] == [("sub.json", 1, 36)]
    assert KeaDocument.from_text('{ "a": [1, 2], "b": {} }').syntax_warnings() == []
