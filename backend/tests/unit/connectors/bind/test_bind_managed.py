# SPDX-License-Identifier: Apache-2.0
"""Managed include files: rendering, in-place upsert and removal with notes, include line planning."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.connectors.bind.managed import AclSpec, KeySpec, ManagedFiles, note_comment, plan_include_lines
from pelagos.connectors.bind.namedconf import ConfigFiles, load_tree, serialize
from pelagos.domain.dns import Zone, ZoneKind

from .conftest import DATA

pytestmark = pytest.mark.unit


def test_render_statements() -> None:
    assert ManagedFiles.key_statement(KeySpec("ddi-admin", "hmac-sha256", "c2VjcmV0")) == (
        'key "ddi-admin" {\n\talgorithm hmac-sha256;\n\tsecret "c2VjcmV0";\n};'
    )
    assert ManagedFiles.acl_statement(AclSpec("lan", ["192.0.2.0/24", "!192.0.2.1"])) == (
        'acl "lan" {\n\t192.0.2.0/24;\n\t!192.0.2.1;\n};'
    )
    assert (
        ManagedFiles.option_statement("forwarders", "{ 192.0.2.53; };") == "forwarders {\n\t192.0.2.53;\n};"
    )
    zone = Zone(
        name="lab.example.lan",
        kind=ZoneKind.PRIMARY,
        file="/var/cache/bind/pelagos/lab.example.lan.db",
        update_policy=["grant ddi-admin zonesub A AAAA"],
        allow_transfer=["key ddi-read"],
        extra={"notify": "explicit"},
    )
    assert ManagedFiles.zone_statement(zone) == (
        'zone "lab.example.lan" {\n\ttype primary;\n\tfile "/var/cache/bind/pelagos/lab.example.lan.db";\n'
        "\tallow-transfer {\n\t\tkey ddi-read;\n\t};\n"
        "\tupdate-policy {\n\t\tgrant ddi-admin zonesub A AAAA;\n\t};\n"
        "\tnotify explicit;\n};"
    )


def test_upsert_and_remove_keep_hand_edits(tmp_root: Path) -> None:
    managed = ManagedFiles(tmp_root)
    doc = managed.document(managed.zones_conf)
    assert serialize(doc) == "# pelagos:managed v1\n"
    a = Zone(name="a.example.lan", kind=ZoneKind.PRIMARY, file="a.db")
    b = Zone(name="b.example.lan", kind=ZoneKind.PRIMARY, file="b.db")
    managed.upsert(doc, managed.zone_statement(a), "zone", "a.example.lan", note_comment("first"))
    managed.upsert(doc, managed.zone_statement(b), "zone", "b.example.lan", None)
    text = serialize(doc)
    assert text == (
        "# pelagos:managed v1\n"
        '# pelagos:note {"notes": "first"}\n'
        'zone "a.example.lan" {\n\ttype primary;\n\tfile "a.db";\n};\n'
        'zone "b.example.lan" {\n\ttype primary;\n\tfile "b.db";\n};\n'
    )
    # A hand edit (comment) survives a replace of the other statement.
    doc = managed.document(managed.zones_conf, text.replace('zone "b', '// hand comment\nzone "b'))
    a.file = "a2.db"
    managed.upsert(doc, managed.zone_statement(a), "zone", "a.example.lan.", note_comment("second"))
    text = serialize(doc)
    assert '# pelagos:note {"notes": "second"}\nzone "a.example.lan" {\n\ttype primary;\n' in text
    assert '\tfile "a2.db";' in text
    assert "first" not in text and '// hand comment\nzone "b' in text
    zones = managed.zones(doc=doc)
    assert [(z.name, z.notes) for z in zones] == [("a.example.lan.", "second"), ("b.example.lan.", None)]
    managed.remove(doc, "zone", "a.example.lan")
    expected = (
        '# pelagos:managed v1\n// hand comment\nzone "b.example.lan" {\n\ttype primary;\n\tfile "b.db";\n};\n'
    )
    assert serialize(doc) == expected


def test_keys_and_acls_read_back(tmp_root: Path) -> None:
    managed = ManagedFiles(tmp_root)
    doc = managed.document(managed.keys_conf)
    managed.upsert(
        doc, managed.key_statement(KeySpec("k1", secret="c2VjcmV0")), "key", "k1", note_comment("x")
    )
    (keys,) = managed.keys(doc)
    assert (keys.name, keys.algorithm, keys.secret, keys.notes) == ("k1", "hmac-sha256", "c2VjcmV0", "x")
    assert keys.masked()["secret"] == "****"
    doc = managed.document(managed.acls_conf)
    managed.upsert(doc, managed.acl_statement(AclSpec("lan", ["192.0.2.0/24"])), "acl", "lan", None)
    assert [a.to_dict() for a in managed.acls(doc)] == [
        {"name": "lan", "elements": ["192.0.2.0/24"], "notes": None}
    ]


def test_resolve_refuses_paths_outside_the_include_dir(tmp_root: Path) -> None:
    managed = ManagedFiles(tmp_root)
    assert managed.resolve("zones.conf") == (tmp_root / "zones.conf").resolve()
    assert managed.resolve("views/internal.conf") == (tmp_root / "views" / "internal.conf").resolve()
    for bad in ("../named.conf", "/etc/passwd", "zones.db", "views/../../x.conf"):
        with pytest.raises(ValueError):
            managed.resolve(bad)


def test_include_lines_debian_layout(tmp_root: Path) -> None:
    etc = tmp_root / "etc"
    etc.mkdir()
    for p in (DATA / "debian").iterdir():
        (etc / p.name).write_text(p.read_text().replace("/etc/bind/", f"{etc}/"))
    managed = ManagedFiles(etc / "pelagos")
    files = ConfigFiles.load(etc / "named.conf")
    edits = plan_include_lines(files, managed)
    assert set(edits) == {etc / "named.conf", etc / "named.conf.options"}
    assert edits[etc / "named.conf"].endswith(f'include "{etc}/pelagos/pelagos.conf";\n')
    assert edits[etc / "named.conf.options"] == (
        f'options {{\n\tdirectory "/var/cache/bind";\n\tinclude "{etc}/pelagos/options.conf";\n}};\n'
    )
    for path, text in edits.items():
        path.write_text(text)
    for path, text in managed.bootstrap_texts().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    tree = load_tree(etc / "named.conf", "n1", checkconf=None, include_dir=etc / "pelagos")
    assert tree.pelagos["include_line_present"] and tree.pelagos["options_include_present"]
    assert all(tree.pelagos["managed_files"].values())
    # Idempotent: nothing more to add.
    assert plan_include_lines(ConfigFiles.load(etc / "named.conf"), managed) == {}


def test_include_lines_views(tmp_root: Path) -> None:
    conf = tmp_root / "named.conf"
    conf.write_text((DATA / "views.conf").read_text().replace("/etc/bind/pelagos", str(tmp_root / "pelagos")))
    managed = ManagedFiles(tmp_root / "pelagos")
    edits = plan_include_lines(ConfigFiles.load(conf), managed)
    text = edits[conf]
    # internal already includes its file; external gets one, the options block and the top level too.
    assert text.count(f'include "{tmp_root}/pelagos/views/internal.conf";') == 1
    assert f'\tinclude "{tmp_root}/pelagos/views/external.conf";\n}};' in text
    assert f'\tinclude "{tmp_root}/pelagos/options.conf";\n}};' in text
    assert text.endswith(f'include "{tmp_root}/pelagos/pelagos.conf";\n')
