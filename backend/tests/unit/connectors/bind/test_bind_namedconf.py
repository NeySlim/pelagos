# SPDX-License-Identifier: Apache-2.0
"""named.conf parser and serializer: byte-exact round trip, structure, edits, includes, load_tree."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.connectors.bind.namedconf import (
    ConfigFiles,
    ParseError,
    canonical,
    files_tree,
    format_statement,
    load_tree,
    parse,
    parse_statements,
    serialize,
    tokenize,
)
from pelagos.domain.dns import ZoneKind, ZoneSource

from .conftest import DATA, mapped_reader

pytestmark = pytest.mark.unit

DATA_FILES = sorted(p for p in DATA.rglob("*") if p.is_file())


@pytest.mark.parametrize("path", DATA_FILES, ids=lambda p: str(p.relative_to(DATA)))
def test_round_trip_data_files(path: Path) -> None:
    text = path.read_text()
    assert serialize(parse(text, str(path))) == text


EDGE_CASES = {
    "crlf": 'options {\r\n\tdirectory "/var/cache/bind";\r\n};\r\n',
    "no_trailing_newline": "options { recursion no; };",
    "escaped_quote": 'options { version "a \\" b"; };\n',
    "comment_glued": 'options{recursion no;//c\n};#h\n/*x*/zone "a"{type hint;file "f";};',
    "empty_statements": "options { ; recursion no;; };;\n",
    "nested": 'logging { channel c { file "f" versions 3; print-time yes; };\n category default { c; }; };\n',
    "unicode": '// café été\noptions { directory "/var/cache/bind"; };\n',
    "only_comments": "# a\n// b\n/* c */\n",
    "empty": "",
    "dyndb_opaque": 'dyndb "sample" "lib.so" { 192.0.2.1 example.lan; };\n',
    "tabs_and_spaces": 'zone   "example.lan"\tIN {\n  type\tprimary ;\n  file "x" ;\n} ;\n',
}


@pytest.mark.parametrize("name", sorted(EDGE_CASES))
def test_round_trip_edge_cases(name: str) -> None:
    text = EDGE_CASES[name]
    assert serialize(parse(text)) == text


def test_every_byte_lands_in_one_token() -> None:
    text = (DATA / "comments.conf").read_text()
    assert "".join(t.text for t in tokenize(text)) == text
    kinds = {t.kind for t in tokenize(text)}
    assert {"comment", "string", "word", "lbrace", "rbrace", "semi", "space"} <= kinds


@pytest.mark.parametrize(
    "text, message",
    [
        ('options { version "x; };', "unterminated quoted string"),
        ("options { recursion no;", "missing '}'"),
        ("recursion no; };", "unexpected '}'"),
        ("/* never closed", "unterminated block comment"),
        ("options { recursion no; }", "terminating ';'"),
    ],
)
def test_parse_errors(text: str, message: str) -> None:
    with pytest.raises(ParseError, match=message):
        parse(text, "named.conf")


def test_structure_of_comments_file() -> None:
    doc = parse((DATA / "comments.conf").read_text())
    names = [n.name for n in doc.statements()]
    assert names == ["options", "zone", "zone"]
    options = doc.find("options")[0]
    assert [s.name for s in options.statements()] == [
        "directory",
        "recursion",
        "allow-query",
        "listen-on",
        "version",
    ]
    recursion = options.first("recursion")
    assert recursion is not None and recursion.args == ["no"]
    assert options.first("listen-on").value_text() == "port 53 { 127.0.0.1; 192.0.2.1; }"
    assert options.first("allow-query").elements() == ["any"]
    assert options.first("version").args == ['not "telling" # not a comment // nor this']
    zones = doc.find("zone")
    assert [z.args[0] for z in zones] == ["example.lan", "2.0.192.in-addr.arpa"]
    assert zones[1].first("file").args == ["2.0.192.in-addr.arpa.db"]


def test_find_by_context() -> None:
    doc = parse((DATA / "views.conf").read_text())
    internal = doc.find("zone", 'view "internal"')
    assert [z.args[0] for z in internal] == ["example.lan", "2.0.192.in-addr.arpa"]
    assert doc.find("type", ('view "external"', 'zone "example.lan"'))[0].args == ["secondary"]
    with pytest.raises(KeyError):
        doc.find("zone", 'view "nope"')


def test_canonical_matches_named_checkconf_style() -> None:
    stmt = parse_statements('zone "x" { type primary; allow-transfer { key "k"; 192.0.2.0/24; }; };')[0]
    assert canonical(stmt) == (
        'zone "x" {\n\ttype primary;\n\tallow-transfer {\n\t\tkey "k";\n\t\t192.0.2.0/24;\n\t};\n};'
    )
    assert format_statement("recursion   no ;", depth=1) == "\trecursion no;"


def test_add_statement_keeps_formatting() -> None:
    text = (DATA / "debian12" / "named.conf.options").read_text()
    doc = parse(text)
    doc.add_statement('include "/etc/bind/pelagos/options.conf";', context="options")
    out = serialize(doc)
    assert out == text.replace(
        "\tlisten-on-v6 { any; };\n};",
        '\tlisten-on-v6 { any; };\n\tinclude "/etc/bind/pelagos/options.conf";\n};',
    )
    top = parse("// top\noptions { recursion no; };\n")
    top.add_statement('include "/etc/bind/pelagos/pelagos.conf";')
    assert serialize(top) == '// top\noptions { recursion no; };\ninclude "/etc/bind/pelagos/pelagos.conf";\n'


def test_add_statement_to_empty_and_unterminated_files() -> None:
    doc = parse("options { };")
    doc.add_statement("recursion no;", context="options")
    assert serialize(doc) == "options {\n\trecursion no;\n};"
    doc = parse("options { recursion no; };")
    doc.add_statement('include "/x.conf";')
    assert serialize(doc) == 'options { recursion no; };\ninclude "/x.conf";\n'
    doc = parse("")
    doc.add_statement('acl "a" { 192.0.2.0/24; };')
    assert serialize(doc) == 'acl "a" {\n\t192.0.2.0/24;\n};\n'


def test_replace_and_remove_statement() -> None:
    text = 'zone "a" {\n\ttype primary;\n\tfile "a.db"; // keep me\n\tnotify no;\n};\n'
    doc = parse(text)
    zone = doc.find("zone")[0]
    notify = zone.first("notify")
    doc.replace_statement(notify, "notify   explicit;")
    assert serialize(doc) == text.replace("notify no;", "notify explicit;")
    doc.remove_statement(zone.first("notify"))
    assert serialize(doc) == 'zone "a" {\n\ttype primary;\n\tfile "a.db"; // keep me\n};\n'
    doc.remove_statement(zone.first("file"))
    assert serialize(doc) == 'zone "a" {\n\ttype primary;\n};\n'
    doc.remove_statement(doc.find("zone")[0])
    assert serialize(doc) == ""


def debian_reader(base: Path) -> tuple[Path, dict[str, Path]]:
    mapping = {f"/etc/bind/{p.name}": p for p in base.iterdir()}
    return Path("/etc/bind/named.conf"), mapping


def test_load_tree_debian_defaults() -> None:
    user_conf, mapping = debian_reader(DATA / "debian")
    tree = load_tree(
        user_conf, "n1", checkconf=None, include_dir=Path("/etc/bind/pelagos"), reader=mapped_reader(mapping)
    )
    assert tree.includes == [
        "/etc/bind/named.conf",
        "/etc/bind/named.conf.options",
        "/etc/bind/named.conf.local",
        "/etc/bind/named.conf.root-hints",
    ]
    directory = next(e for e in tree.options if e.name == "directory")
    assert directory.value == '"/var/cache/bind"'
    assert directory.path == "/etc/bind/named.conf.options" and directory.line == 2
    assert [(z.name, z.kind) for z in tree.zones] == [(".", ZoneKind.HINT)]
    assert tree.zones[0].config_path == "/etc/bind/named.conf.root-hints"
    assert tree.pelagos["include_line_present"] is False
    assert tree.pelagos["options_include_present"] is False


def test_load_tree_debian12_zones_and_master_alias() -> None:
    user_conf, mapping = debian_reader(DATA / "debian12")
    tree = load_tree(user_conf, "n1", checkconf=None, reader=mapped_reader(mapping))
    kinds = {z.name: z.kind for z in tree.zones}
    assert kinds["localhost."] is ZoneKind.PRIMARY and kinds["."] is ZoneKind.HINT
    assert len(tree.zones) == 5
    assert {e.name for e in tree.options} == {"directory", "dnssec-validation", "listen-on-v6"}


def test_load_tree_rhel_include_inside_options() -> None:
    mapping = {
        "/etc/named.conf": DATA / "rhel" / "named.conf",
        "/etc/named.rfc1912.zones": DATA / "rhel" / "named.rfc1912.zones",
        "/etc/named.root.key": DATA / "rhel" / "named.root.key",
        "/etc/crypto-policies/back-ends/bind.config": DATA / "rhel" / "bind.config",
    }
    tree = load_tree(Path("/etc/named.conf"), "n1", checkconf=None, reader=mapped_reader(mapping))
    names = [e.name for e in tree.options]
    assert "disable-algorithms" in names and "disable-ds-digests" in names
    alg = next(e for e in tree.options if e.name == "disable-algorithms")
    assert alg.path == "/etc/crypto-policies/back-ends/bind.config"
    assert len(tree.zones) == 6
    assert all(z.allow_update == ["none"] for z in tree.zones if z.kind is ZoneKind.PRIMARY)
    assert tree.logging and "default_debug" in tree.logging
    other = {o["name"] for o in tree.pelagos["other_statements"]}
    assert "trust-anchors" in other


def test_load_tree_views_and_masked_keys(tmp_root: Path) -> None:
    include_dir = tmp_root / "pelagos"
    (include_dir / "views").mkdir(parents=True)
    (include_dir / "views" / "internal.conf").write_text(
        '# pelagos:managed v1\n# pelagos:note {"notes": "lab zone"}\nzone "lab.example.lan" {\n'
        '\ttype primary;\n\tfile "/var/cache/bind/pelagos/lab.example.lan.db";\n};\n'
    )
    conf = tmp_root / "named.conf"
    conf.write_text((DATA / "views.conf").read_text().replace("/etc/bind/pelagos", str(include_dir)))
    tree = load_tree(conf, "n1", checkconf=None, include_dir=include_dir)
    assert list(tree.views) == ["internal", "external"]
    internal = {z.name: z for z in tree.views["internal"]}
    assert set(internal) == {"example.lan.", "2.0.192.in-addr.arpa.", "lab.example.lan."}
    lab = internal["lab.example.lan."]
    assert lab.source is ZoneSource.PELAGOS and lab.notes == "lab zone"
    assert lab.config_path == str(include_dir / "views" / "internal.conf")
    assert internal["example.lan."].dynamic and internal["example.lan."].update_policy == [
        "grant ddi-admin zonesub A AAAA PTR"
    ]
    external = tree.views["external"][0]
    assert external.kind is ZoneKind.SECONDARY
    assert external.primaries == ["192.0.2.1 key external-xfr"]
    assert external.extra["primaries-options"] == "port 5300"
    assert {k.name for k in tree.keys} == {"internal-xfr", "external-xfr"}
    assert all("****" in k.value and "c2Vj" not in k.value for k in tree.keys)
    assert tree.acls[0].name == "lan" and "192.0.2.0/24" in tree.acls[0].value
    assert tree.pelagos["view_includes_present"] == {"internal": True, "external": False}
    assert tree.pelagos["has_views"] is True


def test_load_tree_catalog_rpz_dnssec() -> None:
    mapping = {"/etc/bind/named.conf": DATA / "catalog-rpz.conf"}
    tree = load_tree(Path("/etc/bind/named.conf"), "n1", checkconf=None, reader=mapped_reader(mapping))
    names = {e.name for e in tree.options}
    assert {"catalog-zones", "response-policy"} <= names
    rpz = next(e for e in tree.options if e.name == "response-policy")
    assert rpz.value.startswith('{ zone "rpz.example.lan" policy given;')
    producer = next(z for z in tree.zones if z.name == "producer.example.lan.")
    assert producer.also_notify == ["192.0.2.2"] and producer.extra["notify"] == "explicit"
    mapping = {"/etc/bind/named.conf": DATA / "dnssec-logging.conf"}
    tree = load_tree(Path("/etc/bind/named.conf"), "n1", checkconf=None, reader=mapped_reader(mapping))
    signed = next(z for z in tree.zones if z.name == "example.lan.")
    assert signed.dnssec_policy == "standard" and signed.inline_signing is True
    assert tree.logging and "queries_log" in tree.logging
    other = {o["name"] for o in tree.pelagos["other_statements"]}
    assert {"key-store", "dnssec-policy"} <= other


def test_relative_includes_follow_directory(tmp_root: Path) -> None:
    (tmp_root / "zones").mkdir()
    (tmp_root / "zones" / "local.conf").write_text('zone "a.example.lan" { type primary; file "a.db"; };\n')
    (tmp_root / "early.conf").write_text("acl x { none; };\n")
    conf = tmp_root / "named.conf"
    conf.write_text(
        f'include "early.conf";\noptions {{ directory "{tmp_root}/zones"; }};\ninclude "local.conf";\n'
    )
    files = ConfigFiles.load(conf)
    assert files.order == [str(conf), str(tmp_root / "early.conf"), str(tmp_root / "zones" / "local.conf")]
    assert files.missing == []


def test_glob_include_and_missing_files(tmp_root: Path) -> None:
    for name in ("b.conf", "a.conf"):
        (tmp_root / name).write_text(f'acl "{name[0]}" {{ none; }};\n')
    conf = tmp_root / "named.conf"
    conf.write_text(
        f'include "{tmp_root}/*.conf.d";\ninclude "{tmp_root}/[ab].conf";\ninclude "/nonexistent/x.conf";\n'
    )
    files = ConfigFiles.load(conf)
    assert files.order[1:] == [str(tmp_root / "a.conf"), str(tmp_root / "b.conf")]
    assert files.missing == ["/nonexistent/x.conf"]


def test_files_tree_masks_secrets(tmp_root: Path) -> None:
    conf = tmp_root / "named.conf"
    conf.write_text('key "k" { algorithm hmac-sha256; secret "c2VjcmV0"; };\noptions { recursion no; };\n')
    payload = files_tree(ConfigFiles.load(conf), tmp_root / "pelagos")
    stmts = payload["files"][0]["statements"]
    assert stmts[0]["name"] == "key"
    assert stmts[0]["statements"][1] == {
        "name": "secret",
        "args": ["****"],
        "line": 1,
        "include": False,
        "value": "****",
    }
    assert "c2VjcmV0" not in repr(payload)
    assert payload["files"][0]["managed"] is False


def test_quote_matches_named_lexer() -> None:
    from pelagos.connectors.bind.namedconf.tree import quote, unquote

    # named keeps `\\` as two backslashes and only unescapes `\"`.
    assert unquote('"a\\\\b"') == "a\\\\b"
    assert unquote('"a\\"b"') == 'a"b'
    assert quote("a\\b") == '"a\\b"' and quote('a"b') == '"a\\"b"'
    for value in ("C:\\dir\\x", 'say "hi"', "plain"):
        assert unquote(quote(value)) == value
    for bad in ("ends\\", 'x\\"y'):
        with pytest.raises(ValueError):
            quote(bad)


def test_unreadable_include_is_recorded(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    conf = tmp_path / "named.conf"
    conf.write_text(f'include "{tmp_path}/sub";\noptions {{ recursion no; }};\n')
    files = ConfigFiles.load(conf)
    assert files.unreadable == [str(tmp_path / "sub")]
    assert files.errors and str(tmp_path / "sub") in files.errors[0]
