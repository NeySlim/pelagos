# SPDX-License-Identifier: Apache-2.0
"""named-checkconf -p as the oracle for the parser, the serializer and the canonical formatter."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from pelagos.connectors.bind.namedconf import canonical, load_tree, parse, serialize
from tests.fixtures.ports import find_binary

pytestmark = pytest.mark.daemon

DATA = Path(__file__).resolve().parents[1] / "unit" / "connectors" / "bind" / "data"
ENTRY_POINTS = [
    "debian/named.conf",
    "debian12/named.conf",
    "rhel/named.conf",
    "views.conf",
    "comments.conf",
    "catalog-rpz.conf",
    "dnssec-logging.conf",
]
_WARNING = re.compile(r"^[^\s{}]+:\d+: ")


def checkconf_print(conf: Path) -> str:
    binary = find_binary("named-checkconf")
    assert binary, "named-checkconf is required"
    proc = subprocess.run([binary, "-p", str(conf)], capture_output=True, text=True, timeout=30, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # Warnings (missing key directories and the like) are printed on stdout before the tree.
    return "".join(line for line in proc.stdout.splitlines(keepends=True) if not _WARNING.match(line))


def relocate(tmp: Path) -> None:
    """Copy the data configurations under tmp with every absolute path pointing inside it."""
    replacements = {
        "/etc/bind/pelagos/": f"{tmp}/pelagos/",
        "/etc/bind/": f"{tmp}/debian12/",
        "/etc/crypto-policies/back-ends/bind.config": f"{tmp}/rhel/bind.config",
        "/etc/named.": f"{tmp}/rhel/named.",
        '"/var/cache/bind"': f'"{tmp}/var"',
        '"/var/named"': f'"{tmp}/var"',
    }
    for src in DATA.rglob("*"):
        if not src.is_file():
            continue
        text = src.read_text()
        for old, new in replacements.items():
            text = text.replace(old, new)
        if src.parent.name == "debian":
            text = text.replace(f"{tmp}/debian12/", f"{tmp}/debian/")
        dest = tmp / src.relative_to(DATA)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
    (tmp / "var" / "keys").mkdir(parents=True)
    (tmp / "pelagos" / "views").mkdir(parents=True)
    (tmp / "pelagos" / "views" / "internal.conf").write_text("# pelagos:managed v1\n")


@pytest.fixture
def relocated(tmp_root: Path) -> Path:
    relocate(tmp_root)
    return tmp_root


@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_reserialized_tree_is_identical_for_named(relocated: Path, entry: str) -> None:
    conf = relocated / entry
    text = conf.read_text()
    copy = conf.with_name("reserialized-" + conf.name)
    copy.write_text(serialize(parse(text, str(conf))))
    assert checkconf_print(conf) == checkconf_print(copy)


@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_canonical_formatter_reproduces_named_checkconf_p(relocated: Path, entry: str) -> None:
    printed = checkconf_print(relocated / entry)
    doc = parse(printed)
    # named's printer leaves stray spaces where optional parts are empty (`listen-on-v6  {`, `null ;`).
    assert "".join(canonical(s) + "\n" for s in doc.statements()) == squeeze(printed)


def squeeze(text: str) -> str:
    return re.sub(r" +", " ", text).replace(" ;", ";")


def test_added_statements_print_as_written(relocated: Path) -> None:
    conf = relocated / "debian12" / "named.conf.options"
    doc = parse(conf.read_text(), str(conf))
    doc.add_statement('allow-transfer { key "ddi-read"; 192.0.2.0/24; };', context="options")
    doc.add_statement('acl "lan" { 192.0.2.0/24; };')
    added = [doc.find("allow-transfer", "options")[0], doc.find("acl")[0]]
    conf.write_text(serialize(doc))
    printed = squeeze(checkconf_print(conf))
    assert canonical(added[0], 1) in printed
    assert canonical(added[1], 0) in printed


def test_fixture_configuration(named_server) -> None:
    conf = named_server.named_conf
    copy = conf.with_name("reserialized.conf")
    copy.write_text(serialize(parse(conf.read_text(), str(conf))))
    assert checkconf_print(conf) == checkconf_print(copy)
    tree = load_tree(conf, "n1", checkconf=find_binary("named-checkconf"))
    assert tree.pelagos["checkconf"]["ok"] is True
    assert {z.name for z in tree.zones} == {
        "example.lan.",
        "2.0.192.in-addr.arpa.",
        "8.b.d.0.1.0.0.2.ip6.arpa.",
    }
    assert [k.name for k in tree.keys] == ["ddi-read", "ddi-admin", "kea-ddns", "secondary-xfr", "rndc-key"]
    assert tree.controls and tree.statistics_channels
