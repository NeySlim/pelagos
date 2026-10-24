# SPDX-License-Identifier: Apache-2.0
"""Lossless zone file editor: comments, directives and untouched lines survive every edit."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from pelagos.connectors.bind import zonefile as zfm
from pelagos.connectors.bind.zonefile import RecordEdit, ZoneFileError
from pelagos.domain.dns import RRset
from pelagos.domain.plan import ChangeOp

pytestmark = pytest.mark.unit

MAIN = """; example.lan, kept by hand
$TTL 3600
$ORIGIN example.lan.
@\tIN SOA ns1 hostmaster (
\t\t2026102401 ; serial
\t\t3600 900 1209600 300 )
\tIN NS ns1
\tIN NS ns2

; hosts
ns1\tIN A 192.0.2.1
\tIN AAAA 2001:db8::1
ns2\tIN A 192.0.2.2   ; second server
www 300 IN A 192.0.2.10
\tIN TXT "hello; world"
$INCLUDE "sub.inc" lab.example.lan.
mail\tIN MX 10 mx.example.net.
"""

SUB = """; lab hosts
$TTL 600
pc1\tA 192.0.2.50
pc2\tA 192.0.2.51
"""


@pytest.fixture
def files(tmp_path: Path) -> zfm.ZoneFiles:
    (tmp_path / "example.lan.db").write_text(MAIN)
    (tmp_path / "sub.inc").write_text(SUB)
    return zfm.load("example.lan", tmp_path / "example.lan.db", tmp_path)


def rs(name: str, rtype: str, ttl: int, *rdata: str) -> RRset:
    return RRset(name=name, rtype=rtype, ttl=ttl, rdata=sorted(rdata))


def test_parse_reads_owners_ttls_origins_and_includes(files: zfm.ZoneFiles) -> None:
    sets = {(r.name, r.rtype): r for r in files.rrsets()}
    assert sets[("example.lan.", "NS")].rdata == ["ns1.example.lan.", "ns2.example.lan."]
    assert sets[("ns1.example.lan.", "AAAA")].rdata == ["2001:db8::1"]
    assert sets[("www.example.lan.", "TXT")].ttl == 3600 and sets[("www.example.lan.", "A")].ttl == 300
    assert sets[("pc1.lab.example.lan.", "A")].ttl == 600
    assert sets[("mail.example.lan.", "MX")].ttl == 3600  # $TTL of the parent restored after the include
    assert files.serial() == 2026102401
    assert [p.name for p in files.order] == ["example.lan.db", "sub.inc"]


def test_serials() -> None:
    assert zfm.next_serial(2026102401, date(2026, 10, 24)) == 2026102402
    assert zfm.next_serial(2026102301, date(2026, 10, 24)) == 2026102400
    assert zfm.next_serial(41) == 42
    assert zfm.next_serial(2**32 - 1) == 1
    assert not zfm.is_date_serial(1234567890)


def test_add_next_to_its_owner_keeps_everything_else(files: zfm.ZoneFiles) -> None:
    edit = RecordEdit(
        ChangeOp.ADD, "www.example.lan.", "AAAA", None, rs("www.example.lan.", "AAAA", 300, "2001:db8::10")
    )
    texts = zfm.edit(files, [edit], serial=2026102402)
    main = texts[files.main]
    assert "2026102402 ; serial" in main and "; hosts" in main and '"hello; world"' in main
    lines = main.splitlines()
    i = lines.index('\tIN TXT "hello; world"')
    assert lines[i + 1] == "www\t300\tIN\tAAAA\t2001:db8::10"
    assert len(lines) == len(MAIN.splitlines()) + 1
    assert set(texts) == {files.main}


def test_delete_an_owner_line_makes_the_next_owner_explicit(files: zfm.ZoneFiles) -> None:
    edit = RecordEdit(
        ChangeOp.DELETE, "ns1.example.lan.", "A", rs("ns1.example.lan.", "A", 3600, "192.0.2.1"), None
    )
    main = zfm.edit(files, [edit])[files.main]
    assert "ns1\tIN A 192.0.2.1" not in main
    assert "ns1\tIN AAAA 2001:db8::1" in main  # inherited the deleted line's owner: written out


def test_replace_in_an_included_file_edits_that_file(files: zfm.ZoneFiles, tmp_path: Path) -> None:
    edit = RecordEdit(
        ChangeOp.REPLACE,
        "pc1.lab.example.lan.",
        "A",
        rs("pc1.lab.example.lan.", "A", 600, "192.0.2.50"),
        rs("pc1.lab.example.lan.", "A", 600, "192.0.2.60"),
    )
    texts = zfm.edit(files, [edit], serial=2026102402)
    sub = texts[tmp_path / "sub.inc"]
    assert sub == "; lab hosts\n$TTL 600\npc1\tIN\tA\t192.0.2.60\npc2\tA 192.0.2.51\n"
    assert "2026102402" in texts[files.main]


def test_ttl_change_rewrites_only_the_ttl(files: zfm.ZoneFiles) -> None:
    edit = RecordEdit(
        ChangeOp.REPLACE,
        "ns2.example.lan.",
        "A",
        rs("ns2.example.lan.", "A", 3600, "192.0.2.2"),
        rs("ns2.example.lan.", "A", 120, "192.0.2.2"),
    )
    main = zfm.edit(files, [edit])[files.main]
    assert "ns2\t120\tIN A 192.0.2.2   ; second server" in main


def test_no_ttl_directive_keeps_inherited_ttls(tmp_path: Path) -> None:
    text = (
        "example.lan. 300 IN SOA ns1.example.lan. h.example.lan. 1 2 3 4 5\n"
        "a 300 IN A 192.0.2.1\nb IN A 192.0.2.2\n"
    )
    (tmp_path / "z.db").write_text(text)
    zf = zfm.load("example.lan", tmp_path / "z.db", tmp_path)
    edit = RecordEdit(ChangeOp.ADD, "a.example.lan.", "TXT", None, rs("a.example.lan.", "TXT", 60, '"x"'))
    out = zfm.edit(zf, [edit])[tmp_path / "z.db"]
    again = zfm.parse_texts("example.lan", tmp_path / "z.db", tmp_path, {tmp_path / "z.db": out})
    assert {(r.owner, r.ttl) for r in again.records if r.rtype == "A"} == {
        ("a.example.lan.", 300),
        ("b.example.lan.", 300),
    }


def test_stale_before_is_refused(files: zfm.ZoneFiles) -> None:
    edit = RecordEdit(
        ChangeOp.DELETE, "www.example.lan.", "A", rs("www.example.lan.", "A", 300, "192.0.2.99"), None
    )
    with pytest.raises(ZoneFileError, match="changed since the plan"):
        zfm.edit(files, [edit])
    add = RecordEdit(
        ChangeOp.ADD, "www.example.lan.", "A", None, rs("www.example.lan.", "A", 300, "192.0.2.1")
    )
    with pytest.raises(ZoneFileError, match="changed since the plan"):
        zfm.edit(files, [add])


def test_new_owner_goes_at_the_end_of_the_main_file(files: zfm.ZoneFiles) -> None:
    edit = RecordEdit(
        ChangeOp.ADD,
        "new.example.lan.",
        "CNAME",
        None,
        rs("new.example.lan.", "CNAME", 3600, "www.example.lan."),
    )
    main = zfm.edit(files, [edit])[files.main]
    assert main.endswith("mail\tIN MX 10 mx.example.net.\nnew\tIN\tCNAME\twww\n")


def test_copy_for_check_points_includes_at_copies(files: zfm.ZoneFiles, tmp_path: Path) -> None:
    edit = RecordEdit(ChangeOp.ADD, "a.example.lan.", "A", None, rs("a.example.lan.", "A", 3600, "192.0.2.7"))
    texts = zfm.edit(files, [edit])
    copy = zfm.copy_for_check(files, texts, tmp_path / "check")
    again = zfm.load("example.lan", copy, tmp_path / "elsewhere")
    assert {r.name for r in again.rrsets()} >= {"a.example.lan.", "pc1.lab.example.lan."}


def test_parse_errors() -> None:
    for text in [
        "$ORIGIN\n",
        "\tIN A 192.0.2.1\n",
        "a IN A (\n",
        'a IN TXT "open\n',
        "$FOO x\n",
        "a 1 IN BOGUS x\n",
    ]:
        with pytest.raises(ZoneFileError):
            zfm.parse_texts("example.lan", Path("/z"), Path("/"), {Path("/z"): text})
