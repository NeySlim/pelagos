# SPDX-License-Identifier: Apache-2.0
"""Record types of B1-RRTYPES: normalization, coexistence rules (DS, DNAME), UPDATE text, static files."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import dns.update
import pytest

from pelagos.connectors.bind import rrset as rr
from pelagos.connectors.bind import zonefile as zfm
from pelagos.connectors.bind.zonefile import RecordEdit
from pelagos.domain import zone_updates
from pelagos.domain.dns import RRset
from pelagos.domain.plan import Change, ChangeOp

pytestmark = pytest.mark.unit

Z = "example.lan."
SSHFP_FP = "123456789abcdef67890123456789abcdef67890"
TLSA_HASH = "d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971"
DS_DIGEST = "2bb183af5f22588179a53b0a98631fad1a292118a24f0a2f6fa15e8a46f2fb63"

# One value per new type, as typed; the second column is dnspython's presentation form.
SAMPLES: dict[str, tuple[str, str]] = {
    "SSHFP": (f"4 1 {SSHFP_FP.upper()}", f"4 1 {SSHFP_FP}"),
    "TLSA": (f"3 1 1 {TLSA_HASH.upper()}", f"3 1 1 {TLSA_HASH}"),
    "HTTPS": ('1 . alpn="h3,h2" port=8443', '1 . alpn="h3,h2" port="8443"'),
    # named refuses an SVCB under _dns without alpn (RFC 9461): every sample carries one.
    "SVCB": ('1 svc.example.lan. alpn="dot" port=853', '1 svc.example.lan. alpn="dot" port="853"'),
    "NAPTR": ('100 10 "S" "SIP+D2U" "" _sip._udp', '100 10 "S" "SIP+D2U" "" _sip._udp.example.lan.'),
    "LOC": ("52 22 23 N 4 53 32 E -2m 0m 10000m 10m", ""),
    "DNAME": ("target.example.net.", "target.example.net."),
    "DS": (f"60485 13 2 {DS_DIGEST.upper()}", f"60485 13 2 {DS_DIGEST}"),
    "URI": ('10 1 "https://www.example.lan/"', '10 1 "https://www.example.lan/"'),
}
NEW_TYPES = ("SSHFP", "TLSA", "HTTPS", "SVCB", "NAPTR", "LOC", "DNAME", "DS", "URI")


def test_new_types_are_granted_and_the_former_defaults_are_kept():
    assert set(NEW_TYPES) <= set(zone_updates.ADMIN_UPDATE_TYPES)
    assert set(zone_updates.PREVIOUS_ADMIN_UPDATE_TYPES) < set(zone_updates.ADMIN_UPDATE_TYPES)
    assert not set(NEW_TYPES) & rr.FORBIDDEN_TYPES


@pytest.mark.parametrize("rtype", NEW_TYPES)
def test_rdata_is_normalized_and_stable(rtype):
    typed, expected = SAMPLES[rtype]
    norm = rr.normalize_rdata(rtype, typed, Z)
    if expected:
        assert norm == [expected]
    assert rr.normalize_rdata(rtype, norm, Z) == norm


@pytest.mark.parametrize(
    "rtype, bad",
    [
        ("SSHFP", "4 2 zz"),
        ("TLSA", "3 1"),
        ("HTTPS", "1 . nokey=="),
        ("SVCB", "x svc.example.lan."),
        ("NAPTR", "100 10 S SIP"),
        ("LOC", "north pole"),
        ("DS", "60485 13 2 nothex"),
        ("URI", "10 https://x"),
    ],
)
def test_bad_rdata_is_refused(rtype, bad):
    with pytest.raises(rr.RRsetError, match=f"invalid {rtype} rdata"):
        rr.normalize_rdata(rtype, bad, Z)


def zone_with(*extra: RRset) -> list[RRset]:
    return [
        RRset(Z, "SOA", 3600, ["ns1.example.lan. hostmaster.example.lan. 1 3600 900 1209600 300"]),
        RRset(Z, "NS", 3600, ["ns1.example.lan."]),
        RRset("ns1.example.lan.", "A", 3600, ["192.0.2.1"]),
        RRset("sub.example.lan.", "NS", 3600, ["ns.sub.example.lan."]),
        RRset("ns.sub.example.lan.", "A", 3600, ["192.0.2.53"]),
        RRset("www.example.lan.", "A", 3600, ["192.0.2.10"]),
        *extra,
    ]


def resolve(changes: list[Change], current: list[RRset] | None = None) -> tuple[list, list[str]]:
    return rr.resolve_changes(Z, changes, zone_with() if current is None else current)


def add(target: str, *rdata: str) -> Change:
    return Change(ChangeOp.ADD, f"{Z}/{target}", after={"rdata": list(rdata), "ttl": 300})


DS = SAMPLES["DS"][0]


def test_every_new_type_resolves_into_one_update():
    changes = [
        add("_22._tcp.ssh/SSHFP", SAMPLES["SSHFP"][0]),
        add("_443._tcp.www/TLSA", SAMPLES["TLSA"][0]),
        add("www/HTTPS", SAMPLES["HTTPS"][0]),
        add("_dns.resolver/SVCB", SAMPLES["SVCB"][0]),
        add("sip/NAPTR", SAMPLES["NAPTR"][0]),
        add("office/LOC", SAMPLES["LOC"][0]),
        add("old/DNAME", SAMPLES["DNAME"][0]),
        add("sub/DS", DS),
        add("_http._tcp/URI", SAMPLES["URI"][0]),
    ]
    resolved, errors = resolve(changes)
    assert errors == [] and [rc.rtype for rc in resolved] == list(NEW_TYPES)
    msg = dns.update.Update(Z)
    rr.build_update(msg, resolved)
    assert len(msg.prerequisite) == len(msg.update) == len(NEW_TYPES)  # nxrrset, then the add
    text = rr.update_text(Z, resolved)
    assert f"update add sub.example.lan. 300 IN DS {SAMPLES['DS'][1]}" in text
    assert '+www.example.lan. 300 IN HTTPS 1 . alpn="h3,h2" port="8443"' in rr.diff_text(resolved)
    back = [rr.inverse(rc) for rc in resolved]
    assert {rc.op for rc in back} == {ChangeOp.DELETE}


def test_ds_only_at_a_delegation():
    _, errors = resolve([add("www/DS", DS)])
    assert errors == ["www.example.lan. has no NS records: a DS record only sits at a delegation"]
    _, errors = resolve([add("@/DS", DS)])
    assert errors == ["example.lan.: a DS record cannot sit at the zone apex"]
    # The delegation and its DS can come in one plan.
    resolved, errors = resolve([add("new/NS", "ns.new.example.lan."), add("new/DS", DS)])
    assert errors == [] and len(resolved) == 2


def test_a_delegation_with_a_ds_loses_both_together():
    current = zone_with(RRset("sub.example.lan.", "DS", 3600, [SAMPLES["DS"][1]]))
    _, errors = resolve([Change(ChangeOp.DELETE, f"{Z}/sub/NS")], current)
    assert errors and "keeps its DS records" in errors[0]
    _, errors = resolve(
        [Change(ChangeOp.DELETE, f"{Z}/sub/NS"), Change(ChangeOp.DELETE, f"{Z}/sub/DS")], current
    )
    assert errors == []
    # The apex NS set is not a delegation: the existing apex rule applies, not this one.
    _, errors = resolve([Change(ChangeOp.DELETE, f"{Z}/@/NS")], current)
    assert errors and "keeps its name servers" in errors[0]


def test_dname_occludes_the_names_below():
    below_www = zone_with(RRset("x.www.example.lan.", "TXT", 3600, ['"x"']))
    _, errors = resolve([add("www/DNAME", "elsewhere.example.net.")], below_www)
    assert errors and "has names below it (x.www.example.lan.)" in errors[0]
    current = zone_with(RRset("old.example.lan.", "DNAME", 3600, ["new.example.lan."]))
    _, errors = resolve([add("host.old/A", "192.0.2.20")], current)
    assert errors == [
        "host.old.example.lan. is below the DNAME at old.example.lan.; no record can be added there"
    ]
    _, errors = resolve([add("a.b.old/TXT", '"x"')], current)
    assert errors and "below the DNAME at old.example.lan." in errors[0]
    # A DNAME and other data at the same name (RFC 6672 2.3): only CNAME is excluded.
    resolved, errors = resolve([add("old/A", "192.0.2.21")], current)
    assert errors == [] and resolved
    _, errors = resolve([add("old/CNAME", "www.example.lan.")], current)
    assert errors and "a CNAME cannot coexist" in errors[0]
    # Names below that the same plan removes no longer block the DNAME.
    _, errors = resolve(
        [
            Change(ChangeOp.DELETE, f"{Z}/ns.sub/A"),
            Change(ChangeOp.DELETE, f"{Z}/sub/NS"),
            Change(ChangeOp.ADD, f"{Z}/sub/DNAME", after={"rdata": ["elsewhere.example.net."]}),
        ]
    )
    assert errors == []


def test_dname_and_ns_share_a_name_only_at_the_apex():
    """RFC 6672 2.3: a DNAME beside NS below the apex would hide behind the zone cut."""
    _, errors = resolve([add("sub/DNAME", "elsewhere.example.net.")], zone_with()[:4])
    assert errors == ["sub.example.lan.: DNAME and NS records share a name only at the zone apex"]
    current = zone_with(RRset("old.example.lan.", "DNAME", 3600, ["new.example.lan."]))
    _, errors = resolve([add("old/NS", "ns.elsewhere.example.net.")], current)
    assert errors == ["old.example.lan.: DNAME and NS records share a name only at the zone apex"]
    apex_only = zone_with()[:2]
    resolved, errors = resolve([add("@/DNAME", "example.net.")], apex_only)
    assert errors == [] and resolved


def test_ds_never_below_another_delegation():
    _, errors = resolve([add("a.sub/NS", "ns.a.example.net."), add("a.sub/DS", DS)])
    assert any("below the delegation sub.example.lan." in e for e in errors)


def test_dname_holds_a_single_target():
    _, errors = resolve([add("old/DNAME", "a.example.net.", "b.example.net.")])
    assert errors == ["old.example.lan. DNAME must have exactly one target"]


# Static zone files: an edit of one record of a new type leaves every other byte in place.
STATIC = """$TTL 3600
$ORIGIN example.lan.
@\tIN SOA ns1 hostmaster ( 2026110101 3600 900 1209600 300 )
\tIN NS ns1
ns1\tIN A 192.0.2.1
sub\tIN NS ns.sub
\tIN DS 60485 13 2 2BB183AF5F22588179A53B0A98631FAD1A292118A24F0A2F6FA15E8A46F2FB63
ns.sub\tIN A 192.0.2.53
_22._tcp.ssh IN SSHFP 4 1 123456789ABCDEF67890123456789ABCDEF67890 ; host key
_443._tcp.www IN TLSA 3 1 1 (
\t\tD2ABDE240D7CD3EE6B4B28C54DF034B97983A1D16E8A410E4561CB106618E971 )
www\tIN HTTPS 1 . alpn="h3,h2" port=8443
_dns.resolver IN SVCB 1 svc alpn=dot port=853
sip\tIN NAPTR 100 10 "S" "SIP+D2U" "" _sip._udp
office\tIN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m
old\tIN DNAME new.example.lan.
_http._tcp IN URI 10 1 "https://www.example.lan/"
"""


@pytest.fixture
def static(tmp_path: Path) -> zfm.ZoneFiles:
    (tmp_path / "db.example.lan").write_text(STATIC)
    return zfm.load(Z, tmp_path / "db.example.lan", tmp_path)


def checkzone(text: str, tmp_path: Path) -> None:
    tool = shutil.which("named-checkzone")
    assert tool, "named-checkzone is required (bind9-utils)"
    path = tmp_path / "check.db"
    path.write_text(text)
    out = subprocess.run([tool, "-i", "local", Z, str(path)], capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stdout + out.stderr


def test_static_file_reads_every_new_type(static, tmp_path):
    checkzone(STATIC, tmp_path)
    types = {r.rtype for r in static.rrsets()}
    assert set(NEW_TYPES) <= types


@pytest.mark.parametrize("rtype", NEW_TYPES)
def test_static_replace_changes_only_its_line(static, tmp_path, rtype):
    current = next(r for r in static.rrsets() if r.rtype == rtype)
    new_value = {
        "SSHFP": f"1 1 {SSHFP_FP}",
        "TLSA": f"3 1 2 {'ab' * 64}",
        "HTTPS": '2 . alpn="h2"',
        "SVCB": "2 svc2.example.lan. alpn=dot port=8853",
        "NAPTR": '100 20 "S" "SIP+D2T" "" _sip._tcp.example.lan.',
        "LOC": "52 22 24.000 N 4 53 32.000 E -2.00m 1m 10000m 10m",
        "DNAME": "renamed.example.lan.",
        "DS": f"12345 13 2 {DS_DIGEST}",
        "URI": '20 1 "https://alt.example.lan/"',
    }[rtype]
    after = RRset(current.name, rtype, current.ttl, rr.normalize_rdata(rtype, new_value, Z))
    edit = RecordEdit(ChangeOp.REPLACE, current.name, rtype, current, after)
    text = zfm.edit(static, [edit])[static.main]
    old_lines, new_lines = STATIC.splitlines(), text.splitlines()
    removed = [line for line in old_lines if line not in new_lines]
    added = [line for line in new_lines if line not in old_lines]
    # Exactly the record's own line(s) went; everything else is byte for byte the same.
    assert len(added) == 1 and removed
    assert [line for line in old_lines if line not in removed] == [
        line for line in new_lines if line not in added
    ]
    checkzone(text, tmp_path)
    again = zfm.parse_texts(Z, static.main, static.main.parent, {static.main: text})
    assert next(r for r in again.rrsets() if r.rtype == rtype).rdata == after.rdata


def test_static_add_and_delete_of_new_types(static, tmp_path):
    add_https = RRset("api.example.lan.", "HTTPS", 300, rr.normalize_rdata("HTTPS", '1 . alpn="h2"', Z))
    gone = next(r for r in static.rrsets() if r.rtype == "SSHFP")
    edits = [
        RecordEdit(ChangeOp.ADD, add_https.name, "HTTPS", None, add_https),
        RecordEdit(ChangeOp.DELETE, gone.name, "SSHFP", gone, None),
    ]
    text = zfm.edit(static, edits)[static.main]
    assert "SSHFP" not in text and text.endswith('api\t300\tIN\tHTTPS\t1 . alpn="h2"\n')
    assert text.replace('api\t300\tIN\tHTTPS\t1 . alpn="h2"\n', "") == STATIC.replace(
        "_22._tcp.ssh IN SSHFP 4 1 123456789ABCDEF67890123456789ABCDEF67890 ; host key\n", ""
    )
    checkzone(text, tmp_path)
