# SPDX-License-Identifier: Apache-2.0
"""Static primary zones against a real named: record plans edit the zone file (comments, $ORIGIN,
$TTL and $INCLUDE kept), bump the serial, reload the zone; rollback edits back with a new serial."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from pelagos.connectors.bind.dns_client import DnsClient
from pelagos.domain.plan import Change, ChangeOp, PlanState
from tests.daemon.test_bind_backend import make_backend
from tests.fixtures import named as named_fx

pytestmark = pytest.mark.daemon

STATIC = """; static.lan: edited by hand, keep this comment
$TTL 3600
@\tIN SOA ns1.static.lan. hostmaster.static.lan. (
\t\t2026102401 ; serial
\t\t3600 900 1209600 300 )
\tIN NS ns1

ns1\tIN A 192.0.2.1   ; the server
www\tIN A 192.0.2.10

$INCLUDE "static.lan.lab.inc" lab.static.lan.
"""

LAB = """; lab hosts
pc1\tIN A 192.0.2.50
"""


def add_static_zone(
    server: named_fx.NamedServer, name: str = "static.lan", transfer: bool = True, extra: str = ""
) -> Path:
    zones = server.root / "zones"
    path = zones / f"{name}.db"
    path.write_text(STATIC.replace("static.lan", name))
    (zones / f"{name}.lab.inc").write_text(LAB)
    xfr = "allow-transfer { key ddi-read; };" if transfer else ""
    conf = server.named_conf.read_text()
    conf += f'zone "{name}" {{ type primary; file "{name}.db"; {xfr} {extra} notify no; }};\n'
    server.named_conf.write_text(conf)
    server.rndc("reconfig")
    return path


def serial(server: named_fx.NamedServer, zone: str) -> int | None:
    return DnsClient("127.0.0.1", server.dns_port).soa_serial(zone)


def test_static_zone_record_edit_keeps_the_file_and_rolls_back(named_server, tmp_root):
    path = add_static_zone(named_server)
    backend = make_backend(named_server, tmp_root)
    zone = backend.static_zone("static.lan")
    assert zone is not None and not zone.dynamic
    add = backend.plan_rrset_changes(
        "static.lan",
        [
            Change(ChangeOp.ADD, "static.lan/mail/A", after={"rdata": ["192.0.2.25"], "ttl": 3600}),
            Change(
                ChangeOp.REPLACE,
                "static.lan/pc1.lab/A",
                after={"rdata": ["192.0.2.51"], "ttl": 3600},
            ),
        ],
        created_by="alice",
    )
    assert add.state is PlanState.VALIDATED, add.validations
    assert "file edit, the zone stays static" in add.summary
    assert "+mail\tIN\tA\t192.0.2.25" in add.diff and "static.lan.lab.inc" in add.diff
    assert any(v.tool == "named-checkzone" and v.ok for v in add.validations)

    result = backend.apply(add)
    assert result.ok, result.message
    text = path.read_text()
    assert text.startswith("; static.lan: edited by hand, keep this comment\n$TTL 3600\n")
    assert "ns1\tIN A 192.0.2.1   ; the server" in text and '$INCLUDE "static.lan.lab.inc"' in text
    assert (path.parent / "static.lan.lab.inc").read_text() == "; lab hosts\npc1\tIN\tA\t192.0.2.51\n"
    new_serial = serial(named_server, "static.lan")
    assert new_serial and new_serial > 2026102401
    assert f"{new_serial} ; serial" in text  # the date-based scheme is kept, in place
    data = {(r.name, r.rtype): r.rdata for r in backend.read_zone("static.lan")}
    assert data[("mail.static.lan.", "A")] == ["192.0.2.25"]
    assert data[("pc1.lab.static.lan.", "A")] == ["192.0.2.51"]
    assert not (path.parent / "static.lan.db.jnl").exists()  # still static: no journal
    assert backend.details[add.id]["apply"]["request"]["mode"] == "file"

    back = backend.rollback(add)
    assert back.ok and back.rolled_back, back.message
    data = {(r.name, r.rtype): r.rdata for r in backend.read_zone("static.lan")}
    assert ("mail.static.lan.", "A") not in data and data[("pc1.lab.static.lan.", "A")] == ["192.0.2.50"]
    assert serial(named_server, "static.lan") > new_serial
    assert "; static.lan: edited by hand, keep this comment" in path.read_text()


def test_static_zone_without_transfer_is_read_from_its_file(named_server, tmp_root):
    add_static_zone(named_server, "quiet.lan", transfer=False)
    backend = make_backend(named_server, tmp_root)
    data = {(r.name, r.rtype): r.rdata for r in backend.read_zone("quiet.lan")}
    assert data[("www.quiet.lan.", "A")] == ["192.0.2.10"]


def test_static_zone_bad_edit_and_unwritable_file_are_refused(named_server, tmp_root):
    path = add_static_zone(named_server)
    backend = make_backend(named_server, tmp_root)
    cname = backend.plan_rrset_changes(
        "static.lan", [Change(ChangeOp.ADD, "static.lan/ns1/CNAME", after={"rdata": ["www"], "ttl": 60})]
    )
    assert cname.state is PlanState.FAILED  # CNAME next to other data
    if os.geteuid() == 0:
        pytest.skip("root writes any file")
    path.chmod(0o444)
    path.parent.chmod(0o555)
    try:
        plan = backend.plan_rrset_changes(
            "static.lan", [Change(ChangeOp.ADD, "static.lan/x/A", after={"rdata": ["192.0.2.9"], "ttl": 60})]
        )
        assert plan.state is PlanState.FAILED
        assert "not writable" in (plan.error or "") and "convert the zone to dynamic" in plan.error
        assert not backend.apply(plan).ok
    finally:
        path.parent.chmod(0o755)
        path.chmod(0o644)


def test_allow_update_none_is_a_static_zone(named_server, tmp_root):
    path = add_static_zone(named_server, "none.lan", extra="allow-update { none; };")
    backend = make_backend(named_server, tmp_root)
    assert backend.static_zone("none.lan") is not None
    plan = backend.plan_rrset_changes(
        "none.lan", [Change(ChangeOp.ADD, "none.lan/mail/A", after={"rdata": ["192.0.2.25"], "ttl": 3600})]
    )
    assert plan.state is PlanState.VALIDATED and "file edit" in plan.summary
    result = backend.apply(plan)
    assert result.ok, result.message
    assert "mail\tIN\tA\t192.0.2.25" in path.read_text()
    data = {(r.name, r.rtype): r.rdata for r in backend.read_zone("none.lan")}
    assert data[("mail.none.lan.", "A")] == ["192.0.2.25"]


def test_allow_update_inherited_from_the_options_takes_updates(named_server, tmp_root):
    path = add_static_zone(named_server, "inherit.lan")
    conf = named_server.named_conf.read_text()
    named_server.named_conf.write_text(
        conf.replace("\trecursion no;", "\trecursion no;\n\tallow-update { key ddi-admin; };", 1)
    )
    named_server.rndc("reconfig")
    backend = make_backend(named_server, tmp_root)
    zone = backend.config_zone("inherit.lan")
    assert zone is not None and zone.dynamic and backend.static_zone("inherit.lan") is None
    plan = backend.plan_rrset_changes(
        "inherit.lan",
        [Change(ChangeOp.ADD, "inherit.lan/mail/A", after={"rdata": ["192.0.2.25"], "ttl": 3600})],
    )
    assert plan.state is PlanState.VALIDATED and "file edit" not in plan.summary
    result = backend.apply(plan)
    assert result.ok, result.message
    data = {(r.name, r.rtype): r.rdata for r in backend.read_zone("inherit.lan")}
    assert data[("mail.inherit.lan.", "A")] == ["192.0.2.25"]
    assert "192.0.2.25" not in path.read_text()  # named keeps the change in its journal


def test_large_static_zone_waits_for_the_queued_reload(named_server, tmp_root):
    """`rndc reload <zone>` only queues the load: a 20k-record zone is verified by polling, never
    restored to the old serial after named already loaded the new one."""
    zones = named_server.root / "zones"
    path = zones / "big.lan.db"
    hosts = "".join(f"h{i}\tIN A 10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}\n" for i in range(20000))
    path.write_text(
        "$TTL 3600\n@\tIN SOA ns1.big.lan. hostmaster.big.lan. ( 1 3600 900 1209600 300 )\n"
        "\tIN NS ns1\nns1\tIN A 192.0.2.1\n" + hosts
    )
    zone = (
        'zone "big.lan" { type primary; file "big.lan.db"; allow-transfer { key ddi-read; }; notify no; };\n'
    )
    named_server.named_conf.write_text(named_server.named_conf.read_text() + zone)
    named_server.rndc("reconfig")
    backend = make_backend(named_server, tmp_root)
    for _ in range(100):
        if serial(named_server, "big.lan") == 1:
            break
        time.sleep(0.1)
    change = Change(ChangeOp.ADD, "big.lan/mail/A", after={"rdata": ["192.0.2.25"], "ttl": 3600})
    plan = backend.plan_rrset_changes("big.lan", [change])
    assert plan.state is PlanState.VALIDATED, plan.validations
    result = backend.apply(plan)
    assert result.ok and not result.rolled_back, result.message
    assert serial(named_server, "big.lan") == 2
    assert "mail\tIN\tA\t192.0.2.25" in path.read_text()


def _count_axfr(backend):
    asked: list[str] = []
    real = backend.dns.axfr

    def spy(zone, key=None):
        asked.append(zone)
        return real(zone, key)

    backend.dns.axfr = spy
    return asked


def test_builtin_zone_is_read_from_its_file_without_a_transfer(named_server, tmp_root):
    add_static_zone(named_server, "localhost", transfer=False)
    backend = make_backend(named_server, tmp_root)
    asked = _count_axfr(backend)
    data = {(r.name, r.rtype) for r in backend.read_zone("localhost")}
    assert ("www.localhost.", "A") in data
    assert asked == []


def test_refused_transfer_is_not_asked_again(named_server, tmp_root):
    from pelagos.connectors.base import ConnectorDenied

    add_static_zone(named_server, "quiet.lan", transfer=False)
    backend = make_backend(named_server, tmp_root)
    asked = _count_axfr(backend)
    for _ in range(3):
        assert backend.read_zone("quiet.lan")
    assert asked == ["quiet.lan"]
    backend._axfr_refused.clear()  # a configuration change asks once more
    backend.read_zone("quiet.lan")
    assert asked == ["quiet.lan", "quiet.lan"]
    # A reconfig by another process (a security plan granting the transfer) asks once more too.
    time.sleep(1.1)
    named_server.rndc("reconfig")
    backend.read_zone("quiet.lan")
    backend.read_zone("quiet.lan")
    assert asked == ["quiet.lan", "quiet.lan", "quiet.lan"]
    with pytest.raises(ConnectorDenied):  # no file to fall back on: denied from memory
        backend._axfr_refused[("nofile.lan.", "_default")] = (time.monotonic(), backend._last_configured())
        backend.read_zone("nofile.lan")
    assert asked == ["quiet.lan", "quiet.lan", "quiet.lan"]
