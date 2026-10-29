# SPDX-License-Identifier: Apache-2.0
"""Policy and catalog zones are told from named.conf; zone reads of the web process are bounded."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import dns.message
import dns.rrset
import pytest

from pelagos.connectors.base import ZoneTooLarge
from pelagos.connectors.bind import dns_client
from pelagos.domain.dns import RRset, ZoneRole, bulk_zone

from .test_bind_backend_unit import conf_tree, make_backend  # noqa: F401

pytestmark = pytest.mark.unit

POLICY = (
    'zone "hagezi.rpz.invalid" { type primary; file "hagezi.db"; };\n'
    'zone "local-block" { type primary; file "block.db"; };\n'
    'zone "catalog.example" { type secondary; primaries { 192.0.2.1; }; };\n'
)


@pytest.fixture
def backend(tmp_root: Path, conf_tree: Path):  # noqa: F811
    named = conf_tree / "named.conf"
    text = named.read_text().replace(
        "\trecursion no;\n",
        "\trecursion no;\n"
        '\tresponse-policy { zone "hagezi.rpz.invalid"; zone "local-block" policy nxdomain; };\n'
        '\tcatalog-zones { zone "catalog.example" default-primaries { 192.0.2.1; }; };\n',
    )
    named.write_text(text + POLICY)
    b, rec = make_backend(tmp_root, conf_tree)
    return b, rec


def test_list_zones_marks_policy_and_catalog_zones(backend) -> None:
    b, _ = backend
    zones = {z.name: z for z in b.list_zones()}
    assert zones["hagezi.rpz.invalid."].role is ZoneRole.POLICY
    assert zones["local-block."].role is ZoneRole.POLICY  # any name in response-policy, not only the suffix
    assert zones["catalog.example."].role is ZoneRole.CATALOG
    assert zones["example.lan."].role is None
    assert zones["local-block."].to_dict()["role"] == "policy"
    assert [n for n, z in zones.items() if bulk_zone(z)] == [
        "hagezi.rpz.invalid.",
        "local-block.",
        "catalog.example.",
    ]


def test_view_statement_applies_to_its_view_only(tmp_root: Path, conf_tree: Path) -> None:  # noqa: F811
    named = conf_tree / "named.conf"
    text = named.read_text().replace('zone "example.lan" { type primary; file "example.lan.db"; };\n', "")
    named.write_text(
        text
        + 'view "inside" { response-policy { zone "block.example"; };\n'
        + '  zone "block.example" { type primary; file "b.db"; }; };\n'
        + 'view "outside" { zone "block.example" { type primary; file "o.db"; }; };\n'
    )
    b, _ = make_backend(tmp_root, conf_tree)
    roles = {z.view: z.role for z in b.list_zones() if z.name == "block.example."}
    assert roles == {"inside": ZoneRole.POLICY, "outside": None}


@pytest.mark.parametrize(
    ("zone", "bulk"),
    [
        ({"name": "x.rpz.invalid.", "kind": "primary"}, True),  # listed by an older node: suffix
        ({"name": "feed.example.", "kind": "secondary", "notes": "pelagos-rpz"}, True),
        ({"name": "block.example.", "kind": "primary", "role": "policy"}, True),
        ({"name": "cat.example.", "kind": "primary", "role": "catalog"}, True),
        ({"name": "example.lan.", "kind": "primary", "role": None}, False),
        ({"name": "invalid.", "kind": "primary"}, False),
    ],
)
def test_bulk_zone_on_listed_dicts(zone: dict[str, Any], bulk: bool) -> None:
    assert bulk_zone(zone) is bulk


def test_web_read_refuses_a_zone_above_the_limit_before_any_transfer(backend, monkeypatch) -> None:
    b, rec = backend
    asked: list[str] = []
    monkeypatch.setattr(b.dns, "axfr", lambda zone, *a, **k: asked.append(zone) or [])
    rec.zonestatus = lambda zone, view=None: {"type": "primary", "nodes": "829735"}  # type: ignore[method-assign]
    b.read_limit = lambda: 50000
    with pytest.raises(ZoneTooLarge) as exc:
        b.read_zone("hagezi.rpz.invalid")
    assert (exc.value.zone, exc.value.size, exc.value.limit) == ("hagezi.rpz.invalid.", 829735, 50000)
    assert asked == []


def test_web_read_under_the_limit_passes_the_bound_to_the_transfer(backend, monkeypatch) -> None:
    b, rec = backend
    seen: dict[str, Any] = {}

    def axfr(zone: str, key: Any = None, max_records: int | None = None) -> list[RRset]:
        seen["max"] = max_records
        return [RRset("example.lan.", "SOA", 300, ["ns1. h. 1 2 3 4 5"])]

    monkeypatch.setattr(b.dns, "axfr", axfr)
    rec.zonestatus = lambda zone, view=None: {"type": "primary", "nodes": "12"}  # type: ignore[method-assign]
    b.read_limit = lambda: 50000
    assert b.read_zone("example.lan")[0].rtype == "SOA"
    assert seen["max"] == 50000


def test_collector_reads_are_unbounded(backend, monkeypatch) -> None:
    b, rec = backend
    monkeypatch.setattr(b.dns, "axfr", lambda zone, key=None: [])
    rec.zonestatus = lambda *a, **k: pytest.fail("no size check without a limit")  # type: ignore[method-assign]
    assert b.read_limit is None
    assert b.read_zone("example.lan") == []


def _messages(count: int, per_message: int) -> list[dns.message.Message]:
    out = []
    for i in range(count):
        msg = dns.message.Message()
        for j in range(per_message):
            msg.answer.append(dns.rrset.from_text(f"h{i}-{j}.example.lan.", 300, "IN", "A", "192.0.2.1"))
        out.append(msg)
    return out


def test_paced_transfer_stops_past_the_limit_and_yields(monkeypatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(dns_client.time, "sleep", sleeps.append)
    assert len(list(dns_client._paced(iter(_messages(3, 10)), "example.lan", 30))) == 3
    assert sleeps == [0, 0, 0]
    with pytest.raises(ZoneTooLarge) as exc:
        list(dns_client._paced(iter(_messages(5, 10)), "example.lan", 25))
    assert exc.value.size == 30 and exc.value.limit == 25
    assert len(list(dns_client._paced(iter(_messages(5, 10)), "example.lan", None))) == 5
