# SPDX-License-Identifier: Apache-2.0
"""A real named with zones shaped like production (AAAA at the apex and on hosts, a /64 reverse
zone in nibbles with some PTR missing) and nothing observed: GET /hosts/ipv6 lists every AAAA,
and its `missing_ptr` agrees with `ptr_mismatch` of the consistency pass."""

from __future__ import annotations

import pytest

from tests.daemon.api_node import V1, login, make_app, make_node

pytestmark = pytest.mark.daemon

SOA = "@ IN SOA ns1.home.lan. hostmaster.home.lan. 1 3600 900 1209600 300\n@ IN NS ns1.example.lan.\n"
FORWARD = (
    "$TTL 300\n" + SOA + "@ IN AAAA 2001:db8:5::1\n@ IN AAAA 2001:db8:5::2\n"
    "desktop IN AAAA 2001:db8:5::a1\nlaptop IN AAAA 2001:db8:5::b2\nprinter IN AAAA 2001:db8:5::c3\n"
)
REV = "0.0.0.0.5.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
REVERSE = (
    "$TTL 300\n" + SOA + "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 IN PTR home.lan.\n"
    "3.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0 IN PTR printer.home.lan.\n"
    "2.b.0.0.0.0.0.0.0.0.0.0.0.0.0.0 IN PTR old-laptop.home.lan.\n"
)
EXPECTED = {"2001:db8:5::2", "2001:db8:5::a1", "2001:db8:5::b2"}


@pytest.fixture
def api(tmp_root, named_server):
    zones = named_server.root / "zones"
    (zones / "home.lan.db").write_text(FORWARD)
    (zones / f"{REV}.db").write_text(REVERSE)
    conf = named_server.named_conf.read_text()
    for name in ("home.lan", REV):
        conf += (
            f'zone "{name}" {{ type primary; file "{name}.db"; '
            "allow-transfer { key ddi-read; }; notify no; };\n"
        )
    named_server.named_conf.write_text(conf)
    named_server.rndc("reconfig")
    ctx = make_node(tmp_root / "node", named=named_server)
    yield login(make_app(ctx)), ctx
    from pelagos.services.container import Services

    Services.of(ctx).close()


def test_zone_aaaa_rows_agree_with_ptr_mismatch(api):
    client, ctx = api
    page = client.get(f"{V1}/hosts/ipv6?per_page=500").get_json()
    assert not any(k.startswith("dns") for k in page["meta"].get("errors", {})), page["meta"]
    by_name = {r["name"]: r for r in page["items"]}
    apex = by_name["home.lan."]
    assert apex["aaaa"] == ["2001:db8:5::1", "2001:db8:5::2"] and apex["observed"] == []
    assert apex["ptr_missing"] == ["2001:db8:5::2"]
    assert {"desktop.home.lan.", "laptop.home.lan.", "printer.home.lan."} <= set(by_name)
    rows = client.get(f"{V1}/hosts/ipv6?filter=missing_ptr&per_page=500").get_json()["items"]
    flagged = {a for r in rows for a in r["ptr_missing"] if a.startswith("2001:db8:5:")}
    from pelagos.services import consistency
    from pelagos.services.container import Services

    # The collector's pass over the same zones read live (no Kea here: the DNS part only).
    dns = Services.of(ctx).dns
    fwd, _node = dns.records("home.lan.")
    rev, _node = dns.records(REV + ".")
    alerts = consistency.run_all(leases=[], reservations=[], forward={"home.lan.": fwd}, reverse=rev)
    no_ptr = {
        a.details["ip"]
        for a in alerts
        if a.kind.value == "ptr_mismatch" and any("has no PTR" in p for p in a.details["problems"])
    }
    assert flagged == no_ptr == EXPECTED
    # Nothing observed yet on this node: said in meta.unavailable.
    assert {u["error"] for u in page["meta"]["unavailable"]} == {"no observation pass yet"}
