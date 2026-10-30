# SPDX-License-Identifier: Apache-2.0
"""IPv6 plans against a real named (dynamic example.lan. and 8.b.d.0.1.0.0.2.ip6.arpa.): the AAAA
and PTR of an observed address written by UPDATE, then moved to another prefix with their PTR."""

from __future__ import annotations

import ipaddress
import time

import pytest

from tests.daemon.api_node import V1, apply, login, make_app, make_node, planned

pytestmark = pytest.mark.daemon

MAC = "00:00:5e:00:53:42"
EUI = "2001:db8:5:0:200:5eff:fe00:5342"
MOVED = "2001:db8:6:0:200:5eff:fe00:5342"
REV = "8.b.d.0.1.0.0.2.ip6.arpa"
DAY = 86400


@pytest.fixture
def api(tmp_root, named_server):
    from pelagos.collector import series as series_mod
    from pelagos.collector.ipv6 import store as obs_store
    from pelagos.collector.ipv6.source import Neighbor

    ctx = make_node(tmp_root / "node", named=named_server)
    now = int(time.time())
    conn = series_mod.connect(ctx.paths.series_db)
    obs_store.ensure(conn)
    for ts in (now - DAY, now):
        obs_store.record(conn, [Neighbor(MAC, EUI, "reachable")], "neighbors", None, ctx.node.id, ts)
    conn.commit()
    conn.close()
    yield login(make_app(ctx)), ctx
    from pelagos.services.container import Services

    Services.of(ctx).close()


def records(client, zone: str) -> dict[tuple[str, str], list[str]]:
    page = client.get(f"{V1}/dns/zones/{zone}/records?per_page=500").get_json()
    return {(r["name"], r["rtype"]): r["rdata"] for r in page["items"]}


def ptr(address: str) -> str:
    return ipaddress.IPv6Address(address).reverse_pointer + "."


def test_selection_then_prefix_replacement(api):
    client, _ctx = api
    item = {"host_key": f"mac:{MAC}", "address": EUI, "name": "v6host.example.lan"}
    plan = planned(client.post(f"{V1}/hosts/ipv6/plan", json={"items": [item]}))
    result = apply(client, plan)
    assert result["state"] == "applied", result
    assert records(client, "example.lan")[("v6host.example.lan.", "AAAA")] == [EUI]
    assert records(client, REV)[(ptr(EUI), "PTR")] == ["v6host.example.lan."]

    body = {"old_prefix": "2001:db8:5::/64", "new_prefix": "2001:db8:6::/64", "zones": ["example.lan"]}
    plan = planned(client.post(f"{V1}/hosts/ipv6/replace-prefix/plan", json=body))
    assert plan["requires_confirmation"] is True
    result = apply(client, plan, confirm=True)
    assert result["state"] == "applied", result
    assert records(client, "example.lan")[("v6host.example.lan.", "AAAA")] == [MOVED]
    rev = records(client, REV)
    assert (ptr(EUI), "PTR") not in rev and rev[(ptr(MOVED), "PTR")] == ["v6host.example.lan."]
