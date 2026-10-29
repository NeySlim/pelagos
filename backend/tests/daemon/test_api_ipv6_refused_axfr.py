# SPDX-License-Identifier: Apache-2.0
"""A real named refusing the transfer of one dynamic zone (allow-transfer by address only, no
ddi-read key): the hosts and IPv6 routes name that zone in meta.errors and list the rest."""

from __future__ import annotations

import time

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import Neighbor
from tests.daemon.api_node import V1, login, make_app, make_node

pytestmark = pytest.mark.daemon

MAC = "02:00:5e:00:53:77"
ZONE = """$TTL 300
@ IN SOA ns1.refused.lan. hostmaster.refused.lan. 1 3600 900 1209600 300
@ IN NS ns1.refused.lan.
ns1 IN A 192.0.2.1
"""


@pytest.fixture
def api(tmp_root, named_server):
    (named_server.root / "zones" / "refused.lan.db").write_text(ZONE)
    conf = named_server.named_conf.read_text()
    conf += (
        'zone "refused.lan" { type primary; file "refused.lan.db"; '
        "update-policy { grant ddi-admin zonesub ANY; }; allow-transfer { 192.0.2.1; }; notify no; };\n"
    )
    named_server.named_conf.write_text(conf)
    named_server.rndc("reconfig")
    ctx = make_node(tmp_root / "node", named=named_server)
    conn = series_mod.connect(ctx.paths.series_db)
    obs_store.ensure(conn)
    obs_store.record(
        conn, [Neighbor(MAC, "2001:db8::77", "reachable")], "neighbors", None, ctx.node.id, int(time.time())
    )
    conn.commit()
    conn.close()
    yield login(make_app(ctx)), ctx
    from pelagos.services.container import Services

    Services.of(ctx).close()


def test_refused_transfer_is_reported_not_a_503(api):
    client, _ctx = api
    r = client.get(f"{V1}/hosts/ipv6")
    assert r.status_code == 200, r.get_json()
    page = r.get_json()
    unread = page["meta"]["errors"]["dns.zones"]
    assert "refused.lan." in unread and "refused" in unread.lower() and "example.lan." not in unread
    assert [row["mac"] for row in page["items"]] == [MAC]
    hosts = client.get(f"{V1}/hosts?per_page=500")
    assert hosts.status_code == 200, hosts.get_json()
    body = hosts.get_json()
    assert "refused.lan." in body["meta"]["errors"]["dns.zones"]
    # example.lan. was read: its A records still make hosts.
    assert any(r["name"].endswith(".example.lan.") for h in body["items"] for r in h["records"])
