# SPDX-License-Identifier: Apache-2.0
"""Hosts through the API on a node running named and kea-dhcp4: one host plan writes the A record,
the PTR and the Kea reservation; the join view then shows them together; rollback undoes all three."""

from __future__ import annotations

import pytest

from tests.daemon.api_node import V1, apply, login, make_app, make_node, planned

pytestmark = pytest.mark.daemon


@pytest.fixture
def api(tmp_root, named_server, kea_dhcp4):
    ctx = make_node(tmp_root / "node", named=named_server, dhcp4=kea_dhcp4)
    yield login(make_app(ctx)), ctx
    from pelagos.services.container import Services

    Services.of(ctx).close()


def rrsets(client, zone: str) -> dict[tuple[str, str], list[str]]:
    page = client.get(f"{V1}/dns/zones/{zone}/records?per_page=500").get_json()
    return {(r["name"], r["rtype"]): r["rdata"] for r in page["items"]}


def test_host_plan_joins_record_ptr_and_reservation(api):
    client, _ctx = api
    body = {
        "hostname": "nas",
        "ip": "192.0.2.42",
        "mac": "AA-BB-CC-DD-EE-42",
        "zone": "example.lan",
        "reservation": True,
        "subnet_id": 1,
        "notes": "storage",
    }
    plan = planned(client.post(f"{V1}/hosts/plan", json=body))
    assert plan["scope"] == "host"
    result = apply(client, plan)
    assert result["state"] == "applied", result
    assert rrsets(client, "example.lan")[("nas.example.lan.", "A")] == ["192.0.2.42"]
    assert rrsets(client, "2.0.192.in-addr.arpa")[("42.2.0.192.in-addr.arpa.", "PTR")] == ["nas.example.lan."]
    reservations = client.get(f"{V1}/dhcp/v4/reservations?subnet_id=1").get_json()["items"]
    assert any(
        r["identifier"] == "aa:bb:cc:dd:ee:42" and r["ip_address"] == "192.0.2.42" for r in reservations
    )

    hosts = client.get(f"{V1}/hosts?q=nas").get_json()
    host = next(h for h in hosts["items"] if h["mac"] == "aa:bb:cc:dd:ee:42")
    assert "192.0.2.42" in host["ips"] and host["reservation"]["hostname"]
    assert {r["rtype"] for r in host["records"]} >= {"A", "PTR"}
    assert client.get(f"{V1}/hosts/{host['key']}").get_json()["key"] == host["key"]

    # One summary for the host plan and one entry per engine plan applied on this node.
    entries = [e for e in client.get(f"{V1}/audit?per_page=50").get_json()["items"] if e["plan_id"]]
    node_entries = [e for e in entries if e["request"].get("entry") == "node"]
    assert {e["engine"] for e in node_entries} == {"bind", "kea4"}
    assert any(e["action"] == "host.apply" and e["request"]["entry"] == "summary" for e in entries)

    rb = client.post(f"{V1}/plans/{plan['id']}/rollback").get_json()
    assert rb["state"] == "rolled_back", rb
    assert ("nas.example.lan.", "A") not in rrsets(client, "example.lan")
    assert ("42.2.0.192.in-addr.arpa.", "PTR") not in rrsets(client, "2.0.192.in-addr.arpa")
    reservations = client.get(f"{V1}/dhcp/v4/reservations?subnet_id=1").get_json()["items"]
    assert not any(r["identifier"] == "aa:bb:cc:dd:ee:42" for r in reservations)


def test_dashboard_reads_both_engines(api):
    client, _ctx = api
    summary = client.get(f"{V1}/dashboard/summary").get_json()
    assert summary["errors"] == {}, summary["errors"]
    assert summary["engines"]["bind"]["running"] and summary["engines"]["kea4"]["running"]
    assert any(p["subnet_id"] == 1 for p in summary["pools"])
    assert any(z["zone"] == "example.lan." for z in summary["zones"])
    assert summary["thresholds"]["alerts_pool_warning_percent"] == 80
