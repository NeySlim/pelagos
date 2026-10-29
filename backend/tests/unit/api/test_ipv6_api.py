# SPDX-License-Identifier: Apache-2.0
"""Observed IPv6 addresses over the API (section 27): hosts with filters, watched prefixes, status,
removal of the 0.2.2 router sources."""

from __future__ import annotations

import json
import time

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import Neighbor

pytestmark = pytest.mark.unit

A = "/api/v1/admin/ipv6"
H = "/api/v1/hosts/ipv6"
MAC = "aa:bb:cc:dd:ee:01"  # pc1 of the fake Kea, A pc1.example.lan.
EUI = "2001:db8::a8bb:ccff:fedd:ee01"
STRANGER = "02:11:22:33:44:55"
DAY = 86400
# A router source as a 0.2.2 node stored it (the connector is gone since 0.2.3).
RETIRED = {"id": "01SRC", "type": "opnsense", "name": "Router", "url": "https://router.example.lan"}


@pytest.fixture
def observed(node_ctx, services):
    now = int(time.time())
    conn = series_mod.connect(node_ctx.paths.series_db)
    obs_store.ensure(conn)
    obs_store.record(conn, [Neighbor(MAC, EUI, "reachable")], "neighbors", None, node_ctx.node.id, now - DAY)
    obs_store.record(conn, [Neighbor(MAC, EUI, "reachable")], "neighbors", None, node_ctx.node.id, now)
    obs_store.record(
        conn, [Neighbor(STRANGER, "2001:db8::99", "reachable")], "neighbors", None, node_ctx.node.id, now
    )
    obs_store.write_status(
        conn,
        [
            {
                "source": "neighbors",
                "source_id": None,
                "node_id": node_ctx.node.id,
                "last_poll": now,
                "error": None,
                "entries": 2,
            }
        ],
    )
    conn.commit()
    yield conn
    conn.close()


def test_hosts_ipv6_rows_proposal_and_filters(role_client, observed):
    c = role_client("viewer")
    page = c.get(H).get_json()
    by_mac = {r["mac"]: r for r in page["items"]}
    pc1 = by_mac[MAC]
    assert pc1["host_key"] == f"mac:{MAC}" and pc1["name"] == "pc1.example.lan."
    assert pc1["ipv4"] == ["192.0.2.100"] and pc1["excepted"] is False and pc1["stale"] == []
    assert pc1["observed"][0]["class"] == "eui64" and pc1["observed"][0]["last_seen"].endswith("Z")
    assert pc1["proposal"]["address"] == EUI and pc1["proposal"]["zone"] == "example.lan."
    assert by_mac[STRANGER]["proposal"] is None and by_mac[STRANGER]["mac_random"] is True
    assert page["meta"]["unavailable"] == []
    assert [r["mac"] for r in c.get(H + "?filter=missing_aaaa").get_json()["items"]] == [MAC]
    assert [r["mac"] for r in c.get(H + "?filter=unknown").get_json()["items"]] == [STRANGER]
    # 0xaa has the locally administered bit set too.
    assert {r["mac"] for r in c.get(H + "?filter=random_mac").get_json()["items"]} == {MAC, STRANGER}
    assert c.get(H + "?filter=stale").get_json()["total"] == 0
    assert [r["mac"] for r in c.get(H + "?zone=example.lan").get_json()["items"]] == [MAC]
    assert c.get(H + "?filter=bogus").status_code == 400


def test_stale_addresses_listed_per_row(role_client, observed, monkeypatch):
    from pelagos.services import ipv6_hosts

    old = "2001:db8:1::a8bb:ccff:fedd:ee01"
    found = [ipv6_hosts.Stale(f"mac:{MAC}", "pc1.example.lan.", "example.lan.", old, MAC, None, EUI)]
    monkeypatch.setattr(ipv6_hosts, "stale_records", lambda *a, **k: found)
    c = role_client("viewer")
    by_mac = {r["mac"]: r for r in c.get(H).get_json()["items"]}
    assert by_mac[MAC]["stale"] == [old] and by_mac[STRANGER]["stale"] == []
    assert [r["stale"] for r in c.get(H + "?filter=stale").get_json()["items"]] == [[old]]


def test_host_exception_flags_the_row(admin, observed):
    r = admin.post(
        "/api/v1/alerts/exceptions",
        json={"kind": "ipv6_missing_aaaa", "key": f"mac:{MAC.upper()}", "comment": "IPv6 by DHCPv6 later"},
    )
    assert r.status_code in (200, 201), r.get_json()
    assert r.get_json()["key"] == f"mac:{MAC}"
    pc1 = next(x for x in admin.get(H).get_json()["items"] if x["mac"] == MAC)
    assert pc1["excepted"] is True
    assert admin.get(H + "?filter=missing_aaaa").get_json()["total"] == 0
    r = admin.post(
        "/api/v1/alerts/exceptions",
        json={"kind": "ipv6_stale_aaaa", "key": "addr:2001:DB8:0:0::1", "comment": "service alias"},
    )
    assert r.get_json()["key"] == "addr:2001:db8::1"
    bad = {"kind": "ipv6_stale_aaaa", "key": "addr:not-an-address", "comment": "x"}
    assert admin.post("/api/v1/alerts/exceptions", json=bad).status_code == 400


def test_prefixes_settings_and_status(admin, node_ctx, observed):
    r = admin.put(A, json={"prefixes": ["2001:db8:5::/64"]})
    assert r.status_code == 200, r.get_json()
    out = r.get_json()
    assert "sources" not in out
    assert out["prefixes"] == ["2001:db8:5::/64"]
    assert {"prefix": "2001:db8:5::/64", "from": "setting"} in out["effective_prefixes"]
    assert out["settings"]["stable_min_days"] == 8
    assert out["status"][0]["source"] == "neighbors" and out["status"][0]["last_poll"].endswith("Z")
    # A GET echoed back changes nothing.
    assert admin.put(A, json=out).get_json()["prefixes"] == ["2001:db8:5::/64"]
    audit = node_ctx.audit_log.query(action="admin.ipv6.replace")[0]
    assert audit[0].request == {"prefixes": ["2001:db8:5::/64"]}


def test_validation_lists_every_error(admin):
    r = admin.put(
        A,
        json={
            "sources": [RETIRED],
            "prefixes": ["192.0.2.0/24", "fe80::/64"],
            "secrets": {"01SRC": {"api_key": "k"}},
            "extra": True,
        },
    )
    assert r.status_code == 400
    assert {e["field"] for e in r.get_json()["errors"]} >= {"sources", "secrets", "prefixes", "extra"}
    assert admin.post(A + "/sources/test", json={"source_id": "01SRC"}).status_code in (404, 405)


def _store_retired(node_ctx) -> None:
    def put(cluster):
        cluster.settings.setdefault("ipv6", {})["sources"] = [RETIRED]
        cluster.settings["ipv6"]["prefixes"] = ["2001:db8:5::/64"]
        for name in ("api_key", "api_secret"):
            key = f"ipv6/source/01SRC/{name}"
            cluster.secrets[key] = node_ctx.secrets.encrypt(key, "s3cret")

    node_ctx.config_store.update_cluster(put, updated_by="node:old")


def test_router_sources_of_0_2_2_are_removed_with_their_secrets(node_ctx):
    from pelagos.services.ipv6_service import retire_router_sources

    _store_retired(node_ctx)
    version = node_ctx.cluster().version
    assert retire_router_sources(node_ctx) is True
    cluster = node_ctx.cluster()
    assert "sources" not in cluster.settings["ipv6"] and cluster.settings["ipv6"]["prefixes"]
    assert not [k for k in cluster.secrets if k.startswith("ipv6/")]
    (entry,) = node_ctx.audit_log.query(action="admin.ipv6.op")[0]
    assert (entry.user, entry.request) == ("system", {"op": "retire_sources", "sources": ["01SRC"]})
    assert "s3cret" not in json.dumps(entry.to_dict())
    # Once done, nothing more is written nor audited.
    assert retire_router_sources(node_ctx) is False
    assert node_ctx.cluster().version == version + 1
    assert len(node_ctx.audit_log.query(action="admin.ipv6.op")[0]) == 1


def test_an_empty_source_list_is_dropped_without_an_audit_entry(node_ctx):
    from pelagos.services.ipv6_service import retire_router_sources

    node_ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("ipv6", {}).__setitem__("sources", []), updated_by="node:old"
    )
    assert retire_router_sources(node_ctx) is True
    assert "sources" not in node_ctx.cluster().settings["ipv6"]
    assert node_ctx.audit_log.query(action="admin.ipv6.op")[0] == []


def test_the_web_start_removes_them(node_paths, node_ctx):
    from pelagos.app import create_app

    _store_retired(node_ctx)
    create_app(node_paths, context=node_ctx, static_dir=node_paths.opt / "none")
    assert "sources" not in node_ctx.cluster().settings["ipv6"]
    assert node_ctx.audit_log.query(action="admin.ipv6.op")[0][0].user == "system"


def test_a_router_source_merged_from_a_0_2_2_peer_is_ignored(admin, node_ctx, observed):
    # A 0.2.2 peer writing after the removal brings the entry back: unused, never shown, gone at next start.
    _store_retired(node_ctx)
    out = admin.get(A).get_json()
    assert "sources" not in out and out["prefixes"] == ["2001:db8:5::/64"]
    assert admin.put(A, json={"prefixes": []}).status_code == 200
    assert node_ctx.cluster().settings["ipv6"]["sources"] == [RETIRED]


def _refusing(fake_registry, zone: str) -> None:
    """A dynamic zone whose transfer named refuses (allow-transfer by address only)."""
    from pelagos.connectors.base import ConnectorDenied
    from pelagos.domain import RRset, Zone, ZoneKind

    dns = fake_registry.dns
    soa = RRset(zone, "SOA", 3600, ["ns1.example.lan. hostmaster.example.lan. 1 3600 900 1209600 300"])
    dns.add_zone(Zone(name=zone, kind=ZoneKind.PRIMARY, dynamic=True), [soa])
    read = dns.read_zone

    def read_zone(name, view=None):
        if name.rstrip(".") + "." == zone:
            raise ConnectorDenied(f"AXFR of {zone} refused: Zone transfer error: REFUSED")
        return read(name, view)

    dns.read_zone = read_zone


def test_a_refused_transfer_is_reported_and_the_rest_listed(role_client, observed, fake_registry):
    _refusing(fake_registry, "refused.lan.")
    c = role_client("viewer")
    r = c.get(H)
    assert r.status_code == 200, r.get_json()
    page = r.get_json()
    assert "refused.lan.: AXFR of refused.lan. refused" in page["meta"]["errors"]["dns.zones"]
    pc1 = next(x for x in page["items"] if x["mac"] == MAC)
    assert pc1["proposal"]["address"] == EUI
    assert [x["mac"] for x in c.get(H + "?filter=missing_aaaa").get_json()["items"]] == [MAC]
    hosts = c.get("/api/v1/hosts")
    assert hosts.status_code == 200 and "dns.zones" in hosts.get_json()["meta"]["errors"]


def test_consistency_pass_skips_on_a_refused_transfer(services, fake_registry):
    assert services.hosts.consistency_pass()["errors"] == {}
    _refusing(fake_registry, "refused.lan.")
    out = services.hosts.consistency_pass()
    assert "refused.lan.: AXFR of refused.lan. refused" in out["errors"]["dns.zones"]
    assert out["found"] == 0 and out["alerts"] == [] and out["by_kind"] == {}


def test_filters_judge_the_zones_the_checks_judge(role_client, observed, fake_registry):
    from pelagos.domain import RRset

    dns = fake_registry.dns
    # pc1's A moves to corp.example., a secondary of an external primary: shown, never judged.
    dns.rrsets["example.lan."].pop(("pc1.example.lan.", "A"))
    dns.rrsets["corp.example."][("pc1.corp.example.", "A")] = RRset(
        "pc1.corp.example.", "A", 300, ["192.0.2.100"]
    )
    c = role_client("viewer")
    pc1 = next(x for x in c.get(H).get_json()["items"] if x["mac"] == MAC)
    assert pc1["proposal"]["zone"] == "corp.example." and pc1["observed"][0]["current"] is True
    assert c.get(H + "?filter=missing_aaaa").get_json()["total"] == 0
    # A zone primary on another node (its cached zone list) is judged.
    from pelagos.services import ipv6_service

    snap = {"engine": "bind", "kind": "zone_list", "payload": [{"name": "corp.example.", "kind": "primary"}]}
    zones = ipv6_service.checked_zones([], [snap])
    assert zones == {"corp.example."}


def test_records_of_an_unjudged_zone_do_not_count(role_client, observed, fake_registry):
    from pelagos.domain import RRset

    # pc1's first A is in corp.example., a secondary: the check proposes from its primary A.
    dns = fake_registry.dns
    dns.zones = {"corp.example.": dns.zones.pop("corp.example."), **dns.zones}
    dns.rrsets["corp.example."][("pc1.corp.example.", "A")] = RRset(
        "pc1.corp.example.", "A", 300, ["192.0.2.100"]
    )
    c = role_client("viewer")
    pc1 = next(x for x in c.get(H).get_json()["items"] if x["mac"] == MAC)
    assert pc1["proposal"]["zone"] == "corp.example."
    assert [x["mac"] for x in c.get(H + "?filter=missing_aaaa").get_json()["items"]] == [MAC]


def test_exception_keys_match_in_any_case(admin, observed, node_ctx):
    from pelagos.domain import new_id

    def add(c):
        c.exceptions.append(
            {"id": new_id(), "kind": "ipv6_missing_aaaa", "key": f"mac:{MAC.upper()}", "comment": "by hand"}
        )

    node_ctx.config_store.update_cluster(add, updated_by="test")
    pc1 = next(x for x in admin.get(H).get_json()["items"] if x["mac"] == MAC)
    assert pc1["excepted"] is True
    dup = {"kind": "ipv6_missing_aaaa", "key": f"mac:{MAC}", "comment": "again"}
    assert admin.post("/api/v1/alerts/exceptions", json=dup).status_code == 409


def test_failing_source_status_gives_failing_since(admin, node_ctx, observed):
    now = int(time.time())
    failing = {"source": "neighbors", "source_id": None, "node_id": node_ctx.node.id, "last_poll": now}
    failing |= {"error": "ip neigh failed", "entries": 0, "failing_since": now - 600}
    obs_store.write_status(observed, [failing])
    observed.commit()
    status = admin.get(A).get_json()["status"][0]
    assert status["error"] == "ip neigh failed"
    assert status["failing_since"].endswith("Z") and status["failing_since"] < status["last_poll"]


def test_mixed_releases_merge_cluster_toml_both_ways(node_ctx, tmp_root):
    from pelagos.core.config_store import ConfigStore
    from pelagos.services.ipv6_service import retire_router_sources

    _store_retired(node_ctx)
    # A 0.2.2 peer holding the same file, sources and secrets included.
    peer_path = tmp_root / "peer-cluster.toml"
    peer_path.write_text(node_ctx.config_store.cluster_path.read_text())
    peer = ConfigStore(tmp_root / "peer.toml", peer_path)
    assert retire_router_sources(node_ctx) is True
    # 0.2.2 -> 0.2.3: the older entries lose to the removal.
    node_ctx.config_store.merge_remote(peer_path.read_text())
    here = node_ctx.cluster()
    assert "sources" not in here.settings["ipv6"] and not [k for k in here.secrets if k.startswith("ipv6/")]
    # 0.2.3 -> 0.2.2: the peer loses them too and loads the merged file.
    assert peer.merge_remote(node_ctx.config_store.cluster_path.read_text()) is True
    there = peer.load_cluster()
    assert "sources" not in there.settings["ipv6"] and not [k for k in there.secrets if k.startswith("ipv6/")]
    assert there.settings["ipv6"]["prefixes"] == ["2001:db8:5::/64"]
    # A source the 0.2.2 peer writes afterwards comes back but is never read nor shown.
    peer.update_cluster(lambda c: c.settings["ipv6"].__setitem__("sources", [RETIRED]), updated_by="node:old")
    assert node_ctx.config_store.merge_remote(peer_path.read_text()) is True
    assert node_ctx.cluster().settings["ipv6"]["sources"] == [RETIRED]
