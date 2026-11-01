# SPDX-License-Identifier: Apache-2.0
"""IPv4 neighbor source and table (section 27, IPv4 neighbors and discovery)."""

from __future__ import annotations

import json
import sqlite3

import pytest

from pelagos.collector import neighbors as generic
from pelagos.collector.ipv6 import neighbors as legacy
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import Neighbor, SourceError

pytestmark = pytest.mark.unit

# `ip -j -4 neigh show` on a Debian 13 node (iproute2 6.15), addresses rewritten to documentation ranges.
IP_4_NEIGH = [
    {"dst": "192.0.2.1", "dev": "eth0", "lladdr": "00:00:0C:9F:F0:01", "state": ["REACHABLE"]},
    {"dst": "192.0.2.31", "dev": "eth0", "lladdr": "b8:27:eb:5a:1:22", "state": ["STALE"]},
    {"dst": "192.0.2.40", "dev": "eth0", "state": ["FAILED"]},
    {"dst": "192.0.2.41", "dev": "eth0", "lladdr": "52:54:00:12:34:56", "state": ["INCOMPLETE"]},
    {"dst": "192.0.2.42", "dev": "eth0", "lladdr": "52:54:00:12:34:57", "state": ["DELAY", "PROBE"]},
    {"dst": "224.0.0.251", "dev": "eth0", "lladdr": "01:00:5e:00:00:fb", "state": ["NOARP"]},
    {"dst": "239.255.255.250", "dev": "eth0", "lladdr": "01:00:5e:7f:ff:fa", "state": ["PERMANENT"]},
    {"dst": "169.254.10.2", "dev": "eth0", "lladdr": "52:54:00:aa:bb:cc", "state": ["REACHABLE"]},
    {"dst": "0.0.0.0", "dev": "eth0", "lladdr": "52:54:00:aa:bb:cd", "state": ["REACHABLE"]},  # noqa: S104
    {"dst": "192.0.2.43", "dev": "eth0", "lladdr": "00:00:00:00:00:00", "state": ["REACHABLE"]},
    {"dst": "2001:db8::1", "dev": "eth0", "lladdr": "52:54:00:aa:bb:ce", "state": ["REACHABLE"]},
]


def test_parse_ip_4_neigh_keeps_reachable_and_stale_entries():
    found = generic.parse(json.dumps(IP_4_NEIGH), 4)
    assert found == [
        Neighbor("00:00:0c:9f:f0:01", "192.0.2.1", "reachable"),
        Neighbor("b8:27:eb:5a:01:22", "192.0.2.31", "stale"),
        Neighbor("52:54:00:12:34:57", "192.0.2.42", "delay"),
    ]
    with pytest.raises(SourceError):
        generic.parse("{", 4)


def test_source_asks_ip_for_the_family():
    asked = []

    def runner(args):
        asked.append(args)
        return json.dumps(IP_4_NEIGH[:1])

    assert generic.NeighborsSource(runner, family=4).poll() == [
        Neighbor("00:00:0c:9f:f0:01", "192.0.2.1", "reachable")
    ]
    assert asked == [["-j", "-4", "neigh", "show"]]
    assert generic.NeighborsSource(lambda a: "[]").poll() == []


def test_ipv6_neighbors_module_is_the_generic_one():
    # Patching run_ip under the former name (the collector tests do) patches the source itself.
    assert legacy is generic
    assert legacy.NeighborsSource is generic.NeighborsSource


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    obs_store.ensure_neighbors(c)
    obs_store.ensure_neighbors(c)  # idempotent: created in place in any cache
    yield c
    c.close()


def test_record_moves_last_seen_but_not_for_stale(conn):
    mac, ip = "b8:27:eb:5a:01:22", "192.0.2.31"
    obs_store.record_neighbors(conn, [Neighbor(mac, ip, "reachable")], 4, "n1", 1000)
    obs_store.record_neighbors(conn, [Neighbor(mac, ip, "reachable")], 4, "n1", 1300)
    obs_store.record_neighbors(conn, [Neighbor(mac, ip, "stale")], 4, "n1", 1600)
    [row] = obs_store.neighbor_rows(conn)
    assert row == {
        "family": 4,
        "mac": mac,
        "address": ip,
        "node_id": "n1",
        "first_seen": 1000,
        "last_seen": 1300,
        "state": "stale",
    }
    assert obs_store.neighbor_rows(conn, since=1301) == []
    indexes = {r[1] for r in conn.execute("PRAGMA index_list(neighbor_observations)")}
    assert "neighbor_observations_mac" in indexes


def test_prune_and_cap(conn, monkeypatch):
    obs_store.record_neighbors(conn, [Neighbor("52:54:00:00:00:01", "192.0.2.5")], 4, "n1", 0)
    obs_store.record_neighbors(conn, [Neighbor("52:54:00:00:00:02", "192.0.2.6")], 4, "n1", 40 * 86400)
    assert obs_store.prune_neighbors(conn, 40 * 86400, 30) == 1
    monkeypatch.setattr(obs_store, "NEIGHBORS_MAX", 2)
    many = [Neighbor(f"52:54:00:00:01:{i:02x}", f"192.0.2.{10 + i}") for i in range(5)]
    assert obs_store.record_neighbors(conn, many, 4, "n1", 41 * 86400) == 2


def test_payload_before_and_after_the_first_pass(conn):
    empty = {"node_id": "n1", "neighbors": [], "status": None, "truncated": False}
    assert obs_store.neighbor_payload(None, "n1") == empty
    bare = sqlite3.connect(":memory:")
    bare.row_factory = sqlite3.Row
    assert obs_store.neighbor_payload(bare, "n1") == empty
    obs_store.write_neighbor_status(conn, {"node_id": "n1", "last_poll": 5, "error": None})
    obs_store.record_neighbors(conn, [Neighbor("52:54:00:00:00:01", "192.0.2.5")], 4, "n1", 5)
    got = obs_store.neighbor_payload(conn, "n1")
    assert got["status"]["last_poll"] == 5 and len(got["neighbors"]) == 1


def test_payload_is_bounded_latest_first(conn, monkeypatch):
    monkeypatch.setattr(obs_store, "ANSWER_MAX", 2)
    for i in range(4):
        obs_store.record_neighbors(
            conn, [Neighbor(f"52:54:00:00:00:0{i}", f"192.0.2.{i + 1}")], 4, "n1", 100 + i
        )
    got = obs_store.neighbor_payload(conn, "n1")
    assert got["truncated"] is True and [n["last_seen"] for n in got["neighbors"]] == [103, 102]
    assert obs_store.neighbor_payload(conn, "n1", since=103)["truncated"] is False
