# SPDX-License-Identifier: Apache-2.0
"""IPv6 observations (section 27): watched prefixes, ipv6_observations, the observer pass."""

from __future__ import annotations

import ipaddress
from types import SimpleNamespace

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.ipv6 import prefixes as px
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.observer import Ipv6Observer, polls_routers
from pelagos.collector.ipv6.source import Neighbor, SourceError

pytestmark = pytest.mark.unit

DAY = 86400
MAC = "bc:24:11:63:b8:06"
REV = "9.9.0.0.8.b.d.0.1.0.0.2.ip6.arpa."  # 2001:db8:99::/48


# Prefixes ------------------------------------------------------------------------------------


def test_reverse_zone_network():
    assert px.reverse_zone_network(REV) == ipaddress.IPv6Network("2001:db8:99::/48")
    assert px.reverse_zone_network("0.0.0.0.9.9.0.0.8.b.d.0.1.0.0.2.ip6.arpa") == ipaddress.IPv6Network(
        "2001:db8:99::/64"
    )
    assert px.reverse_zone_network("2.0.192.in-addr.arpa.") is None
    assert px.reverse_zone_network("ab.8.b.d.0.1.0.0.2.ip6.arpa.") is None


def test_reverse_zone_for_picks_the_longest():
    zones = ["8.b.d.0.1.0.0.2.ip6.arpa.", REV]
    assert px.reverse_zone_for("2001:db8:99::1", zones) == REV
    assert px.reverse_zone_for("2001:db8:1::1", zones) == "8.b.d.0.1.0.0.2.ip6.arpa."
    assert px.reverse_zone_for("2001:db9::1", zones) is None


def test_effective_prefixes_and_ula_rule():
    ula_zone = "d.f.ip6.arpa."  # fd00::/8
    got = px.effective(["2001:db8:5::/64", "bad"], [REV, ula_zone], ["2001:db8:6::/64", "192.0.2.0/24"])
    assert [p.to_dict() for p in got] == [
        {"prefix": "2001:db8:5::/64", "from": "setting"},
        {"prefix": "2001:db8:99::/48", "from": "reverse_zone"},
        {"prefix": "2001:db8:6::/64", "from": "dhcpv6"},
    ]
    with_ula = px.effective(["fd00::/8"], [ula_zone], [])
    assert [p.to_dict() for p in with_ula] == [{"prefix": "fd00::/8", "from": "setting"}]
    assert px.effective([], ["fd99:99::/64"], ["fd99:99::/64"]) == []


def test_watched_drops_link_local_multicast_and_outside():
    watched = px.effective(["2001:db8:99::/48"], [], [])
    assert px.watched("2001:db8:99::1", watched)
    assert not px.watched("fe80::1", watched)
    assert not px.watched("ff02::1", watched)
    assert not px.watched("2001:db8:1::1", watched)
    assert not px.watched("nonsense", watched)


def test_from_snapshots():
    snaps = [
        {
            "engine": "bind",
            "kind": "zone_list",
            "payload": [
                {"name": "example.lan", "kind": "primary"},
                {"name": REV.upper().rstrip("."), "kind": "primary"},
                {"name": "1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", "kind": "forward"},
            ],
        },
        {"engine": "kea6", "kind": "subnets", "payload": [{"subnet": "2001:db8:6::/64", "id": 1}]},
        {"engine": "kea4", "kind": "subnets", "payload": [{"subnet": "192.0.2.0/24"}]},
    ]
    assert px.from_snapshots(snaps) == ([REV], ["2001:db8:6::/64"])


# Store ---------------------------------------------------------------------------------------


@pytest.fixture
def conn(tmp_path):
    c = series_mod.connect(tmp_path / "series.db")
    obs_store.ensure(c)
    yield c
    c.close()


def test_record_keeps_first_seen_and_moves_last_seen(conn):
    n = Neighbor(MAC, "2001:db8:99::1", "reachable")
    obs_store.record(conn, [n], "neighbors", None, "n1", 1000)
    obs_store.record(conn, [Neighbor(MAC, "2001:db8:99::1", "delay")], "neighbors", None, "n1", 2000)
    obs_store.record(conn, [n], "opnsense", "01SRC", "n1", 1500)
    rows = obs_store.observations(conn)
    assert rows == [
        {
            "mac": MAC,
            "address": "2001:db8:99::1",
            "source": "neighbors",
            "source_id": None,
            "node_id": "n1",
            "first_seen": 1000,
            "last_seen": 2000,
            "state": "delay",
        },
        {
            "mac": MAC,
            "address": "2001:db8:99::1",
            "source": "opnsense",
            "source_id": "01SRC",
            "node_id": "n1",
            "first_seen": 1500,
            "last_seen": 1500,
            "state": "reachable",
        },
    ]
    assert [r["source"] for r in obs_store.observations(conn, since=1600)] == ["neighbors"]
    assert obs_store.prune(conn, 1600 + 30 * DAY, 30) == 1


def test_payload_before_the_first_pass(tmp_path):
    path = tmp_path / "series.db"
    series_mod.connect(path).close()
    ro = series_mod.connect(path, readonly=True)
    assert obs_store.payload(ro, "n1") == {"node_id": "n1", "observations": [], "sources": []}
    ro.close()
    assert obs_store.payload(None, "n2")["observations"] == []


# Observer ------------------------------------------------------------------------------------


class FakeSource:
    def __init__(self, kind, found=(), error=None):
        self.kind = kind
        self.found = list(found)
        self.error = error
        self.calls = 0

    def poll(self):
        self.calls += 1
        if self.error:
            raise SourceError(self.error)
        return self.found


def make_ctx(settings, node_id="n1", nodes=("n1", "n2"), modules=None):
    return SimpleNamespace(
        node=SimpleNamespace(id=node_id),
        settings=lambda: settings,
        cluster=lambda: SimpleNamespace(nodes=[SimpleNamespace(id=n) for n in nodes], modules=modules or {}),
        get_secret=lambda name: {"ipv6/source/01SRC/api_key": "k", "ipv6/source/01SRC/api_secret": "s"}.get(
            name
        ),
    )


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def observer(tmp_path, settings, neighbors, routers=None, **ctx_kw):
    store = series_mod.SeriesStore(series_mod.connect(tmp_path / "series.db"))
    clock = Clock(1_800_000_000)
    made = []

    def factory(source, ctx):
        made.append((source["id"], ctx.get_secret(f"ipv6/source/{source['id']}/api_key")))
        return routers

    obs = Ipv6Observer(
        make_ctx(settings, **ctx_kw), store, clock, neighbors=neighbors, router_factory=factory
    )
    return obs, clock, made


SETTINGS = {
    "ipv6": {
        "prefixes": ["2001:db8:99::/64"],
        "sources": [
            {
                "id": "01SRC",
                "type": "opnsense",
                "name": "fw",
                "url": "https://fw.example.lan",
                "verify_tls": True,
                "ca_pem": None,
                "enabled": True,
            }
        ],
    }
}
SEEN = [
    Neighbor(MAC, "2001:db8:99:0:be24:11ff:fe63:b806", "reachable"),
    Neighbor(MAC, "fe80::be24:11ff:fe63:b806", "reachable"),
    Neighbor(MAC, "2001:db8:1::5", "reachable"),
]


def test_service_node_reads_neighbors_and_router(tmp_path):
    neigh = FakeSource("neighbors", SEEN)
    router = FakeSource("opnsense", [Neighbor("bc:24:11:00:00:02", "2001:db8:99::2")])
    obs, clock, made = observer(tmp_path, SETTINGS, neigh, router)
    status = obs.tick()
    assert made == [("01SRC", "k")]
    assert [(s["source"], s["source_id"], s["entries"], s["error"]) for s in status] == [
        ("neighbors", None, 3, None),
        ("opnsense", "01SRC", 1, None),
    ]
    rows = obs_store.observations(obs.conn)
    assert {(r["address"], r["source"]) for r in rows} == {
        ("2001:db8:99:0:be24:11ff:fe63:b806", "neighbors"),
        ("2001:db8:99::2", "opnsense"),
    }
    # Within poll_seconds the router keeps its last status; neighbors are read every pass.
    clock.t += 60
    status = obs.tick()
    assert neigh.calls == 2 and router.calls == 1
    by_source = {x["source"]: x for x in status}
    assert by_source["opnsense"]["last_poll"] == clock.t - 60
    assert by_source["neighbors"]["last_poll"] == clock.t
    clock.t += 300
    obs.tick()
    assert router.calls == 2
    assert {x["source_id"] for x in obs_store.payload(obs.conn, "n1")["sources"]} == {None, "01SRC"}


def test_other_node_never_polls_the_router(tmp_path):
    router = FakeSource("opnsense")
    obs, _, made = observer(tmp_path, SETTINGS, FakeSource("neighbors", SEEN), router, node_id="n2")
    status = obs.tick()
    assert made == [] and router.calls == 0
    assert [s["source"] for s in status] == ["neighbors"]


def test_takeover_when_the_first_node_is_offline_or_too_old(tmp_path):
    obs, _, _ = observer(tmp_path, SETTINGS, FakeSource("neighbors"), FakeSource("opnsense"), node_id="n2")
    obs.offline = lambda: ["n1"]
    assert obs.service_node(SETTINGS) == "n2"
    obs.offline = list
    obs.versions = lambda: {"n1": "0.2.1"}
    assert obs.service_node(SETTINGS) == "n2"
    obs.versions = lambda: {"n1": "0.2.2"}
    assert obs.service_node(SETTINGS) == "n1"
    assert polls_routers(None) and polls_routers("garbage") and not polls_routers("0.1.3")


def test_failures_are_statuses_and_neighbors_can_be_disabled(tmp_path):
    settings = {"ipv6": dict(SETTINGS["ipv6"], neighbors_enabled=False)}
    neigh = FakeSource("neighbors", SEEN)
    obs, _, _ = observer(
        tmp_path, settings, neigh, FakeSource("opnsense", error="API key refused (HTTP 401)")
    )
    status = obs.tick()
    assert neigh.calls == 0
    assert status == [
        {
            "source": "opnsense",
            "source_id": "01SRC",
            "node_id": "n1",
            "last_poll": 1_800_000_000,
            "error": "API key refused (HTTP 401)",
            "entries": 0,
        }
    ]


def test_dhcpv6_leases_only_with_the_module_and_every_poll_seconds(tmp_path):
    from pelagos.domain import Family, Lease

    walks = []

    def leases():
        walks.append(1)
        return [
            Lease(
                ip_address="2001:db8:99::10",
                subnet_id=1,
                family=Family.V6,
                hw_address=MAC,
                lease_type="IA_NA",
                prefix_len=128,
            )
        ]

    store = series_mod.SeriesStore(series_mod.connect(tmp_path / "series.db"))
    clock = Clock(1_800_000_000)
    settings = {"ipv6": {"prefixes": ["2001:db8:99::/64"]}}
    obs = Ipv6Observer(
        make_ctx(settings, modules={"dhcpv6": True}), store, clock, leases, neighbors=FakeSource("neighbors")
    )
    obs.tick()
    clock.t += 60
    obs.tick()
    assert len(walks) == 1
    assert [r["source"] for r in obs_store.observations(obs.conn)] == ["dhcpv6"]
    off = Ipv6Observer(make_ctx(settings), store, clock, leases, neighbors=FakeSource("neighbors"))
    clock.t += 600
    off.tick()
    assert len(walks) == 1


def test_retention_prunes_old_rows(tmp_path):
    settings = {"ipv6": {"prefixes": ["2001:db8:99::/64"]}, "retention": {"ipv6_observation_days": 2}}
    neigh = FakeSource("neighbors", SEEN[:1])
    obs, clock, _ = observer(tmp_path, settings, neigh)
    obs.tick()
    neigh.found = []
    clock.t += 3 * DAY
    obs.tick()
    assert obs_store.observations(obs.conn) == []


def test_reverse_zone_snapshot_makes_a_watched_prefix(tmp_path):
    obs, _, _ = observer(tmp_path, {}, FakeSource("neighbors", SEEN))
    obs.store.write_snapshot("n2", "bind", "zone_list", 1, [{"name": REV.rstrip("."), "kind": "primary"}])
    assert [p.to_dict() for p in obs.effective_prefixes({})] == [
        {"prefix": "2001:db8:99::/48", "from": "reverse_zone"}
    ]
    obs.tick()
    assert [r["address"] for r in obs_store.observations(obs.conn)] == ["2001:db8:99:0:be24:11ff:fe63:b806"]


def test_stale_entries_never_move_last_seen(conn):
    obs_store.record(conn, [Neighbor(MAC, "2001:db8:99::1", "reachable")], "neighbors", None, "n1", 1000)
    obs_store.record(conn, [Neighbor(MAC, "2001:db8:99::1", "stale")], "neighbors", None, "n1", 9000)
    obs_store.record(conn, [Neighbor(MAC, "2001:db8:99::2", "stale")], "neighbors", None, "n1", 9000)
    got = {r["address"]: (r["first_seen"], r["last_seen"], r["state"]) for r in obs_store.observations(conn)}
    assert got == {"2001:db8:99::1": (1000, 1000, "stale"), "2001:db8:99::2": (9000, 9000, "stale")}


def test_unexpected_errors_are_source_statuses(tmp_path):
    class Broken:
        kind = "neighbors"

        def poll(self):
            raise ValueError("boom")

    store = series_mod.SeriesStore(series_mod.connect(tmp_path / "series.db"))

    def factory(source, ctx):
        raise ValueError("Port out of range 0-65535")

    obs = Ipv6Observer(
        make_ctx(SETTINGS), store, Clock(1_800_000_000), neighbors=Broken(), router_factory=factory
    )
    status = obs.tick()
    assert {s["source"]: s["error"] for s in status} == {
        "opnsense": "invalid source: Port out of range 0-65535",
        "neighbors": "unexpected error: boom",
    }
