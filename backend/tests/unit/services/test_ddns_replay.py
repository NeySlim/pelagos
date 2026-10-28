# SPDX-License-Identifier: Apache-2.0
"""DDNS catch-up: outage window from D2 counters, lease selection, window rules, the replay plan."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.collector.series import SeriesStore, connect
from pelagos.connectors.base import ConnectorDenied
from pelagos.domain import AlertKind, Engine, Family, Lease, LeaseState, PlanScope, PlanState, RRset
from pelagos.services import ddns_replay as dr
from pelagos.services.errors import Conflict, EngineUnavailable, ValidationError

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 28, 8, 0, tzinfo=UTC)


def lease(ip: str, host: str | None = "pc1.example.lan.", minutes: int = 10, **kw: Any) -> Lease:
    family = Family.V6 if ":" in ip else Family.V4
    return Lease(
        ip_address=ip,
        subnet_id=1,
        family=family,
        hostname=host,
        cltt=T0 + timedelta(minutes=minutes),
        fqdn_fwd=kw.pop("fwd", True),
        fqdn_rev=kw.pop("rev", True),
        **kw,
    )


def soa(zone: str) -> RRset:
    return RRset(
        name=zone, rtype="SOA", ttl=3600, rdata=["ns1.example.lan. h.example.lan. 1 3600 900 1209600 300"]
    )


FORWARD = [
    soa("example.lan."),
    RRset(name="pc1.example.lan.", rtype="A", ttl=300, rdata=["192.0.2.101"]),
    RRset(name="pc2.example.lan.", rtype="A", ttl=300, rdata=["192.0.2.99"]),
]
REVERSE = [
    soa("2.0.192.in-addr.arpa."),
    RRset(name="101.2.0.192.in-addr.arpa.", rtype="PTR", ttl=300, rdata=["pc1.example.lan."]),
]


# Outage window -----------------------------------------------------------------------------------


def totals(sent=0, ok=0, timeout=0, error=0) -> dict[str, int]:
    return {"update-sent": sent, "update-success": ok, "update-timeout": timeout, "update-error": error}


def test_window_opens_on_timeouts_and_closes_on_success():
    s = dr.track_outage(None, None, totals(5, 5), 100)
    s = dr.track_outage(s, totals(5, 5), totals(5, 5), 160)
    assert s["open"] is None and s["good_at"] == 160
    s = dr.track_outage(s, totals(5, 5), totals(7, 5, timeout=2), 220)
    assert s["open"] == {"since": 160, "cause": "updates", "failed_at": 220}
    # No traffic: still open (a quiet minute proves nothing).
    s = dr.track_outage(s, totals(7, 5, timeout=2), totals(7, 5, timeout=2), 280)
    assert s["open"] is not None
    # Successes and failures in the same minute: still open.
    s = dr.track_outage(s, totals(7, 5, timeout=2), totals(9, 6, timeout=3), 340)
    assert s["open"] is not None
    s = dr.track_outage(s, totals(9, 6, timeout=3), totals(10, 7, timeout=3), 400)
    assert s["open"] is None and s["last"] == {"from": 160, "to": 400} and s["good_at"] == 400


def test_d2_down_opens_and_a_clean_restart_closes():
    s = dr.track_outage(None, None, totals(), 100)
    s = dr.track_outage(s, totals(), totals(), 160)
    s = dr.track_outage(s, totals(), None, 220)
    s = dr.track_outage(s, totals(), None, 280)
    assert s["open"] == {"since": 160, "cause": "d2_down", "failed_at": 280}
    # Counters restart from zero: no failure, the window closes.
    s = dr.track_outage(s, totals(9, 9), totals(), 340)
    assert s["open"] is None and s["last"] == {"from": 160, "to": 340}


def test_restarted_counters_count_from_zero():
    s = dr.track_outage(
        {"open": None, "last": None, "good_at": 100}, totals(50, 40, timeout=10), totals(2, 0, 2), 160
    )
    assert s["open"] == {"since": 100, "cause": "updates", "failed_at": 160}


def test_outage_windows_merge_nodes():
    a = {"last": {"from": 1000, "to": 2000}, "open": None}
    b = {"last": {"from": 500, "to": 1500}, "open": None}
    c = {"last": {"from": 10, "to": 20}, "open": None}
    closed, since = dr.outage_windows([a, b, c, {"junk": 1}, None])  # type: ignore[list-item]
    assert closed == (datetime.fromtimestamp(500, UTC), datetime.fromtimestamp(2000, UTC)) and since is None
    _closed, since = dr.outage_windows([a, {"open": {"since": 3000}}])
    assert since == datetime.fromtimestamp(3000, UTC)


# Selection ---------------------------------------------------------------------------------------


def test_select_missing_and_differing_records():
    leases = [
        lease("192.0.2.101", "pc1.example.lan."),  # A and PTR right
        lease("192.0.2.102", "pc2.example.lan.", minutes=5),  # A differs, PTR missing
        lease("192.0.2.103", "pc3.example.lan.", rev=False),  # A missing, PTR not asked
        lease("192.0.2.104", "pc4.other.lan."),  # forward zone not read: PTR only
        lease("192.0.2.105", None),  # no name
        lease("192.0.2.106", "pc6.example.lan.", fwd=False, rev=False),  # no flag
        lease("192.0.2.107", "pc7.example.lan.", minutes=-30),  # before the window
        lease("192.0.2.108", "pc8.example.lan.", state=LeaseState.EXPIRED_RECLAIMED),
    ]
    found = dr.select(leases, FORWARD, REVERSE, T0, T0 + timedelta(hours=1))
    assert [c.lease.ip_address for c in found] == ["192.0.2.102", "192.0.2.103", "192.0.2.104"]
    by_ip = {c.lease.ip_address: c.problems for c in found}
    assert by_ip["192.0.2.102"] == [
        {"rtype": "A", "name": "pc2.example.lan.", "found": ["192.0.2.99"]},
        {"rtype": "PTR", "name": "102.2.0.192.in-addr.arpa.", "found": []},
    ]
    assert [p["rtype"] for p in by_ip["192.0.2.103"]] == ["A"]
    assert [p["rtype"] for p in by_ip["192.0.2.104"]] == ["PTR"]


def test_select_v6_and_prefixes():
    fwd = [soa("example.lan.")]
    leases = [
        lease("2001:db8::10", "pc1.example.lan.", rev=False),
        lease("2001:db8:1::", "pc1.example.lan.", lease_type="IA_PD", rev=False),
    ]
    found = dr.select(leases, fwd, [], T0, T0 + timedelta(hours=1))
    assert [(c.lease.ip_address, c.problems[0]["rtype"]) for c in found] == [("2001:db8::10", "AAAA")]


def test_zones_needed_longest_match_per_view():
    zones = [
        {"name": "lan.", "view": "_default"},
        {"name": "example.lan.", "view": "_default"},
        {"name": "example.lan.", "view": "inside"},
        {"name": "2.0.192.in-addr.arpa.", "view": "_default"},
        {"name": "unrelated.test.", "view": "_default"},
    ]
    picked = dr.zones_needed([lease("192.0.2.5", "pc.example.lan.")], zones)
    assert [(z["name"], z["view"]) for z in picked] == [
        ("2.0.192.in-addr.arpa.", "_default"),
        ("example.lan.", "_default"),
        ("example.lan.", "inside"),
    ]


def test_replay_alert():
    window = (T0, T0 + timedelta(hours=1))
    found = dr.select([lease("192.0.2.103", "pc3.example.lan.")], FORWARD, REVERSE, *window)
    alert = dr.replay_alert(window, found)
    assert alert.kind is AlertKind.DDNS_REPLAY and alert.node_id is None and alert.subject == "ddns:replay"
    assert alert.details["count"] == 1 and alert.details["from"].startswith("2026-10-28T08:00")
    assert dr.replay_alert(window, []) is None and dr.replay_alert(None, found) is None


# Service -----------------------------------------------------------------------------------------


@dataclass
class FakeDhcp:
    family: Family
    rows: dict[str, list[Lease]]
    local: Any = True
    peer_ids: list[str] = field(default_factory=list)
    broken: set[str] = field(default_factory=set)

    @property
    def engine(self) -> Engine:
        return self.family.kea_engine

    @property
    def peers(self) -> Any:
        return SimpleNamespace(peers_running=lambda e: [SimpleNamespace(id=p, name=p) for p in self.peer_ids])

    def all_leases(self, node_id: str | None = None):
        if node_id in self.broken:
            raise EngineUnavailable(f"node {node_id} is not reachable")
        return [Lease.from_dict(x.to_dict()) for x in self.rows.get(node_id, [])], node_id, False


class FakeDns:
    def __init__(self, records: dict[str, list[RRset]]) -> None:
        self.data = records
        self.read: list[str] = []

    def zones(self):
        return [{"zone": {"name": z, "view": "_default", "kind": "primary"}} for z in self.data]

    def records(self, zone, view):
        self.read.append(zone)
        if self.data[zone] is None:
            raise ConnectorDenied(f"AXFR of {zone} refused")
        return self.data[zone], "n1"


class FakePlans:
    def __init__(self) -> None:
        self.composites: list[tuple[Any, list[Any]]] = []

    def register_composite(self, plan, parts):
        self.composites.append((plan, parts))


def make(node_ctx, dhcp: list[FakeDhcp], store: Any = None, now: datetime | None = None):
    dns = FakeDns({"example.lan.": FORWARD, "2.0.192.in-addr.arpa.": REVERSE, "unrelated.test.": []})
    plans = FakePlans()
    svc = dr.DdnsReplayService(
        node_ctx, dns, lambda: dhcp, plans, lambda: store, clock=lambda: now or T0 + timedelta(hours=2)
    )
    return svc, dns, plans


def test_window_rules(node_ctx, tmp_root):
    svc, _dns, _plans = make(node_ctx, [])
    w = svc.window({})
    assert w.source == "default" and w.end - w.start == timedelta(hours=72)
    w = svc.window({"from": "2026-10-28T08:00:00Z"})
    assert w.source == "request" and w.end == T0 + timedelta(hours=2)
    with pytest.raises(ValidationError):
        svc.window({"from": "2026-10-28T09:00:00Z", "to": "2026-10-28T08:00:00Z"})
    with pytest.raises(ValidationError):
        svc.window({"from": "2026-10-01T00:00:00Z", "to": "2026-10-28T08:00:00Z"})
    with pytest.raises(ValidationError):
        svc.window({"from": "yesterday"})
    store = SeriesStore(connect(tmp_root / "s.sqlite"))
    ts = int(T0.timestamp())
    store.write_snapshot("n2", "d2", dr.OUTAGE_KIND, ts, {"last": {"from": ts, "to": ts + 600}, "open": None})
    svc.store = lambda: store
    w = svc.window({})
    assert (w.source, w.start, w.end) == ("outage", T0, T0 + timedelta(minutes=10))
    store.write_snapshot("n1", "d2", dr.OUTAGE_KIND, ts, {"open": {"since": ts + 3000}, "last": None})
    w = svc.window({})
    assert w.source == "open" and w.start == T0 + timedelta(seconds=3000)


def test_plan_one_node(node_ctx):
    me = node_ctx.node.id
    rows = {
        me: [
            lease("192.0.2.101"),
            lease("192.0.2.102", "pc2.example.lan."),
            lease("192.0.2.103", "pc3.example.lan."),
        ]
    }
    svc, dns, plans = make(node_ctx, [FakeDhcp(Family.V4, rows)])
    plan = svc.plan({"from": "2026-10-28T08:00:00Z", "limit": 1}, "admin")
    assert plan.scope is PlanScope.DHCP_LEASE and plan.engine is Engine.KEA4 and plan.requires_confirmation
    assert plan.state is PlanState.VALIDATED and plan.target_node_ids == [me]
    assert [c.target for c in plan.changes] == ["resend/192.0.2.102"]
    assert plan.summary_message["key"] == "plan.ddns.replay" and plan.summary_message["params"]["count"] == 1
    assert any("1 more leases qualify" in v.output for v in plan.validations)
    assert "~192.0.2.102 pc2.example.lan. A differs (192.0.2.99), PTR missing" in plan.diff
    assert "unrelated.test." not in dns.read and plans.composites == []
    assert node_ctx.plan_store.get(plan.id) is not None


def test_plan_peer_and_families_make_a_composite(node_ctx):
    v4 = FakeDhcp(
        Family.V4,
        {"n2": [lease("192.0.2.103", "pc3.example.lan.")], "n3": []},
        local=None,
        peer_ids=["n2", "n3"],
        broken={"n3"},
    )
    v6 = FakeDhcp(Family.V6, {node_ctx.node.id: [lease("2001:db8::7", "pc7.example.lan.", rev=False)]})
    svc, _dns, plans = make(node_ctx, [v4, v6])
    plan = svc.plan({"from": "2026-10-28T08:00:00Z"}, "admin")
    ((composite, parts),) = plans.composites
    assert composite is plan and [p.engine for p in parts] == [Engine.KEA4, Engine.KEA6]
    assert parts[0].target_node_ids == ["n2"] and parts[1].target_node_ids == [node_ctx.node.id]
    assert all(p.requires_confirmation for p in parts)
    assert any("leases of n3 not read" in v.output and not v.ok for v in plan.validations)
    assert svc.plan({"from": "2026-10-28T08:00:00Z", "family": "v6"}, "admin").engine is Engine.KEA6


def test_plan_refuses_without_lease_cmds(node_ctx, tmp_root):
    me = node_ctx.node.id
    store = SeriesStore(connect(tmp_root / "s.sqlite"))
    store.write_snapshot(me, "kea4", "capabilities", 1, {"running": True, "lease_cmds": False})
    svc, _dns, _plans = make(
        node_ctx, [FakeDhcp(Family.V4, {me: [lease("192.0.2.103", "pc3.example.lan.")]})], store
    )
    plan = svc.plan({"from": "2026-10-28T08:00:00Z"}, "admin")
    assert plan.state is PlanState.FAILED and "lease_cmds" in plan.error


def test_plan_conflict_and_bad_body(node_ctx):
    me = node_ctx.node.id
    svc, _dns, _plans = make(node_ctx, [FakeDhcp(Family.V4, {me: [lease("192.0.2.101")]})])
    with pytest.raises(Conflict):
        svc.plan({"from": "2026-10-28T08:00:00Z"}, "admin")
    with pytest.raises(ValidationError):
        svc.plan({"limit": 0}, "admin")
    with pytest.raises(ValidationError):
        svc.plan({"family": "v5"}, "admin")


def test_unreadable_zone_is_not_judged_and_named_in_the_conflict(node_ctx):
    me = node_ctx.node.id
    svc, dns, _plans = make(node_ctx, [FakeDhcp(Family.V4, {me: [lease("192.0.2.102", "pc2.example.lan.")]})])
    dns.data["2.0.192.in-addr.arpa."] = None
    plan = svc.plan({"from": "2026-10-28T08:00:00Z"}, "admin")
    assert "A differs" in plan.diff and "PTR" not in plan.diff
    assert any("AXFR of 2.0.192.in-addr.arpa. refused" in v.output and not v.ok for v in plan.validations)
    dns.data["example.lan."] = None
    with pytest.raises(Conflict, match=r"records not checked, .*example\.lan\.: AXFR of example\.lan\."):
        svc.plan({"from": "2026-10-28T08:00:00Z"}, "admin")


def test_window_closes_after_a_quiet_period():
    s = dr.track_outage({"open": None, "last": None, "good_at": 100}, totals(), totals(1, 0, 1), 160)
    s = dr.track_outage(s, totals(1, 0, 1), totals(1, 0, 1), 160 + dr.QUIET_CLOSE_SECONDS - 1)
    assert s["open"] is not None
    s = dr.track_outage(s, totals(1, 0, 1), totals(1, 0, 1), 160 + dr.QUIET_CLOSE_SECONDS)
    assert s["open"] is None and s["last"] == {"from": 100, "to": 160 + dr.QUIET_CLOSE_SECONDS}


def test_success_after_the_last_failure_closes_in_the_same_poll():
    s = dr.track_outage({"open": None, "last": None, "good_at": 100}, totals(), totals(1, 0, 1), 160)
    stamps = {"update-success": "2026-10-28 11:17:23.59", "update-timeout": "2026-10-28 11:17:17.14"}
    s2 = dr.track_outage(s, totals(1, 0, 1), totals(4, 1, 3), 170, stamps=stamps)
    assert s2["open"] is None and s2["last"] == {"from": 100, "to": 170}
    stamps["update-timeout"] = "2026-10-28 11:17:30.00"
    assert dr.track_outage(s, totals(1, 0, 1), totals(4, 1, 3), 170, stamps=stamps)["open"] is not None
    raw = {"update-success": [[5, "2026-10-28 11:17:23.59"]], "update-error": [[0, "2026-10-28 09:27:27.06"]]}
    assert dr.sample_stamps(raw) == {
        "update-success": "2026-10-28 11:17:23.59",
        "update-error": "2026-10-28 09:27:27.06",
    }
