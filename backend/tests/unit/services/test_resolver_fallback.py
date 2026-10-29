# SPDX-License-Identifier: Apache-2.0
"""Forwarder fallback and return (section 25, batch R3) on two nodes running BIND: the composite
plans, `resolver.fallback` in cluster.toml, the extension, each collector's automatic return, the
health aggregation and `return_ready`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.resolver import node_health, probes_healthy_since
from pelagos.domain import NodeApplyResult, NodeModules, Peer, Plan, PlanScope, PlanState
from pelagos.services import resolver_fallback as rf
from pelagos.services.dns_service import DnsService, parse_change
from pelagos.services.errors import Conflict, EngineUnavailable, NotFound, ValidationError
from pelagos.services.plan_service import PlanService
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import FakeDnsBackend, fake_context

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
N2 = "N2"


class Gateway:
    """The PeerGateway calls the fallback uses, served by the peers' fake backends."""

    def __init__(self, ctx: Any, backends: dict[str, FakeDnsBackend]) -> None:
        self.ctx = ctx
        self.backends = backends
        self.offline: set[str] = set()
        self.health: dict[str, Any] = {}

    def peer(self, node_id: str) -> Peer | None:
        return next((n for n in self.ctx.cluster().nodes if n.id == node_id), None)

    def peers(self) -> list[Peer]:
        return [n for n in self.ctx.cluster().nodes if n.id != self.ctx.node.id]

    def snapshot(self, peer: Peer, engine: Any, kind: str = "summary") -> dict[str, Any] | None:
        if peer.id in self.offline:
            return None
        return {"config": self.backends[peer.id].read_config().to_dict()}

    def build_plan(self, peer: Peer, name: str, body: dict[str, Any]) -> Plan:
        assert name == "dns.config.plan"
        changes = [parse_change(c, "c") for c in body["changes"]]
        plan = Plan.from_dict(
            self.backends[peer.id].plan_config_change(changes, body["created_by"]).to_dict()
        )
        plan.target_node_ids = [peer.id]
        return plan

    def apply_plan(self, peer: Peer, plan: Plan) -> NodeApplyResult:
        return self.backends[peer.id].apply(plan)

    def rollback_plan(self, peer: Peer, plan: Plan) -> NodeApplyResult:
        return self.backends[peer.id].rollback(plan)

    def preflight_plan(self, peer: Peer, plan: Plan) -> str | None:
        return None

    def action(self, peer: Peer, name: str, body: dict[str, Any], timeout: float | None = None) -> Any:
        assert name == rf.PEER_HEALTH and timeout == rf.HEALTH_TIMEOUT
        if peer.id in self.offline:
            raise EngineUnavailable(f"node {peer.name} is offline")
        return self.health[peer.id]


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> float:
        return self.now.timestamp()


@pytest.fixture
def two(node_ctx):
    def add(cfg) -> None:
        cfg.nodes.append(
            Peer(
                id=N2,
                name="ns2",
                url="https://ns2.example.lan:8444",
                cert_fingerprint="sha256:00",
                modules=NodeModules(bind=True),
            )
        )

    node_ctx.config_store.update_cluster(add, updated_by="test")
    n1 = node_ctx.node.id
    local = FakeDnsBackend(fake_context(n1, "bind", node_ctx.paths.backups_dir / "b1"))
    remote = FakeDnsBackend(fake_context(N2, "bind", node_ctx.paths.backups_dir / "b2"))
    remote.options.pop("forward")  # ns2 recursed directly, without forwarders
    remote.options.pop("forwarders")
    gateway = Gateway(node_ctx, {N2: remote})
    registry = ConnectorRegistry(dns=local)
    plans = PlanService(node_ctx, registry, gateway)
    plans.cluster_parts[PlanScope.DNS_RESOLVER] = rf.FallbackWriter(node_ctx, clock := Clock())
    dns = DnsService(node_ctx, local, gateway)
    service = rf.ResolverFallbackService(node_ctx, dns, gateway, plans, clock=clock)
    return {
        "ctx": node_ctx, "n1": n1, "local": local, "remote": remote, "gateway": gateway,
        "plans": plans, "service": service, "clock": clock,
    }  # fmt: skip


def audit(ctx, action: str) -> list[Any]:
    """Entries of one action prefix, oldest first."""
    entries, _ = ctx.audit_log.query(action=action, per_page=200)
    return sorted(entries, key=lambda e: e.id)


def fallback(ctx) -> dict[str, Any] | None:
    return rf.read_fallback(ctx.settings())


def apply(t, plan: Plan) -> Any:
    return t["plans"].apply(plan, "alice", confirm=True)


def test_fallback_plan_writes_every_node_and_the_cluster_entry(two):
    t = two
    plan = t["service"].plan_fallback({"preset": "quad9", "tls": True, "hours": 6}, "alice")
    assert plan.scope is PlanScope.DNS_RESOLVER and plan.requires_confirmation
    assert plan.summary_message["key"] == "plan.resolver.fallback"
    assert plan.summary_message["params"]["nodes"] == "ns1, ns2"
    assert plan.target_node_ids == [t["n1"], N2]
    with pytest.raises(Exception, match="confirm"):
        t["plans"].apply(plan, "alice", confirm=False)
    assert apply(t, plan).state is PlanState.APPLIED
    value = '{ 9.9.9.9 port 853 tls "dns.quad9.net"; 149.112.112.112 port 853 tls "dns.quad9.net";'
    for backend in (t["local"], t["remote"]):
        assert backend.options["forward"] == "first"
        assert backend.options["forwarders"].startswith(value)
        assert "dns.quad9.net" in backend.tls
        assert backend.options["dnssec-validation"] == "auto"  # never touched
    fb = fallback(t["ctx"])
    assert fb["node_ids"] == [t["n1"], N2] and fb["preset"] == "quad9" and fb["by"] == "alice"
    assert fb["tls_name"] == "dns.quad9.net" and fb["forward"] == "first" and fb["returned"] == []
    assert fb["started_at"] == "2026-10-29T12:00:00.000Z" and fb["until"] == "2026-10-29T18:00:00.000Z"
    assert fb["before"] == {
        t["n1"]: {"forward": "only", "forwarders": ["192.0.2.53"]},
        N2: {"forward": None, "forwarders": None},
    }
    with pytest.raises(Conflict):
        t["service"].plan_fallback({"preset": "quad9"}, "alice")
    # The audit keeps who asked, the fallback id and its nodes.
    entries = audit(t["ctx"], "dns.resolver.")
    node_entry = next(e for e in entries if e.request.get("entry") == "node")
    assert node_entry.request["op"] == "fallback" and node_entry.request["fallback_id"] == fb["id"]
    assert node_entry.request["node_ids"] == [t["n1"], N2]
    assert any(e.action == "dns.resolver.apply" and e.request.get("entry") == "summary" for e in entries)


def test_return_plan_restores_before_exactly_and_drops_the_entry(two):
    t = two
    original = (dict(t["local"].options), dict(t["remote"].options))
    apply(t, t["service"].plan_fallback({"forwarders": ["192.0.2.99", "2001:db8::99"], "hours": 2}, "alice"))
    assert t["local"].tls == {} and t["local"].options["forwarders"] == "{ 192.0.2.99; 2001:db8::99; }"
    plan = t["service"].plan_return("bob")
    assert plan.summary_message["key"] == "plan.resolver.return" and plan.requires_confirmation
    assert apply(t, plan).state is PlanState.APPLIED
    assert (t["local"].options, t["remote"].options) == original
    assert fallback(t["ctx"]) is None
    with pytest.raises(Conflict):
        t["service"].plan_return("bob")


def test_rollback_of_the_fallback_removes_it_everywhere(two):
    t = two
    original = (dict(t["local"].options), dict(t["remote"].options))
    plan = t["service"].plan_fallback({"preset": "cloudflare", "node_ids": [N2], "hours": 1}, "alice")
    assert plan.target_node_ids == [N2, t["n1"]]  # the BIND part on ns2, the entry written here
    apply(t, plan)
    assert t["local"].options == original[0] and t["remote"].options["forward"] == "first"
    assert t["plans"].rollback(plan, "alice").state is PlanState.ROLLED_BACK
    assert (t["local"].options, t["remote"].options) == original and fallback(t["ctx"]) is None


def test_a_failing_node_leaves_nothing_behind(two):
    t = two
    original = dict(t["local"].options)
    plan = t["service"].plan_fallback({"preset": "quad9"}, "alice")
    t["remote"].failure = EngineUnavailable("named stopped")
    result = apply(t, plan)
    assert result.state is not PlanState.APPLIED
    assert t["local"].options == original and fallback(t["ctx"]) is None


@pytest.mark.parametrize(
    ("body", "field"),
    [
        ({}, "forwarders"),
        ({"preset": "nope"}, "preset"),
        ({"forwarders": ["dns.example"]}, "forwarders"),
        ({"forwarders": "9.9.9.9"}, "forwarders"),
        ({"preset": "quad9", "forward": "last"}, "forward"),
        ({"preset": "quad9", "hours": 25}, "hours"),
        ({"preset": "quad9", "hours": 0}, "hours"),
        ({"preset": "quad9", "hours": True}, "hours"),
        ({"forwarders": ["192.0.2.1"], "tls": True}, "tls_name"),
        ({"forwarders": ["192.0.2.1"], "tls_name": "bad name"}, "tls_name"),
        ({"preset": "quad9", "node_ids": ["nope"]}, "node_ids"),
    ],
)
def test_fallback_refusals(two, body, field):
    with pytest.raises(ValidationError) as exc:
        two["service"].plan_fallback(body, "alice")
    assert exc.value.errors[0]["field"] == field


def test_operator_presets_and_offline_peer(two):
    t = two

    def own(cfg) -> None:
        cfg.settings.setdefault("resolver", {})["presets"] = [
            {"id": "isp", "name": "ISP", "forwarders": ["192.0.2.200"]}
        ]

    t["ctx"].config_store.update_cluster(own, updated_by="test")
    ids = [p["id"] for p in rf.presets(t["ctx"].settings())]
    assert ids == ["quad9", "quad9_unfiltered", "cloudflare", "isp"]
    t["gateway"].offline.add(N2)
    with pytest.raises(EngineUnavailable, match="ns2 does not answer"):
        t["service"].plan_fallback({"preset": "isp"}, "alice")
    plan = t["service"].plan_fallback({"preset": "isp", "node_ids": [t["n1"]]}, "alice")
    apply(t, plan)
    assert t["local"].options["forwarders"] == "{ 192.0.2.200; }"


def test_return_with_an_offline_node_keeps_it_for_its_collector(two):
    t = two
    apply(t, t["service"].plan_fallback({"preset": "quad9"}, "alice"))
    t["gateway"].offline.add(N2)
    plan = t["service"].plan_return("bob")
    assert plan.target_node_ids == [t["n1"]]
    apply(t, plan)
    fb = fallback(t["ctx"])
    assert fb["returned"] == [t["n1"]] and fb["until"] == "2026-10-29T12:00:00.000Z"
    assert t["local"].options["forward"] == "only"


def test_extend(two):
    t = two
    with pytest.raises(Conflict):
        t["service"].extend({"until": "2026-10-29T13:00:00.000Z"}, "alice")
    apply(t, t["service"].plan_fallback({"preset": "quad9", "hours": 1}, "alice"))
    out = t["service"].extend({"until": "2026-10-30T10:00:00.000Z"}, "alice", "192.0.2.7")
    assert out["fallback"]["until"] == "2026-10-30T10:00:00.000Z"
    for bad in ("2026-10-29T11:00:00.000Z", "2026-10-30T12:00:01.000Z", "soon", None):
        with pytest.raises(ValidationError):
            t["service"].extend({"until": bad}, "alice")
    entry = audit(t["ctx"], "dns.resolver.op")[-1]
    assert entry.request["op"] == "extend" and entry.client_ip == "192.0.2.7"


# Automatic return ----------------------------------------------------------------------------------


def collector_apply(t):
    plans = PlanService(t["ctx"], ConnectorRegistry(dns=t["local"]), t["gateway"])
    return lambda plan: plans.apply(plan, "system", confirm=True)


def test_auto_return_at_the_deadline_then_the_last_node_removes_the_entry(two):
    t = two
    original = dict(t["local"].options)
    apply(t, t["service"].plan_fallback({"preset": "quad9", "tls": True, "hours": 1}, "alice"))
    run = collector_apply(t)
    assert rf.auto_return(t["ctx"], t["local"], run, T0 + timedelta(minutes=59)) is None
    assert rf.auto_return(t["ctx"], t["local"], run, T0 + timedelta(hours=1)) == "returned"
    assert t["local"].options == original and t["local"].tls == {}
    fb = fallback(t["ctx"])
    assert fb["returned"] == [t["n1"]]
    assert rf.auto_return(t["ctx"], t["local"], run, T0 + timedelta(hours=2)) is None  # done already
    entry = audit(t["ctx"], "dns.resolver.op")[-1]
    assert entry.user == "system" and entry.request["op"] == "return" and entry.plan_id
    # ns2 comes back later: its collector returns its own part, the last one removes the entry.
    ns2_ctx = _as_node(t["ctx"], N2)
    assert rf.auto_return(
        ns2_ctx, t["remote"], lambda p: _apply_direct(t["remote"], p), T0 + timedelta(hours=3)
    )
    assert "forward" not in t["remote"].options and fallback(t["ctx"]) is None


def test_auto_return_disabled_and_manual_change(two):
    t = two
    apply(t, t["service"].plan_fallback({"preset": "quad9", "hours": 1}, "alice"))

    def off(cfg) -> None:
        cfg.settings.setdefault("resolver", {})["fallback_auto_return_enabled"] = False

    t["ctx"].config_store.update_cluster(off, updated_by="test")
    run = collector_apply(t)
    assert rf.auto_return(t["ctx"], t["local"], run, T0 + timedelta(hours=2)) is None
    assert t["local"].options["forward"] == "first"
    # Forwarders changed by hand during the fallback: flagged, and the automatic return skips it.
    t["local"].options["forwarders"] = "{ 192.0.2.77; }"
    assert rf.auto_return(t["ctx"], t["local"], run, T0 + timedelta(hours=2)) == "manual_change"
    assert fallback(t["ctx"])["manual_change"] is True
    assert rf.auto_return(t["ctx"], t["local"], run, T0 + timedelta(hours=2)) is None


def test_auto_return_marks_a_node_already_back(two):
    t = two
    apply(t, t["service"].plan_fallback({"preset": "quad9", "node_ids": [t["n1"]], "hours": 1}, "alice"))
    t["local"].options["forward"], t["local"].options["forwarders"] = "only", "{ 192.0.2.53; }"
    calls: list[Plan] = []
    assert rf.auto_return(t["ctx"], t["local"], calls.append, T0 + timedelta(hours=1)) == "returned"
    assert calls == [] and fallback(t["ctx"]) is None


def test_auto_return_failure_keeps_the_entry(two):
    t = two
    apply(t, t["service"].plan_fallback({"preset": "quad9", "node_ids": [t["n1"]], "hours": 1}, "alice"))
    out = rf.auto_return(t["ctx"], t["local"], lambda plan: None, T0 + timedelta(hours=1))
    assert out.startswith("failed") and fallback(t["ctx"])["returned"] == []


def _as_node(ctx, node_id):
    class Ctx:
        def __getattr__(self, name):
            return getattr(ctx, name)

    view = Ctx()
    view.node = type("N", (), {"id": node_id})()
    return view


def _apply_direct(backend, plan):
    result = backend.apply(plan)
    plan.state = PlanState.APPLIED if result.ok else PlanState.FAILED
    return plan


# Health ------------------------------------------------------------------------------------------


def probe(kind, name, address, ok=True, last_failure=None, failures=0):
    return {
        "kind": kind, "name": name, "address": address, "family": 4, "ok": ok, "rtt_ms": 12.5 if ok else None,
        "checked_at": 0, "last_failure": last_failure, "failures": failures,
    }  # fmt: skip


def test_probes_healthy_since():
    now = int(T0.timestamp())
    roots = [probe("root", "a", "192.0.2.1"), probe("root", "b", "192.0.2.2", last_failure=now - 60)]
    assert probes_healthy_since([]) == "unknown"
    assert probes_healthy_since(roots) is None  # one letter always answered
    both = [probe("root", "a", "192.0.2.1", last_failure=now - 600), roots[1]]
    assert probes_healthy_since(both) == "2026-10-29T11:50:00.000Z"
    tld = [probe("tld", "com", "192.0.2.5", ok=False, last_failure=now, failures=1)]
    assert probes_healthy_since(roots + tld) == "unhealthy"
    tld = [probe("tld", "com", "192.0.2.5", last_failure=now - 120)]
    assert probes_healthy_since(roots + tld) == "2026-10-29T11:58:00.000Z"


def test_node_health_reads_the_cache(node_ctx):
    conn = series_mod.connect(node_ctx.paths.series_db)
    store = series_mod.SeriesStore(conn)
    now = int(T0.timestamp())
    store.write_resolver_samples(
        now - 30,
        "n",
        {
            "queries_out_per_second": 12.5,
            "latency_p95_ms": 180.0,
            "cache_nodes": 4.0,
            "mismatch_per_minute": 2.0,
        },
    )
    store.write_resolver_probes(
        [
            probe("root", "a", "192.0.2.1"),
            probe("tld", "com", "192.0.2.5"),
            probe("tld", "lan", "192.0.2.6", False, now, 4),
        ]
    )
    health = node_health(store, "n", now, 120, ["com"])
    assert health["error"] is None and health["sampled_at"] == "2026-10-29T11:59:30.000Z"
    assert health["rates"]["queries_out"] == 12.5 and health["rates"]["cache_hit_percent"] is None
    assert health["latency_ms"] == {"p50": None, "p95": 180.0} and health["cache"]["nodes"] == 4.0
    assert health["roots"] == [
        {"letter": "a", "address": "192.0.2.1", "family": 4, "rtt_ms": 12.5, "ok": True, "last_failure": None}
    ]
    assert [(x["tld"], x["ok"], x["served"], x["servers"]) for x in health["tlds"]] == [
        ("com", True, False, 1),
        ("lan", False, True, 1),
    ]
    assert health["probes_healthy_since"] == "unhealthy"
    assert health["observed_max_7d"]["mismatch_per_minute"] == 2.0
    assert health["observed_max_7d"]["tld_failures"] == 4
    assert node_health(store, "n", now + 600, 120)["error"] == "statistics-channel unreachable"
    assert node_health(None, "n", now, 120)["error"] == "no resolver measure yet"
    conn.close()


def healthy(node_id, since=None):
    return {
        "node_id": node_id, "probes_healthy_since": since, "observed_max_7d": {"latency_p95_ms": 900.0,
        "mismatch_per_minute": 1.0, "tld_failures": 2},
    }  # fmt: skip


def test_health_aggregates_nodes_and_offers_the_return(two, monkeypatch):
    t = two
    local = healthy(t["n1"], "2026-10-29T11:00:00.000Z")
    monkeypatch.setattr(t["service"], "local_health", lambda: local)
    t["gateway"].health[N2] = healthy(N2)
    body = t["service"].health()
    assert [n["node_id"] for n in body["nodes"]] == [t["n1"], N2] and body["unavailable"] == []
    assert body["fallback"] is None and body["return_ready"] is False
    assert [p["id"] for p in body["presets"]][:1] == ["quad9"]
    th = body["thresholds"]
    assert th["latency_p95_ms"] == {"warning": 800, "critical": 1600, "observed_max_7d": 900.0}
    assert th["mismatch_count"]["observed_max_7d"] == 15.0  # 1 per minute over a 15 minute window
    assert th["tld_failures"] == {"warning": 3, "observed_max_7d": 2}
    assert th["lru_per_minute"] == {"info": 100, "observed_max_7d": None}

    apply(t, t["service"].plan_fallback({"preset": "quad9"}, "alice"))
    assert t["service"].health()["return_ready"] is True
    local["probes_healthy_since"] = "2026-10-29T11:50:00.000Z"  # healthy for 10 of the 15 minutes
    assert t["service"].health()["return_ready"] is False
    t["clock"].now = T0 + timedelta(minutes=5)
    assert t["service"].health()["return_ready"] is True
    t["gateway"].offline.add(N2)
    body = t["service"].health()
    assert body["return_ready"] is False and body["unavailable"][0]["node_id"] == N2
    assert [n["node_id"] for n in t["service"].health(t["n1"])["nodes"]] == [t["n1"]]
    with pytest.raises(NotFound):
        t["service"].health("nope")


def test_peer_actions_health_and_tls_parts(node_ctx):
    from pelagos.core.replication import PeerActionError
    from pelagos.services.peer_actions import RESOLVER_HEALTH, PeerActions

    backend = FakeDnsBackend(fake_context(node_ctx.node.id, "bind", node_ctx.paths.backups_dir / "b"))
    actions = PeerActions(node_ctx, ConnectorRegistry(dns=backend))
    health = actions(RESOLVER_HEALTH, {}, "peer")
    assert health["node_id"] == node_ctx.node.id and health["error"] == "no resolver measure yet"
    built = actions(
        "dns.config.plan",
        {"changes": [{"op": "replace", "target": "tls/dns.quad9.net"}], "created_by": "alice"},
        "peer",
    )
    assert built["plan"]["changes"][0]["target"] == "tls/dns.quad9.net"
    with pytest.raises(PeerActionError, match="tls/ changes"):
        actions(
            "dns.config.plan", {"changes": [{"op": "add", "target": "raw:keys.conf", "after": "x"}]}, "peer"
        )


def test_collector_task_returns_this_node(two):
    import threading
    from types import SimpleNamespace

    from pelagos.collector.main import Collector

    t = two
    original = dict(t["local"].options)
    apply(t, t["service"].plan_fallback({"preset": "quad9", "node_ids": [t["n1"]], "hours": 1}, "alice"))

    def past(cfg) -> None:
        cfg.settings["resolver"]["fallback"]["until"] = "2026-01-01T00:00:00.000Z"

    t["ctx"].config_store.update_cluster(past, updated_by="test")
    rig = SimpleNamespace(
        ctx=t["ctx"],
        backends=SimpleNamespace(dns=t["local"], kea4=None, kea6=None, d2=None),
        backend_lock=threading.RLock(),
        _replication_synced=lambda: True,
    )
    rig._apply_as_system = lambda plan: Collector._apply_as_system(rig, plan)
    Collector.resolver_return(rig)
    assert t["local"].options == original and fallback(t["ctx"]) is None
    Collector.resolver_return(rig)  # nothing left to do
