# SPDX-License-Identifier: Apache-2.0
"""Rollback of a plan sent to peers (section 6, FIX-PEERROLLBACK): the peers' guards are asked
before any node rolls back, a user rollback runs on the peers first and stops at the first node
that does not confirm, and the parts of a composite plan carry the plan's finished_at."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from pelagos.connectors.base import ConnectorError
from pelagos.core.plans import NO_ROLLBACK_SCOPES, PlanStore
from pelagos.core.registry import ConnectorRegistry as CoreRegistry
from pelagos.core.secrets import SecretBox
from pelagos.domain import Change, ChangeOp, Engine, NodeApplyResult, Plan, PlanScope, PlanState
from pelagos.domain.common import utcnow
from pelagos.services.plan_service import PlanError
from tests.unit.services.kea_pair import N2, Pair

pytestmark = pytest.mark.unit


@pytest.fixture
def pair(node_ctx) -> Pair:
    out = Pair(node_ctx)
    rollback = out.k1.rollback

    def local(plan: Plan) -> NodeApplyResult:
        out.gateway.order.append(out.n1)
        return rollback(plan)

    out.k1.rollback = local  # type: ignore[method-assign]
    return out


def _applied(pair: Pair, sid: int = 40) -> Plan:
    plan = pair.subnet_plan(sid)
    assert pair.plans.apply(plan, "admin", True).state is PlanState.APPLIED
    assert plan.target_node_ids == [pair.n1, N2]
    return plan


def _entries(pair: Pair, plan: Plan) -> int:
    return pair.ctx.audit_log.query(plan_id=plan.id, per_page=200)[1]


def test_rollback_asks_the_peer_first_then_rolls_back_the_peer_first(pair):
    plan = _applied(pair)
    result = pair.plans.rollback(plan, "admin")
    assert result.state is PlanState.ROLLED_BACK
    assert pair.gateway.calls("check_rollback", N2) == 1
    assert pair.gateway.order == [N2, pair.n1]
    assert pair.k1.rolled_back == [plan.id] and pair.k2.rolled_back == [plan.id]


def test_hand_edit_on_the_peer_only_refuses_everywhere_and_writes_nothing(pair):
    plan = _applied(pair)
    until, audited = plan.rollback_until, _entries(pair, plan)
    pair.k2.hash_override = "edited-by-hand-on-ns2"
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(plan, "admin")
    assert exc.value.code == "precondition_failed" and exc.value.detail.startswith("ns2: ")
    assert plan.state is PlanState.APPLIED and plan.rollback_until == until
    assert pair.ctx.plan_store.get(plan.id).state is PlanState.APPLIED
    assert pair.k1.rolled_back == [] and pair.k2.rolled_back == [] and pair.gateway.order == []
    assert _entries(pair, plan) == audited
    pair.k2.hash_override = None
    assert pair.plans.rollback(plan, "admin").state is PlanState.ROLLED_BACK


def test_peer_engine_error_in_its_guard_answers_engine_unavailable(pair, monkeypatch):
    plan = _applied(pair)

    def down(p: Plan) -> None:
        raise ConnectorError("kea4 control socket: connection refused")

    monkeypatch.setattr(pair.k2, "check_rollback", down)
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(plan, "admin")
    assert exc.value.code == "engine_unavailable" and plan.state is PlanState.APPLIED
    assert pair.gateway.order == []


def test_older_peer_without_the_route_refusing_inside_its_rollback_stops_the_rollback(pair, monkeypatch):
    plan = _applied(pair)
    pair.gateway.old.add(N2)

    def refused(p: Plan) -> NodeApplyResult:
        return NodeApplyResult(node_id=N2, ok=False, message="rollback guard lost: build a new plan")

    monkeypatch.setattr(pair.k2, "rollback", refused)
    result = pair.plans.rollback(plan, "admin")
    assert result.state is PlanState.FAILED and plan.rollback_until is None
    assert pair.gateway.order == [N2] and pair.k1.rolled_back == []
    by_node = {r.node_id: r for r in result.results}
    assert "guard lost" in by_node[N2].message
    assert not by_node[pair.n1].ok and "ns2 did not roll back first" in by_node[pair.n1].message
    assert all(r.message_message is not None for r in result.results if not r.ok)


def test_unreachable_peer_refuses_before_anything_and_the_plan_stays_rollable(pair):
    plan = _applied(pair)
    until = plan.rollback_until
    pair.gateway.offline.add(N2)
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(plan, "admin")
    assert exc.value.code == "node_unreachable" and exc.value.extra["node_ids"] == [N2]
    assert exc.value.extra["partial_allowed"] is False
    assert plan.state is PlanState.APPLIED and plan.rollback_until == until
    assert pair.gateway.order == [] and pair.k1.rolled_back == []
    pair.gateway.offline.discard(N2)
    assert pair.plans.rollback(plan, "admin").state is PlanState.ROLLED_BACK


def test_precheck_stops_at_the_first_silent_peer(pair, monkeypatch):
    top, _ = _host(pair, parts=3)
    monkeypatch.setattr(pair.k1, "check_rollback", lambda p: None)
    pair.gateway.offline.add(N2)
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(top, "admin")
    assert exc.value.code == "node_unreachable"
    assert pair.gateway.calls("check_rollback", N2) == 1  # not once per part


def test_peer_gateway_verdicts_for_transport_and_server_errors(pair):
    from pelagos.core.replication import UNREACHABLE, ReplicationError
    from pelagos.services.peers import PeerGateway

    plan, peer = pair.subnet_plan(), pair.gateway.peer(N2)
    gateway = PeerGateway(pair.ctx)

    class Client:
        def __init__(self, exc: Exception | None) -> None:
            self.exc = exc

        def check_rollback(self, p: Plan) -> tuple[str | None, str | None]:
            if self.exc is not None:
                raise self.exc
            return None, None

    cases = [
        (ReplicationError("connect refused", code=UNREACHABLE), "node_unreachable"),
        (ReplicationError("timed out"), "node_unreachable"),
        (TimeoutError("timed out"), "node_unreachable"),
        (ReplicationError("POST /plans/check-rollback on ns2: 500", 500), "engine_unavailable"),
    ]
    for exc, code in cases:
        gateway._client_with_timeout = lambda p, t, e=exc: Client(e)  # type: ignore[method-assign]
        problem, got = gateway.check_rollback(peer, plan)
        assert got == code and problem and problem.startswith("ns2: "), (exc, got)
    gateway._client_with_timeout = lambda p, t: Client(None)  # type: ignore[method-assign]
    assert gateway.check_rollback(peer, plan) == (None, None)
    gateway._client_with_timeout = lambda p, t: None  # type: ignore[method-assign]
    assert gateway.check_rollback(peer, plan)[1] == "node_unreachable"
    gateway._client_with_timeout = lambda p, t: object()  # type: ignore[method-assign]
    assert gateway.check_rollback(peer, plan) == (None, None)  # a client without the call


def test_undo_after_a_failed_apply_keeps_its_order_and_goes_on(pair, monkeypatch):
    plan = pair.subnet_plan()
    monkeypatch.setattr(
        pair.k2,
        "apply",
        lambda p: NodeApplyResult(node_id=N2, ok=False, message="boom", outcome_unknown=True),
    )
    monkeypatch.setattr(
        pair.k2, "rollback", lambda p: NodeApplyResult(node_id=N2, ok=False, message="still down")
    )
    result = pair.plans.apply(plan, "admin", True)
    assert result.state is PlanState.FAILED
    # Reverse order: the peer first; its failure does not keep this node from undoing its apply.
    assert pair.gateway.order == [N2, pair.n1] and pair.k1.rolled_back == [plan.id]
    assert pair.gateway.calls("check_rollback", N2) == 0


def _host(pair: Pair, parts: int = 1) -> tuple[Plan, list[Plan]]:
    # Kea parts on both nodes; each subnet plan carries the configuration hash it was built on,
    # so the parts after the first drop it (they apply on top of the first).
    built = [pair.subnet_plan(40 + 4 * i) for i in range(parts)]
    for later in built[1:]:
        later.preconditions = []
    top = Plan(scope=PlanScope.HOST, node_id=pair.n1, summary="host", target_node_ids=[pair.n1, N2])
    top.state = PlanState.VALIDATED
    pair.ctx.plan_store.put(top)
    pair.plans.register_composite(top, built)
    assert pair.plans.apply(top, "admin", True).state is PlanState.APPLIED
    return top, pair.plans.parts(top)


def test_stopped_rollback_marks_each_part_as_it_really_is(pair, monkeypatch):
    top, parts = _host(pair, parts=3)
    pair.gateway.old.add(N2)
    # Kea guards each part against the hash right after it: parts of one engine only roll back in
    # order, which this test does not exercise.
    monkeypatch.setattr(pair.k1, "check_rollback", lambda p: None)
    rollback = pair.k2.rollback

    def refuse_the_middle(p: Plan) -> NodeApplyResult:
        if p.id == parts[1].id:
            return NodeApplyResult(node_id=N2, ok=False, message="rollback guard lost: build a new plan")
        return rollback(p)

    monkeypatch.setattr(pair.k2, "rollback", refuse_the_middle)
    result = pair.plans.rollback(top, "admin")
    assert result.state is PlanState.FAILED and top.rollback_until is None
    assert [p.state for p in parts] == [PlanState.APPLIED, PlanState.FAILED, PlanState.ROLLED_BACK]
    stored = pair.ctx.plan_store.parts(top.id) or []
    assert [p.state for p in stored] == [PlanState.APPLIED, PlanState.FAILED, PlanState.ROLLED_BACK]
    assert pair.gateway.order == [N2, pair.n1, N2]
    assert pair.k1.rolled_back == [parts[2].id]


def test_composite_parts_carry_the_plan_finished_at_and_rollback_until(pair):
    top, parts = _host(pair)
    assert top.finished_at is not None and top.rollback_until is not None
    for part in parts:
        assert part.finished_at == top.finished_at and part.rollback_until == top.rollback_until
        assert part.expires_at == top.expires_at


def test_composite_part_goes_to_the_peer_with_its_finished_at(pair, monkeypatch):
    top, parts = _host(pair)
    seen: list[Plan] = []
    rollback = pair.gateway.rollback_plan

    def spy(peer: Any, plan: Plan) -> NodeApplyResult:
        seen.append(plan)
        return rollback(peer, plan)

    monkeypatch.setattr(pair.gateway, "rollback_plan", spy)
    assert pair.plans.rollback(top, "admin").state is PlanState.ROLLED_BACK
    assert [p.id for p in seen] == [parts[0].id]
    assert seen[0].finished_at == top.finished_at is not None


def test_composite_part_refused_on_the_peer_leaves_every_part_applied(pair):
    top, parts = _host(pair)
    pair.k2.hash_override = "edited-by-hand-on-ns2"
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(top, "admin")
    assert exc.value.code == "precondition_failed"
    assert top.state is PlanState.APPLIED and all(p.state is PlanState.APPLIED for p in parts)
    assert pair.k1.rolled_back == [] and pair.k2.rolled_back == []


def test_finished_at_of_parts_survives_a_restart(tmp_path):
    box = SecretBox(b"k" * 32)
    store = PlanStore(plans_dir=tmp_path, box=box)
    top = Plan(scope=PlanScope.HOST, node_id="n1", summary="host")
    part = Plan(scope=PlanScope.DHCP_RESERVATION, node_id="n1", summary="r", engine=Engine.KEA4)
    store.put(top)
    store.set_parts(top.id, [part])
    top.state = part.state = PlanState.APPLIED
    store.finish(top, 3600)
    (loaded,) = PlanStore(plans_dir=tmp_path, box=box).parts(top.id) or []
    assert loaded.finished_at == top.finished_at and loaded.rollback_until == top.rollback_until


def test_part_of_a_plan_a_restart_interrupted_gets_finished_at(tmp_path):
    box = SecretBox(b"k" * 32)
    store = PlanStore(plans_dir=tmp_path, box=box)
    top = Plan(scope=PlanScope.HOST, node_id="n1", summary="host")
    done = Plan(scope=PlanScope.DHCP_RESERVATION, node_id="n1", summary="r", engine=Engine.KEA4)
    store.put(top)
    store.set_parts(top.id, [done])
    top.state, done.state = PlanState.APPLYING, PlanState.APPLIED
    store.update(top)
    again = PlanStore(plans_dir=tmp_path, box=box)
    plan = again.get(top.id)
    (part,) = again.parts(top.id) or []
    assert plan.interrupted and part.finished_at == plan.finished_at is not None
    assert part.rollback_until == plan.rollback_until is not None


class Recorder:
    """Any engine's backend: records applies and rollbacks, guards nothing."""

    def __init__(self, node_id: str, order: list[str]) -> None:
        self.node_id = node_id
        self.order = order
        self.checked: list[str] = []

    def apply(self, plan: Plan) -> NodeApplyResult:
        return NodeApplyResult(node_id=self.node_id, ok=True, message="applied")

    def check_rollback(self, plan: Plan) -> None:
        self.checked.append(plan.id)

    def rollback(self, plan: Plan) -> NodeApplyResult:
        self.order.append(self.node_id)
        return NodeApplyResult(node_id=self.node_id, ok=True, message="rolled back")


ENGINE_OF = {"dhcp": Engine.KEA4, "dns": Engine.BIND, "d2": Engine.D2}


@pytest.mark.parametrize("scope", [s for s in PlanScope if s not in (PlanScope.HOST, PlanScope.RESTORE)])
def test_every_scope_rolls_back_as_before_on_a_healthy_pair(pair, scope):
    """A rollback no guard refuses: every scope that rolls back is asked once on the peer, then rolled
    back on both nodes, the peer first; the job scopes still refuse before asking anyone."""
    from pelagos.services.registry import ConnectorRegistry

    order: list[str] = []
    here, there = Recorder(pair.n1, order), Recorder(N2, order)
    pair.plans.registry = ConnectorRegistry(dns=here, kea4=here, kea6=here, d2=here)  # type: ignore[arg-type]
    pair.gateway.backends[N2] = there  # type: ignore[assignment]
    plan = Plan(
        scope=scope,
        node_id=pair.n1,
        summary=scope.value,
        engine=ENGINE_OF.get(scope.value.split(".")[0], Engine.BIND),
        changes=[Change(ChangeOp.REPLACE, "x", before={}, after={})],
        target_node_ids=[pair.n1, N2],
    )
    plan.state = PlanState.APPLIED
    pair.ctx.plan_store.put(plan)
    pair.ctx.plan_store.finish(plan, 3600)
    if scope in NO_ROLLBACK_SCOPES:
        with pytest.raises(PlanError) as exc:
            pair.plans.rollback(plan, "admin")
        assert exc.value.code == "plan_state" and pair.gateway.calls("check_rollback", N2) == 0
        assert order == []
        return
    result = pair.plans.rollback(plan, "admin")
    assert result.state is PlanState.ROLLED_BACK, result
    assert here.checked == [plan.id] and pair.gateway.calls("check_rollback", N2) == 1
    assert order == [N2, pair.n1]


def test_core_registry_check_rollback_verdicts():
    class Guard:
        def __init__(self, exc: Exception | None) -> None:
            self.exc = exc

        def check_rollback(self, plan: Plan) -> None:
            if self.exc is not None:
                raise self.exc

    from pelagos.connectors.base import PreconditionFailed
    from pelagos.domain.plan import Precondition, PreconditionKind

    plan = Plan(scope=PlanScope.DHCP_SUBNET, node_id="n1", summary="s", engine=Engine.KEA4)
    reg = CoreRegistry("n2")
    assert reg.check_rollback(plan) == (None, None)  # engine not here: no verdict
    reg.register(Engine.KEA4, Guard(None))
    assert reg.check_rollback(plan) == (None, None)
    pre = Precondition(PreconditionKind.CONFIG_HASH, "kea4:config", "a", "n2")
    reg.register(Engine.KEA4, Guard(PreconditionFailed(pre, "b")))
    problem, code = reg.check_rollback(plan)
    assert code == "precondition_failed" and "expected a, observed b" in str(problem)
    reg.register(Engine.KEA4, Guard(ConnectorError("socket down")))
    assert reg.check_rollback(plan) == ("socket down", "engine_unavailable")
    job = Plan(scope=PlanScope.INSTALL, node_id="n1", summary="i", engine=Engine.KEA4)
    assert reg.check_rollback(job) == (None, None)


def test_window_unchanged_by_the_parts(pair, monkeypatch):
    top, _ = _host(pair)
    later = utcnow() + timedelta(hours=2)
    for mod in ("pelagos.core.plans", "pelagos.services.plan_service"):
        monkeypatch.setattr(f"{mod}.utcnow", lambda: later)
    assert pair.plans.rollback(top, "admin").state is PlanState.ROLLED_BACK
    assert all(p.rollback_until is None for p in pair.plans.parts(top))


def _through_the_peer_app(pair: Pair, tmp_path, missing_route: bool = False) -> None:
    """Node 2's /repl/v1 handler behind a real ReplicationClient and the real PeerGateway."""
    import dataclasses

    from pelagos.core.audit_log import AuditLog
    from pelagos.core.replication import ReplicationApp, ReplicationClient, ReplicationError
    from pelagos.services.peers import PeerGateway

    registry = CoreRegistry(N2)
    registry.register(Engine.KEA4, pair.k2)
    node = dataclasses.replace(pair.ctx.node, id=N2, name="ns2")
    app = ReplicationApp(node, pair.ctx.config_store, AuditLog(tmp_path / "audit.jsonl"), registry=registry)
    client = ReplicationClient(pair.gateway.peer(N2), None)  # type: ignore[arg-type]

    def call(method: str, path: str, body=None, *args, **kwargs):
        assert (method, path) == ("POST", "/plans/check-rollback")
        if missing_route:
            raise ReplicationError("POST /plans/check-rollback on ns2: 404", 404)
        return app._check_rollback(body)[1]

    client._call = call  # type: ignore[method-assign]
    gateway = PeerGateway(pair.ctx)
    gateway._client_with_timeout = lambda peer, timeout: client  # type: ignore[method-assign]
    pair.gateway.check_rollback = gateway.check_rollback  # type: ignore[method-assign]


def test_peer_route_refusal_reaches_this_node_as_409(pair, tmp_path):
    plan = _applied(pair)
    _through_the_peer_app(pair, tmp_path)
    pair.k2.hash_override = "edited-by-hand-on-ns2"
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(plan, "admin")
    assert exc.value.code == "precondition_failed" and exc.value.detail.startswith("ns2: ")
    assert plan.state is PlanState.APPLIED and pair.gateway.order == []
    pair.k2.hash_override = None
    assert pair.plans.rollback(plan, "admin").state is PlanState.ROLLED_BACK


def test_peer_without_the_route_gives_no_verdict(pair, tmp_path):
    plan = _applied(pair)
    _through_the_peer_app(pair, tmp_path, missing_route=True)
    assert pair.plans.rollback(plan, "admin").state is PlanState.ROLLED_BACK
    assert pair.gateway.order == [N2, pair.n1]


N4 = "N4KEAPEER0000000000000000D"


def _third_kea_node(pair: Pair) -> Any:
    from pelagos.domain import NodeModules, Peer
    from tests.unit.services.fakes import FakeDhcpBackend, fake_context
    from tests.unit.services.kea_pair import ha_config

    def add(cfg: Any) -> None:
        cfg.nodes.append(
            Peer(
                id=N4,
                name="ns4",
                url="https://ns4.example.lan:8444",
                cert_fingerprint="sha256:00",
                modules=NodeModules(kea4=True),
            )
        )

    pair.ctx.config_store.update_cluster(add, updated_by="test")
    k4 = FakeDhcpBackend(fake_context(N4, "kea4", pair.ctx.paths.backups_dir / "k4"), node_id=N4)
    ha_config(k4.config, "ns2")
    pair.gateway.backends[N4] = k4
    return k4


def test_three_nodes_peers_first_in_reverse_order_and_a_guard_anywhere_refuses_all(pair):
    k4 = _third_kea_node(pair)
    plan = pair.subnet_plan()
    assert set(plan.target_node_ids) == {pair.n1, N2, N4}
    assert pair.plans.apply(plan, "admin", True).state is PlanState.APPLIED
    k4.hash_override = "edited-by-hand-on-ns4"
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(plan, "admin")
    assert exc.value.code == "precondition_failed" and exc.value.detail.startswith("ns4: ")
    assert pair.gateway.order == [] and plan.state is PlanState.APPLIED
    k4.hash_override = None
    assert pair.plans.rollback(plan, "admin").state is PlanState.ROLLED_BACK
    peers = [n for n in reversed(plan.target_node_ids) if n != pair.n1]
    assert pair.gateway.order == [*peers, pair.n1]


def test_three_nodes_without_the_precheck_a_late_refusal_stops_after_the_peers_before_it(pair, monkeypatch):
    """Older peers: the peer asked first may already be undone when the next refuses (section 6,
    three nodes or more); this node is never touched after a refusal."""
    _third_kea_node(pair)
    plan = pair.subnet_plan()
    assert pair.plans.apply(plan, "admin", True).state is PlanState.APPLIED
    pair.gateway.old.update({N2, N4})
    peers = [n for n in reversed(plan.target_node_ids) if n != pair.n1]
    first, second = peers
    refuser = pair.gateway.backends[second]
    monkeypatch.setattr(
        refuser, "rollback", lambda p: NodeApplyResult(node_id=second, ok=False, message="guard lost")
    )
    result = pair.plans.rollback(plan, "admin")
    assert result.state is PlanState.FAILED
    assert pair.gateway.order == [first, second] and pair.k1.rolled_back == []
    assert pair.gateway.backends[first].rolled_back == [plan.id]
    by_node = {r.node_id: r for r in result.results}
    assert by_node[first].ok and not by_node[second].ok and not by_node[pair.n1].ok
