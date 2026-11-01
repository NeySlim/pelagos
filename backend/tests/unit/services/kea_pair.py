# SPDX-License-Identifier: Apache-2.0
"""A two-node Kea HA pair for the partial apply tests (B1-KEAOFFLINE): n1 is this node, N2 a peer
served by a fake gateway that can be offline, run a stopped Kea, or be an older release."""

from __future__ import annotations

import copy
from collections import Counter
from typing import Any

from pelagos.collector import kea_shared
from pelagos.core.replication import PeerStatus
from pelagos.domain import Change, ChangeOp, Engine, Family, NodeApplyResult, NodeModules, Peer, Plan
from pelagos.services import kea_files
from pelagos.services.dhcp_service import DhcpService
from pelagos.services.plan_service import PlanService
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import FakeDhcpBackend, fake_context

N2 = "N2KEAPEER0000000000000000B"
N3 = "N3BINDPEER000000000000000C"


def ha_config(config: dict[str, Any], me: str) -> dict[str, Any]:
    """The fake configuration with a real hot-standby relationship ns1/ns2."""
    for hook in config["hooks-libraries"]:
        if "libdhcp_ha" in hook["library"]:
            hook["parameters"] = {
                "high-availability": [
                    {
                        "this-server-name": me,
                        "mode": "hot-standby",
                        "max-response-delay": 60000,
                        "heartbeat-delay": 10000,
                        "peers": [
                            {"name": "ns1", "role": "primary", "url": "http://192.0.2.1:8000/"},
                            {"name": "ns2", "role": "standby", "url": "http://192.0.2.2:8000/"},
                        ],
                    }
                ]
            }
    return config


class Gateway:
    """The PeerGateway calls of the partial apply, served by the peers' fake backends."""

    def __init__(self, ctx: Any, backends: dict[str, FakeDhcpBackend]) -> None:
        self.ctx = ctx
        self.backends = backends
        self.offline: set[str] = set()
        self.engine_down: set[str] = set()
        self.old: set[str] = set()
        self.refusing: dict[str, str] = {}
        self.counts: Counter[tuple[str, str]] = Counter()

    def calls(self, name: str, node_id: str) -> int:
        return self.counts[(name, node_id)]

    def peers(self) -> list[Peer]:
        return [n for n in self.ctx.cluster().nodes if n.id != self.ctx.node.id]

    def peer(self, node_id: str) -> Peer | None:
        return next((p for p in self.peers() if p.id == node_id), None)

    def peers_running(self, engine: Engine) -> list[Peer]:
        return [p for p in self.peers() if getattr(p.modules, engine.value, False)]

    def forget(self, node_id: str | None = None) -> None:
        self.counts[("forget", str(node_id))] += 1

    def status(self, peer: Peer) -> PeerStatus:
        self.counts[("status", peer.id)] += 1
        collections = None if peer.id in self.old else list(kea_files_names())
        return PeerStatus(peer.id, peer.id not in self.offline, collections=collections)

    def preflight_plan(self, peer: Peer, plan: Plan) -> str | None:
        self.counts[("preflight_plan", peer.id)] += 1
        if peer.id in self.offline:
            return f"{peer.name}: connection refused"
        return self.refusing.get(peer.id)

    def preflight_verdict(self, peer: Peer, plan: Plan) -> tuple[str | None, str | None]:
        self.counts[("preflight_plan", peer.id)] += 1
        if peer.id in self.engine_down:
            return f"{peer.name}: kea-dhcp4 is not running", None if peer.id in self.old else "engine_down"
        if peer.id in self.refusing:
            return self.refusing[peer.id], None
        check = getattr(self.backends[peer.id], "preflight", None)
        return (check(plan) if callable(check) else None), None

    def _peer_plan(self, peer: Peer, plan: Plan) -> Plan:
        out = Plan.from_dict(plan.to_dict())
        out.preconditions = [p for p in out.preconditions if p.node_id in (None, peer.id)]
        return out

    def apply_plan(self, peer: Peer, plan: Plan) -> NodeApplyResult:
        if peer.id in self.offline:
            return NodeApplyResult(node_id=peer.id, ok=False, message="unreachable", outcome_unknown=True)
        result = self.backends[peer.id].apply(self._peer_plan(peer, plan))
        result.node_id = peer.id
        return result

    def rollback_plan(self, peer: Peer, plan: Plan) -> NodeApplyResult:
        result = self.backends[peer.id].rollback(self._peer_plan(peer, plan))
        result.node_id = peer.id
        return result

    def snapshot(
        self, peer: Peer, engine: Engine, kind: str = "summary", params: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        if peer.id in self.offline or peer.id not in self.backends:
            return None
        backend = self.backends[peer.id]
        if kind == "config":
            return {"config": backend.config_get(), "config_hash": backend.config_hash()}
        if kind == "summary":
            return {"capabilities": backend.capabilities().to_dict()}
        return None

    def build_plan(self, peer: Peer, name: str, body: dict[str, Any]) -> Plan:
        assert name == "dhcp.config.plan"
        backend = self.backends[peer.id]
        config = kea_shared.shared_overlay(body["shared_from"], backend.config_get())
        plan = backend.plan_config_replace(config, body["created_by"])
        plan.target_node_ids = [peer.id]
        return plan


def kea_files_names() -> tuple[str, ...]:
    return (kea_files.COLLECTION,)


class Pair:
    def __init__(self, node_ctx: Any, k1: Any = None, k2: Any = None) -> None:
        """Fake backends by default; a daemon test passes real KeaBackends of an HA pair."""
        self.ctx = node_ctx
        self.n1 = node_ctx.node.id

        def add(cfg: Any) -> None:
            cfg.nodes.append(
                Peer(
                    id=N2,
                    name="ns2",
                    url="https://ns2.example.lan:8444",
                    cert_fingerprint="sha256:00",
                    modules=NodeModules(kea4=True),
                )
            )

        node_ctx.config_store.update_cluster(add, updated_by="test")
        root = node_ctx.paths.backups_dir
        if k1 is None:
            k1 = FakeDhcpBackend(fake_context(self.n1, "kea4", root / "k1"), node_id=self.n1)
            k2 = FakeDhcpBackend(fake_context(N2, "kea4", root / "k2"), node_id=N2)
            ha_config(k1.config, "ns1")
            ha_config(k2.config, "ns2")
            k2.ha.server_name, k2.ha.partner.server_name = "ns2", "ns1"
        self.k1, self.k2 = k1, k2
        self.gateway = Gateway(node_ctx, {N2: self.k2})
        self.plans = PlanService(node_ctx, ConnectorRegistry(kea4=self.k1), self.gateway)
        self.dhcp = DhcpService(node_ctx, Family.V4, self.k1, self.gateway)
        self.dhcp.plans = self.plans
        self.plans.kea = {Engine.KEA4: self.dhcp}

    def kea(self, node_id: str) -> FakeDhcpBackend:
        return self.k1 if node_id == self.n1 else self.k2

    def add_old_bind_node(self) -> None:
        def add(cfg: Any) -> None:
            cfg.nodes.append(
                Peer(
                    id=N3,
                    name="ns3",
                    url="https://ns3.example.lan:8444",
                    cert_fingerprint="sha256:00",
                    modules=NodeModules(bind=True),
                )
            )

        self.ctx.config_store.update_cluster(add, updated_by="test")
        self.gateway.old.add(N3)

    def away(self, node_id: str, *, in_touch: bool = False, engine_down: bool = False) -> None:
        """The peer goes away (or only its Kea); this node's Kea sees the partner lost unless in touch."""
        (self.gateway.engine_down if engine_down else self.gateway.offline).add(node_id)
        if isinstance(self.k1, FakeDhcpBackend):
            self.k1.ha.partner.communication_interrupted = not in_touch  # type: ignore[union-attr]

    def back(self, node_id: str) -> None:
        self.gateway.offline.discard(node_id)
        self.gateway.engine_down.discard(node_id)
        if isinstance(self.k1, FakeDhcpBackend):
            self.k1.ha.partner.communication_interrupted = False  # type: ignore[union-attr]

    def subnet_plan(self, sid: int = 40) -> Plan:
        change = {"op": "add", "target": f"subnet4/{sid}", "after": {"subnet": f"198.51.100.{sid}/30"}}
        return self.dhcp.plan("subnet", {"change": change}, "admin")

    def options_plan(self, target: str) -> Plan:
        change = {"op": "replace", "target": target, "after": True if target.startswith("ddns-") else {}}
        if target == "hooks-libraries":
            change["after"] = copy.deepcopy(self.k1.config["hooks-libraries"])
        kind = "hooks" if target == "hooks-libraries" else "ddns"
        return self.dhcp.plan(kind, {"changes": [change]}, "admin")

    def reconcile(self, source: str, target: str) -> Plan:
        plan = self.dhcp.plan_reconcile({"source_node_id": source, "target_node_id": target}, "admin")
        result = self.plans.apply(plan, "admin", True)
        assert result.state.value == "applied", result
        return plan

    def records(self) -> list[dict[str, Any]]:
        return self.ctx.cluster().collection(kea_files.COLLECTION)

    def summary(self, plan_id: str) -> Any:
        entries, _ = self.ctx.audit_log.query(per_page=200)
        return next(e for e in entries if e.plan_id == plan_id and e.request.get("entry") == "summary")


def change(op: str, target: str, after: Any = None) -> Change:
    return Change(ChangeOp(op), target, after=after)
