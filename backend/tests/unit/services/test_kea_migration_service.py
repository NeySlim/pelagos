# SPDX-License-Identifier: Apache-2.0
"""Kea migration analysis across the cluster: inventory, report assembly, HA symmetry (section 26)."""

from __future__ import annotations

import copy
import json
import stat
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.connectors.kea import migration as mig
from pelagos.domain import NodeModules, Peer
from pelagos.services import kea_migration_service as kms
from pelagos.services.errors import EngineUnavailable, ServiceError, ValidationError
from pelagos.services.peer_actions import KEA_MIGRATION_ANALYZE, KEA_MIGRATION_INVENTORY, PeerActions
from tests.unit.installer.fakes import make_env

pytestmark = pytest.mark.unit

KEA_DATA = Path(__file__).resolve().parents[1] / "connectors" / "kea" / "data"
DPKG_26 = "kea-dhcp4-server\t2.6.3-1+deb13u1\tii \nkea-common\t2.6.3-1+deb13u1\tii \n"
LAYOUT = mig.TargetLayout("3.2", "isc", "/usr/lib/x86_64-linux-gnu/kea/hooks", None)


def dhcp4(server: str = "ns1") -> dict[str, Any]:
    cfg = json.loads((KEA_DATA / "kea26-migration-dhcp4.json").read_text())
    for hook in cfg["Dhcp4"]["hooks-libraries"]:
        for rel in (hook.get("parameters") or {}).get("high-availability") or []:
            rel["this-server-name"] = server
    return cfg


def answer(node_id: str, cfg: dict[str, Any]) -> dict[str, Any]:
    """A kea_dry_run answer as installer.kea_migration.analyze builds it, from a real conversion."""
    conv = mig.convert("kea4", cfg, LAYOUT, node_id)
    return {
        "node_id": node_id,
        "series": "3.2",
        "source": "isc",
        "target_version": "3.2.1-isc20260928103142",
        "findings": [f.to_dict() for f in conv.findings],
        "diffs": {"kea4": conv.diff("/etc/kea/kea-dhcp4.conf")},
        "files": [],
        "packages": {"remove": [{"name": "kea-dhcp4-server", "version": "2.6.3-1+deb13u1"}], "install": []},
        "validation": {"kea4": {"ok": True, "mode": "dry_run", "output": "", "version": "3.2.1"}},
        "configs": {"kea4": mig.mask_secrets(conv.after)},
    }


class Peers:
    def __init__(self, handlers: dict[str, Any]) -> None:
        self.handlers = handlers
        self.calls: list[tuple[str, str, float | None]] = []

    def peer(self, node_id: str) -> Any:
        return SimpleNamespace(id=node_id, name="ns2") if node_id in self.handlers else None

    def action(self, peer: Any, name: str, body: dict[str, Any], timeout: float | None = None) -> Any:
        self.calls.append((peer.id, name, timeout))
        result = self.handlers[peer.id](name, body)
        if isinstance(result, Exception):
            raise result
        return json.loads(json.dumps(result))


@pytest.fixture
def service(node_ctx, tmp_path):
    env = make_env(tmp_path / "host")
    env.runner.responses["dpkg-query -W"] = DPKG_26
    env.runner.responses["dpkg-query -S"] = "kea-dhcp4-server: /usr/sbin/kea-dhcp4\n"
    env.runner.responses["dpkg --print-architecture"] = "arm64\n"
    node_ctx.config_store.update_cluster(
        lambda c: c.nodes.append(
            Peer(
                id="node-b",
                name="ns2",
                url="https://ns2.example.lan:8444",
                cert_fingerprint="fp-b",
                modules=NodeModules(kea4=True),
            )
        ),
        updated_by="test",
    )
    svc = kms.KeaMigrationService(node_ctx, env_factory=lambda: env)
    return svc


def test_local_inventory_reads_the_package_and_the_series_data(service):
    inv = service.local_inventory()
    assert inv["arch"] == "arm64"
    assert inv["distro"] == {"id": "debian", "codename": "trixie"}
    kea4 = inv["engines"]["kea4"]
    assert kea4["version"] == "2.6.3" and kea4["series"] == "2.6" and kea4["source"] == "distro"
    assert kea4["package"] == "kea-dhcp4-server" and kea4["maintained"] is False
    assert kea4["eol"] == "2026-07-30"
    assert {"series": "3.0", "source": "backports"} in inv["targets"]


def test_overview_asks_each_kea_peer_and_keeps_one_cluster_target(service):
    peer_inv = {**service.local_inventory(), "node_id": "node-b", "name": "ns2"}
    peer_inv["targets"] = [t for t in peer_inv["targets"] if t["source"] == "isc"]  # a Rocky node
    service.peers = Peers({"node-b": lambda name, body: peer_inv})
    out = service.overview()
    assert [n["node_id"] for n in out["nodes"]] == [service.ctx.node.id, "node-b"]
    assert service.peers.calls[0][1] == KEA_MIGRATION_INVENTORY
    by = {(t["series"], t["source"]): t for t in out["targets"]}
    assert by[("3.2", "isc")]["available"] and by[("3.2", "isc")]["recommended"]
    assert by[("3.0", "backports")]["available"] is False and "note" in by[("3.0", "backports")]
    assert out["analysis"] is None and out["current"] is None


def test_overview_reports_an_offline_peer(service):
    service.peers = Peers({"node-b": lambda name, body: EngineUnavailable("node ns2 is offline")})
    nodes = service.overview()["nodes"]
    assert nodes[1]["reachable"] is False and "offline" in nodes[1]["error"]


def test_analyze_merges_both_nodes_and_checks_ha_symmetry(service):
    me = service.ctx.node.id
    service.local_dry_run = lambda series, source: answer(me, dhcp4("ns1"))
    other = dhcp4("ns2")
    for hook in other["Dhcp4"]["hooks-libraries"]:
        for rel in (hook.get("parameters") or {}).get("high-availability") or []:
            rel["max-response-delay"] = 60000
    service.peers = Peers({"node-b": lambda name, body: answer("node-b", other)})
    report = service.analyze({"series": "3.2", "source": "isc"}, "admin", "192.0.2.50")
    assert report["node_ids"] == [me, "node-b"]
    assert service.peers.calls == [("node-b", KEA_MIGRATION_ANALYZE, kms.ANALYZE_TIMEOUT)]
    assert set(report["diffs"]) == {me, "node-b"}
    asym = [f for f in report["findings"] if f["code"] == "ha_asymmetric"]
    assert len(asym) == 1 and asym[0]["message"]["params"]["fields"] == ["max-response-delay"]
    assert asym[0]["node_id"] == me
    assert report["blocking"] and report["counts"]["blocking"] == 1
    assert report["counts"]["converted"] > 0
    assert report["outage_estimate_seconds"] == kms.OUTAGE_HA_SECONDS
    assert report["target_version"] == "3.2.1-isc20260928103142"
    # Kept on this node, 0640, and audited.
    path = service.report_path
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert service.last_report()["id"] == report["id"]
    [entry] = [e for e in service.ctx.audit_log.read() if e.action == "kea.migration.analyze"]
    assert entry.target == f"kea-migration:{report['id']}" and entry.client_ip == "192.0.2.50"
    assert entry.response == {"blocking": True, "counts": report["counts"]}


def test_symmetric_pair_has_no_finding_and_an_unreachable_peer_blocks(service):
    me = service.ctx.node.id
    service.local_dry_run = lambda series, source: answer(me, dhcp4("ns1"))
    service.peers = Peers({"node-b": lambda name, body: answer("node-b", dhcp4("ns2"))})
    report = service.analyze({"series": "3.2", "source": "isc"}, "admin")
    assert not [f for f in report["findings"] if f["code"] == "ha_asymmetric"]
    assert not report["blocking"]
    service.peers = Peers({"node-b": lambda name, body: EngineUnavailable("node ns2 is offline")})
    report = service.analyze({"series": "3.2", "source": "isc"}, "admin")
    assert report["unreachable"] == ["node-b"]
    lost = [f for f in report["findings"] if f["code"] == "node_unreachable"]
    assert lost[0]["severity"] == "blocking" and lost[0]["message"]["params"] == {"node": "ns2"}
    assert "offline" in lost[0]["error"]


def test_analyze_validates_target_and_nodes(service):
    with pytest.raises(ValidationError):
        service.analyze({"series": "2.6", "source": "isc"}, "admin")
    with pytest.raises(ValidationError):
        service.analyze({"series": "3.2", "source": "isc", "node_ids": ["nope"]}, "admin")
    me = service.ctx.node.id
    service.local_dry_run = lambda series, source: answer(me, dhcp4("ns1"))
    report = service.analyze({"series": "3.2", "source": "isc", "node_ids": [me]}, "admin")
    assert report["node_ids"] == [me]


def test_ha_pairs_matches_partners_by_server_name():
    a, b, c = dhcp4("ns1"), dhcp4("ns2"), dhcp4("ns1")
    configs = {"n1": {"kea4": a}, "n2": {"kea4": b}, "n3": {"kea4": copy.deepcopy(c)}}
    assert kms.ha_pairs(configs, "kea4") == [("n1", "n2"), ("n2", "n3")]
    assert kms.ha_pairs({"n1": {"kea4": a}}, "kea4") == []


def test_peer_actions_serve_inventory_and_analysis_without_the_engine_lock(service, monkeypatch):
    me = service.ctx.node.id
    monkeypatch.setattr(kms.KeaMigrationService, "local_inventory", lambda self: {"node_id": me})
    monkeypatch.setattr(
        kms.KeaMigrationService, "local_analyze", lambda self, s, o: {"series": s, "source": o}
    )
    actions = PeerActions(service.ctx, registry=None)
    held, done = threading.Event(), threading.Event()

    def poll() -> None:  # a long collector poll holds the engine lock
        with actions.lock:
            held.set()
            done.wait(10)

    t = threading.Thread(target=poll)
    t.start()
    held.wait(5)
    try:
        assert actions(KEA_MIGRATION_INVENTORY, {}, "node-b") == {"node_id": me}
        assert actions(KEA_MIGRATION_ANALYZE, {"series": "3.2", "source": "isc"}, "node-b") == {
            "series": "3.2",
            "source": "isc",
        }
    finally:
        done.set()
        t.join()


def test_upstream_version():
    assert kms.upstream("1:2.6.3-1+deb13u1") == "2.6.3"
    assert kms.upstream("3.2.1-isc20260928103142") == "3.2.1"
    assert kms.upstream("3.0.1") == "3.0.1"


def test_a_node_without_kea_is_not_analyzed_by_default_and_a_peer_without_files_is_a_finding(service):
    me = service.ctx.node.id
    # A DNS-only node used as the admin UI.
    service.ctx.node.engines = {k: v for k, v in service.ctx.node.engines.items() if k == "bind"}
    called: list[str] = []
    service.local_dry_run = lambda series, source: called.append(me) or answer(me, dhcp4("ns1"))
    service.peers = Peers({"node-b": lambda name, body: answer("node-b", dhcp4("ns2"))})
    report = service.analyze({"series": "3.2", "source": "isc"}, "admin")
    assert report["node_ids"] == ["node-b"] and called == []
    service.peers = Peers({"node-b": lambda name, body: ValidationError("no Kea configuration to analyze")})
    report = service.analyze({"series": "3.2", "source": "isc"}, "admin")
    [f] = [f for f in report["findings"] if f["code"] == "node_not_analyzed"]
    assert f["severity"] == "blocking" and f["node_id"] == "node-b"
    assert f["message"]["params"] == {"node": "ns2"} and "no Kea" in f["error"]
    assert report["blocking"] and report["unreachable"] == []


def test_an_unreachable_kea_node_makes_every_target_unavailable(service):
    service.peers = Peers({"node-b": lambda name, body: EngineUnavailable("node ns2 is offline")})
    out = service.overview()
    assert not any(t["available"] for t in out["targets"])


def test_any_offline_or_older_node_makes_targets_unavailable_with_a_reason(service):
    service.ctx.config_store.update_cluster(
        lambda c: c.nodes.append(
            Peer(id="node-c", name="ns3", url="https://ns3.example.lan:8444", cert_fingerprint="fp-c")
        ),
        updated_by="test",
    )
    peer_inv = {**service.local_inventory(), "node_id": "node-b", "name": "ns2"}
    older = ServiceError("not_supported", "ns3: this node does not serve action kea.migration.inventory")
    service.peers = Peers({"node-b": lambda name, body: peer_inv, "node-c": lambda name, body: older})
    targets = service.overview()["targets"]
    assert targets and not any(t["available"] for t in targets)
    assert targets[0]["reason"]["code"] == "node_unreachable" and "not serve" in targets[0]["reason"]["error"]


def test_a_node_that_cannot_install_the_target_is_the_reason(service):
    peer_inv = {**service.local_inventory(), "node_id": "node-b", "name": "ns2"}
    peer_inv["targets"] = [t for t in peer_inv["targets"] if t["series"] == "3.0"]
    service.peers = Peers({"node-b": lambda name, body: peer_inv})
    by = {(t["series"], t["source"]): t for t in service.overview()["targets"]}
    assert by[("3.2", "isc")]["available"] is False
    assert by[("3.2", "isc")]["reason"] == {"code": "not_offered", "node": "ns2"}
    assert by[("3.0", "isc")]["available"] and by[("3.0", "isc")]["reason"] is None


def test_an_empty_package_version_stays_unknown(service, monkeypatch):
    service.env_factory().runner.responses["dpkg-query -W"] = "kea-dhcp4-server\t\tii \n"
    data = {"series": {"kea": {"2.6": {"maintained": False}, "3.99": {"maintained": "yes"}}}}
    monkeypatch.setattr(kms.advisories, "load", lambda var: data)
    kea4 = service.local_inventory()["engines"]["kea4"]
    assert kea4["series"] is None and kea4["maintained"] is None


def test_a_non_boolean_maintenance_entry_stays_unknown(service, monkeypatch):
    monkeypatch.setattr(kms.advisories, "load", lambda var: {"series": {"kea": {"2.6": {"maintained": 1}}}})
    assert service.local_inventory()["engines"]["kea4"]["maintained"] is None


def test_the_analysis_lock_holds_across_workers(service):
    import fcntl
    import os

    from pelagos.services.errors import Conflict

    me = service.ctx.node.id
    service.local_dry_run = lambda series, source: answer(me, dhcp4("ns1"))
    service.peers = Peers({"node-b": lambda name, body: answer("node-b", dhcp4("ns2"))})
    lock = service.report_path.with_name(kms.LOCK_NAME)
    lock.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o640)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # another worker's analysis
        with pytest.raises(Conflict):
            service.analyze({"series": "3.2", "source": "isc"}, "admin")
    finally:
        os.close(fd)
    assert service.analyze({"series": "3.2", "source": "isc"}, "admin")["node_ids"]


def test_unknown_series_has_no_maintenance_state(service, monkeypatch):
    monkeypatch.setattr(kms.advisories, "load", lambda var: {})
    assert service.local_inventory()["engines"]["kea4"]["maintained"] is None


def test_one_analysis_at_a_time_and_a_failed_one_is_audited(service):
    from pelagos.domain import AuditResult
    from pelagos.services.errors import Conflict

    me = service.ctx.node.id
    service.local_dry_run = lambda series, source: answer(me, dhcp4("ns1"))
    service.peers = Peers({"node-b": lambda name, body: answer("node-b", dhcp4("ns2"))})
    with kms._ANALYZE_LOCK, pytest.raises(Conflict):
        service.analyze({"series": "3.2", "source": "isc"}, "admin")

    def boom(report: dict) -> None:
        raise OSError("disk full")

    service._keep = boom
    with pytest.raises(OSError):
        service.analyze({"series": "3.2", "source": "isc"}, "admin")
    [entry] = [e for e in service.ctx.audit_log.read() if e.action == "kea.migration.analyze"]
    assert entry.result is AuditResult.ERROR and "disk full" in entry.response["error"]


def test_an_open_file_divergence_is_reported(service):
    me = service.ctx.node.id
    service.local_dry_run = lambda series, source: answer(me, dhcp4("ns1"))
    service.peers = Peers({"node-b": lambda name, body: answer("node-b", dhcp4("ns2"))})
    alert = SimpleNamespace(node_id="node-b", state=None, details={"path": "/etc/kea/kea-dhcp4.conf"})
    service.alerts = SimpleNamespace(
        open_by_subject=lambda kind, subject: [alert] if subject == "kea4:config-file" else []
    )
    report = service.analyze({"series": "3.2", "source": "isc"}, "admin")
    [f] = [f for f in report["findings"] if f["code"] == "config_diverged"]
    assert f["severity"] == "info" and f["node_id"] == "node-b" and f["engine"] == "kea4"
    assert f["message"]["params"]["file"] == "/etc/kea/kea-dhcp4.conf"


def test_an_unused_engine_is_info_and_gates_nothing(service):
    me = service.ctx.node.id
    state = {"active": "inactive", "enabled": "disabled"}

    def units(node_id: str) -> dict[str, Any]:
        used = not (state["active"] == "inactive" and state["enabled"] == "disabled")
        return {"kea4": {"unit": "kea-dhcp4-server.service", **state, "used": used}}

    def mine(series: str, source: str) -> dict[str, Any]:
        a = answer(me, dhcp4("ns1"))
        error = {"version": "3.2.1", "error": "hook missing"}
        failed = mig.Finding("blocking", "validation_failed", "kea4", "", error, "manual", None, me)
        a["findings"].append(failed.to_dict())
        a["units"] = units(me)
        return a

    other = dhcp4("ns2")
    for hook in other["Dhcp4"]["hooks-libraries"]:
        for rel in (hook.get("parameters") or {}).get("high-availability") or []:
            rel["max-response-delay"] = 60000
    service.local_dry_run = mine
    service.peers = Peers(
        {"node-b": lambda name, body: {**answer("node-b", other), "units": units("node-b")}}
    )
    report = service.analyze({"series": "3.2", "source": "isc"}, "admin")
    assert not report["blocking"] and report["counts"]["blocking"] == 0
    # No used daemon on any node: nothing restarts.
    assert report["outage_estimate_seconds"] == 0
    assert not [f for f in report["findings"] if f["code"] == "ha_asymmetric"]
    [failed] = [f for f in report["findings"] if f["code"] == "validation_failed"]
    assert failed["severity"] == "info" and failed["unused"] and failed["severity_if_used"] == "blocking"
    idle = [f for f in report["findings"] if f["code"] == "engine_unused"]
    assert [f["node_id"] for f in idle] == [me, "node-b"]
    assert idle[0]["message"]["params"] == {
        "engine": "kea4",
        "node": service.ctx.node.name,
        "unit": "kea-dhcp4-server.service",
        "active": "inactive",
        "enabled": "disabled",
    }
    assert all(f["severity"] == "info" for f in report["findings"] if f.get("unused"))
    assert report["units"][me]["kea4"]["used"] is False
    # Enabled but stopped, or running but not enabled: used, its findings gate again.
    for active, enabled in (("inactive", "enabled"), ("active", "disabled"), ("unknown", "unknown")):
        state.update(active=active, enabled=enabled)
        report = service.analyze({"series": "3.2", "source": "isc"}, "admin")
        assert report["blocking"] and report["counts"]["blocking"] == 2
        assert report["outage_estimate_seconds"] == kms.OUTAGE_HA_SECONDS
        assert not [f for f in report["findings"] if f.get("unused") or f["code"] == "engine_unused"]
