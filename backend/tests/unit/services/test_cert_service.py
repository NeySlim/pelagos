# SPDX-License-Identifier: Apache-2.0
"""Certificates across nodes: one job, one step per node, a failing node does not stop the others;
the peer actions a node serves for another (status, request, check, upload with a sealed key)."""

from __future__ import annotations

import time
from typing import Any

import pytest

from pelagos.core.webcert import checks, manager
from pelagos.core.webcert import config as wc
from pelagos.domain import JobState, Peer
from pelagos.services import cert_service
from pelagos.services.cert_service import CertService
from pelagos.services.errors import ServiceError
from pelagos.services.jobs import JobStore
from pelagos.services.peer_actions import PeerActions
from tests.unit.core.webcert_pki import key_pem_of, make_leaf, make_pki, pem_of, sign_csr

pytestmark = pytest.mark.unit
HOST = "ns1.example.lan"


@pytest.fixture(autouse=True)
def hermetic(monkeypatch, node_ctx):
    monkeypatch.setattr(checks.SYSTEM_TRUST, "roots", lambda: {})
    monkeypatch.setattr(cert_service, "POLL_SECONDS", 0.01)
    node_ctx.node.web_url = f"https://{HOST}:8443"


class FakePeers:
    """Two peers: ns2 issues fine, ns3 fails; actions are answered like a peer's collector."""

    def __init__(self) -> None:
        self.known = {
            "N2": Peer(
                id="N2",
                name="ns2",
                url="https://ns2.example.lan:8444",
                cert_fingerprint="",
                web_url="https://ns2.example.lan:8443",
            ),
            "N3": Peer(
                id="N3",
                name="ns3",
                url="https://ns3.example.lan:8444",
                cert_fingerprint="",
                web_url="https://ns3.example.lan:8443",
            ),
        }
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.jobs: dict[str, dict[str, Any]] = {}

    def peer(self, node_id: str) -> Peer | None:
        return self.known.get(node_id)

    def action(self, peer: Peer, name: str, body: dict[str, Any], timeout: float | None = None) -> Any:
        self.calls.append((peer.name, name, body))
        if name == "certs.run":
            ok = peer.name == "ns2"
            self.jobs[peer.id] = {
                "id": body["job_id"],
                "state": "done" if ok else "failed",
                "error": None if ok else "ACME: rate limited",
            }
            return {"started": True}
        if name == "certs.status":
            return {"job": self.jobs.get(peer.id), "current": {"fingerprint": "sha256:ff"}}
        raise AssertionError(name)


def wait(job, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while job.state in (JobState.QUEUED, JobState.RUNNING) and time.monotonic() < deadline:
        time.sleep(0.02)


def test_apply_to_all_nodes_runs_each_node_and_reports_the_failures(node_ctx, monkeypatch):
    peers = FakePeers()
    for peer in peers.known.values():
        node_ctx.config_store.update_cluster(lambda c, p=peer: c.nodes.append(p), updated_by="test")
    service = CertService(node_ctx, peers, JobStore())
    pki = make_pki()

    def local_issue(src, scope, csr_pem):
        cert = sign_csr(pki.inter, csr_pem)
        return pem_of(cert) + pem_of(pki.inter.cert) + pem_of(pki.root.cert), 7

    monkeypatch.setattr(service.local, "_issue_ucm", local_issue)
    body = {
        "source": "ucm",
        "node_ids": "all",
        "ucm": {"url": "https://ucm.example.lan", "ca_id": 2},
        "secrets": {"ucm_api_key": "k-123456"},
    }
    out = service.set_cluster_source(body, "admin", None)
    job = service.jobs.get(out["job"]["id"])
    wait(job)
    steps = {s["node_id"]: s["state"] for s in job.steps if s["name"].startswith("cert/")}
    assert steps == {node_ctx.node.id: "done", "N2": "done", "N3": "failed"}
    assert job.state is JobState.FAILED and "ns3" in job.error
    # Each peer requested its own certificate; no key travelled.
    runs = [c for c in peers.calls if c[1] == "certs.run"]
    assert [c[0] for c in runs] == ["ns2", "ns3"]
    assert all("key" not in str(c[2]).lower() for c in peers.calls)
    summary = [e for e in node_ctx.audit_log.read() if e.request.get("entry") == "summary"]
    assert summary and summary[-1].result.value == "error"
    # The cluster setting applies to a node enrolled later, by id.
    assert wc.effective(node_ctx.settings(), "N9")[1] == wc.CLUSTER_SCOPE


def test_upload_to_other_nodes_requires_their_names(node_ctx):
    peers = FakePeers()
    for peer in peers.known.values():
        node_ctx.config_store.update_cluster(lambda c, p=peer: c.nodes.append(p), updated_by="test")
    service = CertService(node_ctx, peers, JobStore())
    pki = make_pki()
    leaf, key = make_leaf(pki.inter, [HOST, "ns2.example.lan"])
    body = {
        "cert_pem": pem_of(leaf),
        "chain_pem": pem_of(pki.inter.cert) + pem_of(pki.root.cert),
        "key_pem": key_pem_of(key),
    }
    with pytest.raises(ServiceError, match="ns3"):
        service.upload(node_ctx.node.id, {**body, "also_node_ids": ["N3"]}, "admin", None)
    out = service.upload(node_ctx.node.id, {**body, "also_node_ids": ["N2"]}, "admin", None)
    assert out["also"] == {"ns2": "sent: the node installs it within a minute"}
    cfg = node_ctx.cluster()
    sealed = cfg.secrets[wc.transfer_secret("N2")]
    assert sealed.startswith("enc:v1:") and "PRIVATE" not in node_ctx.paths.cluster_toml.read_text()
    assert cfg.settings["certificates"]["nodes"]["N2"]["transfer"]["from_node"] == node_ctx.node.id


def test_peer_actions_serve_this_nodes_certificate(node_ctx):
    actions = PeerActions(node_ctx, registry=None)
    status = actions("certs.status", {}, "N2")
    assert status["node_id"] == node_ctx.node.id
    request = actions("certs.request", {"key_type": "ec-p256", "names": [], "actor": "admin"}, "N2")
    pki = make_pki()
    cert = sign_csr(pki.inter, request["csr_pem"])
    chain = pem_of(cert) + pem_of(pki.inter.cert) + pem_of(pki.root.cert)
    report = actions("certs.check", {"certs_pem": chain, "use_pending_key": True}, "N2")
    assert report["ok"]
    out = actions("certs.upload", {"certs_pem": chain, "use_pending_key": True, "actor": "admin"}, "N2")
    assert out["installed"] and manager.CertManager(node_ctx).current()[0] == cert
    # A key sent by the caller comes sealed for this node with the master key.
    leaf, key = make_leaf(pki.inter, [HOST])
    sealed = node_ctx.secrets.encrypt(f"certs/upload/{node_ctx.node.id}", key_pem_of(key))
    chain = pem_of(leaf) + pem_of(pki.inter.cert) + pem_of(pki.root.cert)
    out = actions("certs.upload", {"certs_pem": chain, "key_sealed": sealed, "actor": "admin"}, "N2")
    assert out["installed"]
    bad = make_leaf(pki.inter, ["elsewhere.example.lan"])
    sealed = node_ctx.secrets.encrypt(f"certs/upload/{node_ctx.node.id}", key_pem_of(bad[1]))
    out = actions("certs.upload", {"certs_pem": pem_of(bad[0]), "key_sealed": sealed, "actor": "admin"}, "N2")
    assert out["installed"] is False and not out["checks"]["ok"]
