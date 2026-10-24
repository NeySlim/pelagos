# SPDX-License-Identifier: Apache-2.0
"""Two live nodes on localhost over real mTLS: enrollment, push on write, pull, tie-break, revocation."""

from __future__ import annotations

import os
import socket
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import pytest

from pelagos.core import ca as ca_mod
from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.config_store import ConfigStore, NodeConfig
from pelagos.core.context import NodeContext, read_replication_state
from pelagos.core.enrollment import EnrollError, EnrollRequest, enroll_node
from pelagos.core.paths import Paths
from pelagos.core.repl_http import pinned_context, request_json
from pelagos.core.replication import (
    ReplicationClient,
    ReplicationError,
    ReplicationServer,
    ReplicationService,
    client_ssl_context,
)
from pelagos.domain import AuditEntry, Change, ChangeOp, Engine, NodeApplyResult, Plan, PlanScope, Role, User
from pelagos.domain.common import new_id, utcnow
from tests.fixtures.ports import free_port, wait_for

pytestmark = pytest.mark.unit

PW = "Fixture-Admin-Password-1"


@dataclass
class LiveNode:
    paths: Paths
    ctx: NodeContext
    service: ReplicationService

    @property
    def id(self) -> str:
        return self.ctx.node.id

    @property
    def url(self) -> str:
        return self.ctx.node.replication_url

    def restart(self) -> None:
        self.service.stop()
        self.service = ReplicationService(self.ctx, peer_poll_seconds=300)
        self.service.start()


class Cluster:
    """Creates nodes on demand and stops every service at teardown."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.nodes: list[LiveNode] = []

    def first(self, name: str = "ns1") -> LiveNode:
        port = free_port()
        paths = dev_paths(self.root / name)
        bootstrap_first_node(
            paths,
            name=name,
            admin_password=PW,
            replication_url=f"https://127.0.0.1:{port}",
            engines={"bind": True, "kea4": True},
        )
        _set_listen(paths, port)
        return self._start(paths)

    def enroll(self, issuer: LiveNode, name: str = "ns2", ca: bool = False) -> LiveNode:
        port = free_port()
        paths = dev_paths(self.root / name)
        paths.ensure()
        store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")
        store.save_node(
            NodeConfig(
                id=new_id(),
                name=name,
                replication_listen=f"127.0.0.1:{port}",
                replication_url=f"https://127.0.0.1:{port}",
                web_url=f"https://{name}.example.lan:8443",
                engines={"bind": True},
            )
        )
        token = issuer.service.enrollment.issue_token(f"user:admin@node:{issuer.id}", ca=ca)
        enroll_node(
            paths, url=token["url"], token=token["token"], ca_fingerprint=token["ca_fingerprint"], name=name
        )
        return self._start(paths)

    def _start(self, paths: Paths) -> LiveNode:
        ctx = NodeContext.build(paths)
        service = ReplicationService(ctx, peer_poll_seconds=300)
        service.start()
        node = LiveNode(paths, ctx, service)
        self.nodes.append(node)
        return node

    def stop_all(self) -> None:
        for node in self.nodes:
            node.service.stop()


def _set_listen(paths: Paths, port: int) -> None:
    store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")
    node = store.load_node()
    node.replication_listen = f"127.0.0.1:{port}"
    store.save_node(node)


@pytest.fixture
def cluster(tmp_root: Path) -> Iterator[Cluster]:
    c = Cluster(tmp_root)
    try:
        yield c
    finally:
        c.stop_all()


@pytest.fixture
def pair(cluster: Cluster) -> tuple[LiveNode, LiveNode]:
    a = cluster.first()
    b = cluster.enroll(a)
    return a, b


def _entry(node: LiveNode, action: str) -> AuditEntry:
    return AuditEntry(node_id=node.id, action=action, target="zone:example.lan.", user="alice")


def _same_audit(a: LiveNode, b: LiveNode) -> bool:
    return a.ctx.audit_log.head() == b.ctx.audit_log.head()


# Enrollment ---------------------------------------------------------------


def test_enroll_second_node(pair):
    a, b = pair
    assert (b.paths.pki_dir / "node.crt").exists() and (b.paths.pki_dir / "ca.crt").exists()
    assert not (b.paths.pki_dir / "ca.key").exists()
    assert b.paths.master_key.read_text() == a.paths.master_key.read_text()
    assert oct(b.paths.master_key.stat().st_mode & 0o777) == "0o600"
    assert ca_mod.node_id_from_cert((b.paths.pki_dir / "node.crt").read_bytes()) == b.id
    cfg_a, cfg_b = a.ctx.cluster(), b.ctx.cluster()
    assert {n.id for n in cfg_a.nodes} == {a.id, b.id}
    assert cfg_a.version == 2 and cfg_b.version == 2
    peer_b = cfg_a.peer(b.id)
    assert peer_b.url == b.url and peer_b.modules.bind is True and peer_b.modules.kea4 is False
    assert peer_b.enrolled_by == f"user:admin@node:{a.id}"
    # B pulled the audit log on start, including the enrollment entry written by A.
    actions = [e.action for e in b.ctx.audit_log.read()]
    assert "admin.node.enroll" in actions
    assert _same_audit(a, b)
    assert read_replication_state(a.paths) == "ready" and b.ctx.replication_state == "ready"


def test_enroll_with_ca_flag_hands_over_the_ca_key(cluster):
    a = cluster.first()
    c = cluster.enroll(a, name="ns3", ca=True)
    assert (c.paths.pki_dir / "ca.key").read_bytes() == (a.paths.pki_dir / "ca.key").read_bytes()
    assert c.service.enrollment.can_issue()


def test_token_is_single_use_and_expires(cluster, tmp_root):
    a = cluster.first()
    issued = a.service.enrollment.issue_token("user:admin")
    tokens = a.service.enrollment.tokens
    assert tokens.pending() == 1
    rec = tokens.consume(issued["token"])
    assert rec is not None and rec.created_by == "user:admin"
    assert tokens.consume(issued["token"]) is None
    short = a.service.enrollment.issue_token("user:admin", ttl_seconds=1)
    rec = tokens._load()[tokens._hash(short["token"])]
    rec.expires_at = utcnow() - timedelta(seconds=1)
    tokens._save({rec.token_hash: rec})
    assert tokens.consume(short["token"]) is None
    assert tokens.pending() == 0
    # A consumed or unknown token is refused with 403 and leaves a DENIED audit entry.
    paths = dev_paths(tmp_root / "ns9")
    with pytest.raises(EnrollError) as err:
        enroll_node(
            paths, url=a.url, token=issued["token"], ca_fingerprint=issued["ca_fingerprint"], name="ns9"
        )
    assert err.value.code == "invalid_token"
    assert not paths.cluster_toml.exists()
    denied = [e for e in a.ctx.audit_log.read() if e.result.value == "denied"]
    assert denied and denied[0].action == "admin.node.enroll"


def test_anonymous_enroll_failures_do_not_flood_the_audit_log(cluster):
    a = cluster.first()
    svc = a.service.enrollment
    _key, csr = ca_mod.node_csr(new_id(), "ns9", ["ns9"])
    bogus = _enroll_request("nope", csr.decode())

    def denied() -> int:
        return sum(1 for e in a.ctx.audit_log.read() if e.result.value == "denied")

    for _ in range(5):
        with pytest.raises(EnrollError):
            svc.enroll(bogus, "192.0.2.50")
    assert denied() == 1
    with pytest.raises(EnrollError):
        svc.enroll(bogus, "192.0.2.51")
    assert denied() == 2


def test_invalid_enroll_request_does_not_burn_the_token(cluster):
    a = cluster.first()
    svc = a.service.enrollment
    issued = svc.issue_token("user:admin")
    with pytest.raises(EnrollError) as err:
        svc.enroll(_enroll_request(issued["token"], "garbage"))
    assert err.value.code == "validation_error"
    # A CSR for an already enrolled id is refused too, and the token survives both.
    _key, csr = ca_mod.node_csr(a.id, "ns1", ["ns1"])
    with pytest.raises(EnrollError) as err:
        svc.enroll(_enroll_request(issued["token"], csr.decode()))
    assert err.value.code == "conflict"
    assert svc.tokens.pending() == 1


def _enroll_request(token: str, csr_pem: str) -> EnrollRequest:
    return EnrollRequest.from_dict(
        {"token": token, "name": "ns9", "csr_pem": csr_pem, "url": "https://192.0.2.9:8444"}
    )


def test_wrong_ca_fingerprint_is_refused_before_sending_the_token(cluster, tmp_root):
    a = cluster.first()
    issued = a.service.enrollment.issue_token("user:admin")
    with pytest.raises(EnrollError) as err:
        enroll_node(
            dev_paths(tmp_root / "x"), url=a.url, token=issued["token"], ca_fingerprint="sha256:00", name="x"
        )
    assert err.value.code == "fingerprint_mismatch"
    assert a.service.enrollment.tokens.pending() == 1  # the token was never sent


def test_enroll_cli(cluster, tmp_root, monkeypatch):
    from pelagos.cli import main

    a = cluster.first()
    issued = a.service.enrollment.issue_token("user:admin")
    home = tmp_root / "cli"
    port = free_port()
    rc = main(
        [
            "--home",
            str(home),
            "enroll",
            "--url",
            issued["url"],
            "--token",
            issued["token"],
            "--ca-fingerprint",
            issued["ca_fingerprint"],
            "--name",
            "ns4",
            "--replication-url",
            f"https://127.0.0.1:{port}",
            "--engines",
            "bind,d2",
        ]
    )
    monkeypatch.delenv("PELAGOS_HOME", raising=False)
    assert rc == 0
    paths = dev_paths(home)
    assert paths.cluster_toml.exists() and paths.master_key.exists()
    store = ConfigStore(paths.node_toml, paths.cluster_toml)
    node = store.load_node()
    assert node.name == "ns4" and node.engines == {"bind": True, "kea4": False, "kea6": False, "d2": True}
    assert a.ctx.cluster().peer(node.id).modules.d2 is True
    # Enrolling again on an initialized tree is refused; missing options are a usage error.
    issued2 = a.service.enrollment.issue_token("user:admin")
    again = ["--home", str(home), "enroll", "--url", issued2["url"], "--token", issued2["token"]]
    assert main([*again, "--ca-fingerprint", issued2["ca_fingerprint"]]) == 1
    assert main(again) == 2
    monkeypatch.delenv("PELAGOS_HOME", raising=False)


# Replication ----------------------------------------------------------------


def test_push_on_write_through_collector_socket(pair):
    a, b = pair
    a.ctx.config_store.update_cluster(
        lambda c: c.users.append(User(id="u2", username="bob", password_hash="x", roles=["viewer"])),
        updated_by=f"user:admin@node:{a.id}",
    )
    wait_for(lambda: b.ctx.cluster().version == a.ctx.cluster().version, timeout=10, what="config push")
    assert b.ctx.cluster().user("bob") is not None
    b.ctx.audit_log.append(_entry(b, "dns.rrset.add"))
    a.ctx.audit_log.append(_entry(a, "dns.rrset.delete"))
    wait_for(lambda: _same_audit(a, b), timeout=10, what="audit push both ways")
    assert {e.action for e in a.ctx.audit_log.read()} >= {"dns.rrset.add", "dns.rrset.delete"}


def test_offline_peer_pulls_the_diff_on_return(pair):
    a, b = pair
    b.service.stop()
    a.ctx.config_store.update_cluster(
        lambda c: c.roles.append(Role(name="ops", permissions=["read:dns"])), updated_by=f"node:{a.id}"
    )
    for i in range(3):
        a.ctx.audit_log.append(_entry(a, f"dns.rrset.add{i}"))
    # The collector.sock datagrams reach A's listener, and its worker pushes and fails.
    wait_for(lambda: a.service._pending, timeout=5, what="write signalled")
    statuses = a.service.replicator.statuses
    wait_for(lambda: not statuses[b.id].reachable, timeout=10, what="failed push recorded")
    assert a.service._pending, "the push must stay pending while the peer is down"
    assert statuses[b.id].error
    assert b.ctx.cluster().version < a.ctx.cluster().version

    b.restart()  # pull on start
    assert b.ctx.cluster().version == a.ctx.cluster().version
    assert any(r.name == "ops" for r in b.ctx.cluster().roles)
    assert _same_audit(a, b)
    # The pending push on A succeeds once B is back (B's pull woke it), and the retry state clears.
    wait_for(lambda: not a.service._pending, timeout=10, what="pending push retried")
    assert a.service.replicator.statuses[b.id].reachable


def test_anti_entropy_catches_interleaved_audit(pair):
    a, b = pair
    b.service.stop()
    # Both nodes write while disconnected; B's entries sort before A's by ULID time.
    b.ctx.audit_log.append(_entry(b, "written.on.b"))
    a.ctx.audit_log.append(_entry(a, "written.on.a"))
    b.restart()
    assert _same_audit(a, b)
    assert {e.action for e in a.ctx.audit_log.read()} >= {"written.on.a", "written.on.b"}
    # Failed pushes do not count as polls, and B contacting A wakes A's pending push.
    assert a.service.replicator.offline_peers() == []
    wait_for(lambda: not a.service._pending, timeout=10, what="pending push retried after B returned")
    assert a.service.replicator.statuses[b.id].reachable


def test_peer_offline_after_three_failed_polls(pair):
    a, b = pair
    b.service.stop()
    for _ in range(2):
        a.service.replicator.pull_all()
    assert a.service.replicator.offline_peers() == []
    a.service.replicator.pull_all()
    assert a.service.replicator.offline_peers() == [b.id]
    b.restart()
    a.service.replicator.pull_all()
    assert a.service.replicator.offline_peers() == []


def test_tie_break_rule(pair):
    a, b = pair
    cfg_a, cfg_b = a.ctx.cluster(), b.ctx.cluster()
    assert cfg_a.version == cfg_b.version
    # Same version written independently: B's is newer, so A must adopt it and B must refuse A's.
    cfg_a.version = cfg_b.version = cfg_a.version + 1
    cfg_a.updated_at = utcnow() - timedelta(seconds=30)
    cfg_b.updated_at = utcnow()
    cfg_a.modules["advanced_editor"] = False
    cfg_b.modules["dhcpv6"] = True
    a.paths.cluster_toml.write_text(cfg_a.dumps())
    b.paths.cluster_toml.write_text(cfg_b.dumps())
    statuses = a.service.replicator.pull_all()
    assert statuses[0].reachable and statuses[0].config_adopted is True
    assert a.ctx.cluster().modules == {"dhcpv6": True, "advanced_editor": True}
    assert b.ctx.cluster().modules == {"dhcpv6": True, "advanced_editor": True}
    # Same version and timestamp: the lexically greater updated_by wins.
    cfg_a, cfg_b = a.ctx.cluster(), b.ctx.cluster()
    cfg_a.version = cfg_b.version = cfg_a.version + 1
    cfg_a.updated_at = cfg_b.updated_at = utcnow()
    cfg_a.updated_by, cfg_b.updated_by = "node:zzz", "node:aaa"
    cfg_a.settings["plan_ttl_seconds"] = 111
    cfg_b.settings["plan_ttl_seconds"] = 222
    a.paths.cluster_toml.write_text(cfg_a.dumps())
    b.paths.cluster_toml.write_text(cfg_b.dumps())
    b.service.replicator.pull_all()
    assert a.ctx.cluster().settings["plan_ttl_seconds"] == 111
    assert b.ctx.cluster().settings["plan_ttl_seconds"] == 111


def test_revoked_node_is_refused(pair):
    a, b = pair
    client_to_a = ReplicationClient(b.ctx.cluster().peer(a.id), b.service.client_context)
    assert client_to_a.status().reachable
    peer = a.service.enrollment.revoke(b.id, f"user:admin@node:{a.id}")
    cfg = a.ctx.cluster()
    assert cfg.peer(b.id) is None and peer.cert_fingerprint in cfg.revoked
    with pytest.raises(ReplicationError) as err:
        client_to_a.status()
    assert err.value.status == 403 and err.value.code == "revoked"
    assert any(e.action == "admin.node.revoke" for e in a.ctx.audit_log.read())
    with pytest.raises(EnrollError):
        a.service.enrollment.revoke(a.id, "user:admin")


def test_unknown_or_missing_client_certificate(pair, tmp_root):
    a, b = pair
    ca = ca_mod.KeyPair((a.paths.pki_dir / "ca.key").read_bytes(), (a.paths.pki_dir / "ca.crt").read_bytes())
    stranger = new_id()
    key_pem, csr = ca_mod.node_csr(stranger, "stranger", ["stranger"])
    (tmp_root / "s.key").write_bytes(key_pem)
    (tmp_root / "s.crt").write_bytes(ca_mod.sign_node(ca, csr))
    ctx = client_ssl_context(a.paths.pki_dir / "ca.crt", tmp_root / "s.crt", tmp_root / "s.key")
    with pytest.raises(ReplicationError) as err:
        ReplicationClient(b.ctx.cluster().peer(a.id), ctx).status()
    assert err.value.status == 403 and err.value.code == "unknown_node"
    anonymous = request_json(a.url, "GET", "/repl/v1/status", ssl_context=pinned_context(ca.cert_pem))
    assert anonymous.status == 401 and anonymous.body["code"] == "client_certificate_required"
    public = request_json(a.url, "GET", "/repl/v1/ca", ssl_context=pinned_context(ca.cert_pem))
    assert public.status == 200 and ca_mod.same_fingerprint(
        public.body["ca_fingerprint"], ca_mod.fingerprint(ca.cert_pem)
    )
    # A peer presenting the certificate of another node than the one in [[nodes]] is refused by the client.
    wrong = b.ctx.cluster().peer(a.id).replace(id=stranger)
    with pytest.raises(ReplicationError, match="presented node"):
        ReplicationClient(wrong, b.service.client_context).status()


# Plans and snapshots --------------------------------------------------------------


class FakeBindBackend:
    def __init__(self, fail: bool = False) -> None:
        self.applied: list[str] = []
        self.rolled: list[str] = []
        self.fail = fail

    def apply(self, plan: Plan) -> NodeApplyResult:
        if self.fail:
            raise RuntimeError("named-checkconf: syntax error")
        self.applied.append(plan.id)
        return NodeApplyResult(node_id="", ok=True, message="UPDATE sent")

    def rollback(self, plan: Plan) -> NodeApplyResult:
        self.rolled.append(plan.id)
        return NodeApplyResult(node_id="", ok=True, message="inverse UPDATE sent")

    def snapshot(self) -> dict:
        return {"zones": ["example.lan."]}


def _plan(node: LiveNode) -> Plan:
    change = Change(ChangeOp.ADD, "example.lan./www/A", after={"ttl": 300, "rdata": ["192.0.2.10"]})
    return Plan(
        scope=PlanScope.DNS_RRSET,
        node_id=node.id,
        summary="add www",
        created_by="alice",
        engine=Engine.BIND,
        changes=[change],
        diff="+www.example.lan. 300 IN A 192.0.2.10",
    )


def test_remote_plan_apply_rollback_and_snapshot(pair):
    a, b = pair
    backend = FakeBindBackend()
    b.service.registry.register(Engine.BIND, backend)
    client = ReplicationClient(a.ctx.cluster().peer(b.id), a.service.client_context)
    plan = _plan(a)
    result = client.apply_plan(plan)
    assert result.ok and result.node_id == b.id and backend.applied == [plan.id]
    assert len(result.audit_ids) == 1
    entry = b.ctx.audit_log.get(result.audit_ids[0])
    assert entry.action == "dns.rrset.apply" and entry.user == f"node:{a.id}" and entry.plan_id == plan.id
    rolled = client.rollback_plan(plan)
    assert rolled.ok and backend.rolled == [plan.id]
    snap = client.engine_snapshot("bind")
    assert snap["zones"] == ["example.lan."] and snap["node_id"] == b.id
    with pytest.raises(ReplicationError) as err:
        client.engine_snapshot("kea4")
    assert err.value.status == 404
    # A failing connector becomes a failed NodeApplyResult, never a 500.
    b.service.registry.register(Engine.BIND, FakeBindBackend(fail=True))
    failed = client.apply_plan(_plan(a))
    assert failed.ok is False and "syntax error" in failed.message
    assert b.ctx.audit_log.get(failed.audit_ids[0]).result.value == "error"
    # Engine the node does not run.
    kea_plan = _plan(a).replace(engine=Engine.KEA4, scope=PlanScope.DHCP_SUBNET)
    assert client.apply_plan(kea_plan).ok is False


# Certificates -----------------------------------------------------------------------


def test_certificate_renewal_through_a_peer_and_locally(pair, tmp_root):
    a, b = pair
    ca = ca_mod.KeyPair((a.paths.pki_dir / "ca.key").read_bytes(), (a.paths.pki_dir / "ca.crt").read_bytes())
    enrolled_fp = a.ctx.cluster().peer(b.id).cert_fingerprint
    # Give B a certificate that expires in 10 days.
    csr = ca_mod.csr_for_key((b.paths.pki_dir / "node.key").read_bytes(), b.id, "ns2", ["ns2"])
    short = ca_mod.sign_node(ca, csr, days=10)
    (b.paths.pki_dir / "node.crt").write_bytes(short)
    b.service.reload_certificates()
    assert ca_mod.needs_renewal(short)
    assert b.service.renew_certificate() is True
    renewed = (b.paths.pki_dir / "node.crt").read_bytes()
    assert not ca_mod.needs_renewal(renewed)
    assert ca_mod.cert_not_after(renewed) > utcnow() + timedelta(days=700)
    assert a.ctx.cluster().peer(b.id).cert_fingerprint == ca_mod.fingerprint(renewed)
    # The replaced certificate is revoked; the renewal is audited with the op verb.
    assert enrolled_fp and enrolled_fp in a.ctx.cluster().revoked
    renew_entry = [e for e in a.ctx.audit_log.read() if e.action == "admin.node.op"][-1]
    assert renew_entry.request == {"op": "renew"}
    # The new certificate is used on the next connection.
    assert ReplicationClient(b.ctx.cluster().peer(a.id), b.service.client_context).status().reachable
    assert b.service.renew_certificate() is False
    # The CA holder renews itself.
    before = (a.paths.pki_dir / "node.crt").read_bytes()
    assert a.service.renew_certificate(force=True) is True
    after = (a.paths.pki_dir / "node.crt").read_bytes()
    assert after != before and a.ctx.cluster().peer(a.id).cert_fingerprint == ca_mod.fingerprint(after)
    assert ca_mod.fingerprint(before) in a.ctx.cluster().revoked
    assert ReplicationClient(a.ctx.cluster().peer(b.id), a.service.client_context).status().reachable
    # Once B has adopted that config, A's previous certificate no longer authenticates.
    wait_for(lambda: ca_mod.fingerprint(before) in b.ctx.cluster().revoked, timeout=10, what="revocation")
    (tmp_root / "old.crt").write_bytes(before)
    old_ctx = client_ssl_context(
        a.paths.pki_dir / "ca.crt", tmp_root / "old.crt", a.paths.pki_dir / "node.key"
    )
    with pytest.raises(ReplicationError) as err:
        ReplicationClient(a.ctx.cluster().peer(b.id), old_ctx).status()
    assert err.value.code == "revoked"


# Robustness -----------------------------------------------------------------------


def test_malformed_peer_answers_never_escape_the_replicator(pair, monkeypatch):
    a, b = pair
    a.ctx.audit_log.append(_entry(a, "dns.rrset.add"))
    monkeypatch.setattr(
        b.service.app, "_get_audit", lambda _q: (200, {"entries": [{"bogus": True}], "next": None})
    )
    peer_b = a.ctx.cluster().peer(b.id)
    replicator = a.service.replicator
    for call in (lambda: replicator.sync_peer(peer_b), lambda: replicator.push_all()[0]):
        status = call()
        assert status.reachable is False and status.error
    monkeypatch.setattr(b.service.app, "config_payload", lambda: {"version": 99})
    monkeypatch.setattr(
        b.service.app, "status_payload", lambda: {"node_id": b.id, "config_version": 99, "audit_count": 0}
    )
    assert replicator.sync_peer(peer_b).reachable is False


def test_run_once_backs_off_when_the_replicator_raises(pair, monkeypatch):
    a, _b = pair
    svc = a.service

    def boom(*_args, **_kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(svc.replicator, "push_all", boom)
    monkeypatch.setattr(svc.replicator, "pull_all", boom)
    with svc._lock:
        svc._pending.add("audit")
        svc._retry_at = 0.0
    svc._next_poll = 0.0
    svc.run_once()  # must not raise
    assert svc._pending and svc._retry_at is not None and svc._retry_at > time.monotonic()
    assert svc._next_poll > time.monotonic() + 100


def test_newer_schema_on_a_peer_is_a_divergence_not_an_outage(pair, monkeypatch):
    a, b = pair
    toml_text = b.paths.cluster_toml.read_text()
    newer = "schema_version = 99\n" + "\n".join(
        line for line in toml_text.splitlines() if not line.startswith("schema_version")
    )
    real_status = b.service.app.status_payload

    def status_payload():
        data = real_status()
        data["config_version"] += 5
        return data

    monkeypatch.setattr(b.service.app, "status_payload", status_payload)
    monkeypatch.setattr(b.service.app, "config_payload", lambda: {"version": 0, "toml": newer})
    replicator = a.service.replicator
    status = replicator.sync_peer(a.ctx.cluster().peer(b.id))
    assert status.reachable is True and status.code == "schema_mismatch"
    assert status.to_dict()["code"] == "schema_mismatch"
    assert replicator.failures[b.id] == 0 and replicator.offline_peers() == []


def test_replication_server_binds_ipv6_brackets(pair):
    a, _b = pair
    if not socket.has_ipv6:
        pytest.skip("no IPv6")
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::1", 0))
            port = s.getsockname()[1]
    except OSError:
        pytest.skip("no IPv6 loopback")
    server = ReplicationServer(a.service.app, f"[::1]:{port}", a.service.server_context)
    server.start()
    try:
        assert server.address[0] == "::1" and server.url == f"https://[::1]:{port}"
        peer = a.ctx.cluster().peer(a.id).replace(url=server.url)
        assert ReplicationClient(peer, a.service.client_context).status().node_id == a.id
    finally:
        server.stop()


def test_housekeeping_purges_old_backups_and_tokens(cluster):
    a = cluster.first()
    old = a.paths.backups_dir / "bind" / "20200101T000000000000Z-01JBOLD"
    new = a.paths.backups_dir / "bind" / (utcnow().strftime("%Y%m%dT%H%M%S%fZ") + "-01JBNEW")
    for d in (old, new):
        d.mkdir(parents=True)
        (d / "manifest.json").write_text("{}")
    tokens = a.service.enrollment.tokens
    issued = a.service.enrollment.issue_token("user:admin", ttl_seconds=1)
    rec = tokens._load()[tokens._hash(issued["token"])]
    rec.expires_at = utcnow() - timedelta(seconds=1)
    tokens._save({rec.token_hash: rec})
    assert a.service.housekeeping() == [old]
    assert new.exists() and not old.exists()
    assert tokens._load() == {}


def test_replication_state_file(pair):
    a, _b = pair
    assert a.paths.replication_state_file.read_text().strip() == "ready"
    assert a.ctx.replication_state == "ready"
    a.ctx.replication_state_override = "syncing"
    assert a.ctx.replication_state == "syncing"
    a.ctx.replication_state_override = None
    a.service.stop()
    assert not a.paths.replication_state_file.exists()
    assert read_replication_state(a.paths) == "ready"
    assert not os.path.exists(a.paths.collector_sock)
