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
from types import SimpleNamespace

import pytest

from pelagos.collector.events import SignalListener
from pelagos.core import ca as ca_mod
from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.config_store import ConfigStore, NodeConfig
from pelagos.core.context import (
    SYNCING_STALE_SECONDS,
    NodeContext,
    read_replication_state,
    write_replication_state,
)
from pelagos.core.enrollment import EnrollError, EnrollRequest, enroll_node
from pelagos.core.paths import Paths
from pelagos.core.repl_http import pinned_context, request_json
from pelagos.core.replication import (
    ReplicationClient,
    ReplicationError,
    ReplicationServer,
    ReplicationService,
    client_ssl_context,
    start_collector_side,
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

    monkeypatch.setattr("pelagos.core.enrollment.check_free", lambda *_: None)  # default ports may be busy
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


def test_collector_hook_shares_the_collector_listener(cluster, tmp_root):
    a = cluster.first()
    b = cluster.enroll(a)
    a.service.stop()
    listener = SignalListener(a.paths.collector_sock)
    listener.open()
    handle = start_collector_side(a.ctx, listener, None)
    try:
        assert handle.service.listener is None
        a.service = handle.service
        a.ctx.config_store.update_cluster(
            lambda c: c.users.append(User(id="u3", username="carol", password_hash="x", roles=["viewer"])),
            updated_by=f"user:admin@node:{a.id}",
        )
        wait_for(
            lambda: listener.wait(0.2) is not None and b.ctx.cluster().version == a.ctx.cluster().version,
            timeout=10,
            what="config push via collector listener",
        )
    finally:
        handle.close()
        listener.close()
    with pytest.raises(NotImplementedError):
        start_collector_side(SimpleNamespace(paths=dev_paths(tmp_root / "bare")), listener, None)


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


def _write(node: LiveNode, mutate) -> None:
    node.ctx.config_store.update_cluster(mutate, updated_by=f"user:admin@node:{node.id}")


def _same_config(*nodes: LiveNode) -> bool:
    return len({n.ctx.config_store.digest() for n in nodes}) == 1


def test_concurrent_writes_on_two_nodes_are_both_kept(pair):
    """The lost write of the former last-writer-wins rule: one write on each node in the same window."""
    a, b = pair
    assert _same_config(a, b)
    b.service.stop()
    _write(a, lambda c: c.users.append(User(id=new_id(), username="bob", password_hash="x")))
    _write(b, lambda c: c.settings.__setitem__("plan_ttl_seconds", 321))
    cfg_a, cfg_b = a.ctx.cluster(), b.ctx.cluster()
    # Same version on both sides: the former rule kept one file whole and dropped the other write.
    assert cfg_a.version == cfg_b.version
    legacy = cfg_a if cfg_a.wins_over(cfg_b) else cfg_b
    assert legacy.user("bob") is None or legacy.settings["plan_ttl_seconds"] != 321

    b.restart()  # pull (and push) on start
    for node in (a, b):
        cfg = node.ctx.cluster()
        assert cfg.user("bob") is not None and cfg.settings["plan_ttl_seconds"] == 321
    assert _same_config(a, b)
    assert a.ctx.cluster().version == b.ctx.cluster().version > cfg_a.version


def test_concurrent_writes_to_the_same_key_resolve_alike_everywhere(pair):
    a, b = pair
    b.service.stop()
    _write(a, lambda c: c.settings.__setitem__("plan_ttl_seconds", 111))
    _write(b, lambda c: c.settings.__setitem__("plan_ttl_seconds", 222))
    # Same counter on both: the greater node id wins, on whichever node merges.
    expected = 111 if a.id > b.id else 222
    b.restart()
    assert a.ctx.settings()["plan_ttl_seconds"] == expected
    assert b.ctx.settings()["plan_ttl_seconds"] == expected
    # A later write wins over both, whoever made the earlier ones.
    _write(b, lambda c: c.settings.__setitem__("plan_ttl_seconds", 333))
    wait_for(lambda: a.ctx.settings()["plan_ttl_seconds"] == 333, timeout=10, what="push of the newer write")
    assert _same_config(a, b)


def test_deletions_are_tombstoned_and_beat_concurrent_edits(pair):
    a, b = pair
    _write(a, lambda c: c.roles.append(Role(name="ops", permissions=["read:dns"])))
    _write(a, lambda c: c.secrets.__setitem__("tsig/old", "enc:v1:x"))
    wait_for(lambda: _same_config(a, b), timeout=10, what="role replicated")
    b.service.stop()
    _write(a, lambda c: setattr(c, "roles", [r for r in c.roles if r.name != "ops"]))
    _write(a, lambda c: c.secrets.pop("tsig/old"))
    # B edits the role A deleted and adds a module switch, all while disconnected.
    _write(b, lambda c: setattr(next(r for r in c.roles if r.name == "ops"), "description", "edited"))
    _write(b, lambda c: c.modules.__setitem__("dhcpv6", True))
    _write(b, lambda c: c.settings.__setitem__("plan_ttl_seconds", 700))
    b.restart()
    for node in (a, b):
        cfg = node.ctx.cluster()
        assert all(r.name != "ops" for r in cfg.roles), "the deleted role came back"
        assert "tsig/old" not in cfg.secrets
        assert cfg.modules["dhcpv6"] is True and cfg.settings["plan_ttl_seconds"] == 700
    assert _same_config(a, b)
    # A record created again after its deletion is live again.
    _write(b, lambda c: c.roles.append(Role(name="ops", permissions=["read:dhcp"])))
    wait_for(lambda: any(r.name == "ops" for r in a.ctx.cluster().roles), timeout=10, what="re-created role")
    assert next(r for r in a.ctx.cluster().roles if r.name == "ops").permissions == ["read:dhcp"]


def test_three_nodes_converge_after_concurrent_writes(cluster):
    a = cluster.first()
    b = cluster.enroll(a, "ns2")
    c = cluster.enroll(a, "ns3")
    for node in (a, b, c):
        node.service.replicator.pull_all()
    assert _same_config(a, b, c)
    for node in (a, b, c):
        node.service.stop()
    _write(a, lambda cfg: cfg.users.append(User(id=new_id(), username="ann", password_hash="x")))
    _write(b, lambda cfg: cfg.roles.append(Role(name="dhcp-ops", permissions=["read:dhcp"])))
    _write(c, lambda cfg: cfg.settings["collector"].__setitem__("poll_seconds", 15))
    _write(c, lambda cfg: cfg.modules.__setitem__("advanced_editor", False))
    for node in (a, b, c):
        node.service = ReplicationService(node.ctx, peer_poll_seconds=300)
        node.service.start(pull=False)
    # Anti-entropy only, in an order where no single exchange sees every write.
    c.service.replicator.pull_all()
    a.service.replicator.pull_all()
    assert _same_config(a, b, c)
    for node in (a, b, c):
        cfg = node.ctx.cluster()
        assert cfg.user("ann") is not None
        assert any(r.name == "dhcp-ops" for r in cfg.roles)
        assert cfg.settings["collector"]["poll_seconds"] == 15
        assert cfg.modules["advanced_editor"] is False
    assert len({n.ctx.cluster().version for n in (a, b, c)}) == 1


def test_recreated_record_does_not_revive_fields_from_an_offline_node(cluster):
    """C is offline while A deletes and re-creates a role: C's old fields must not come back."""
    a = cluster.first()
    b = cluster.enroll(a, "ns2")
    c = cluster.enroll(a, "ns3")
    _write(a, lambda cfg: cfg.roles.append(Role(name="ops", description="old", permissions=["read:dns"])))
    for node in (a, b, c):
        node.service.replicator.pull_all()
    assert _same_config(a, b, c)
    c.service.stop()
    _write(a, lambda cfg: setattr(cfg, "roles", [r for r in cfg.roles if r.name != "ops"]))
    _write(a, lambda cfg: cfg.roles.append(Role(name="ops", permissions=["read:dhcp"])))
    b.service.replicator.pull_all()
    c.restart()
    for node in (a, b, c):
        node.service.replicator.pull_all()
    assert _same_config(a, b, c)
    for node in (a, b, c):
        ops = next(r for r in node.ctx.cluster().roles if r.name == "ops")
        assert ops.description is None and ops.permissions == ["read:dhcp"]


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


def test_a_blocked_handler_does_not_stall_the_other_peers(pair, monkeypatch):
    """Handlers run on OS threads: one waiting on the backend lock leaves /status answering."""
    import threading

    a, b = pair
    release = threading.Event()
    entered = threading.Event()

    def slow_snapshot(engine, kind, params):
        entered.set()
        release.wait(20)
        return {"engine": engine, "kind": kind}

    b.service.app.snapshot = slow_snapshot
    peer_b = a.ctx.cluster().peer(b.id)
    answers: list[dict] = []
    worker = threading.Thread(
        target=lambda: answers.append(
            ReplicationClient(peer_b, a.service.client_context, timeout=30).engine_snapshot("bind", "zones")
        )
    )
    worker.start()
    try:
        assert entered.wait(10)
        started = time.monotonic()
        assert ReplicationClient(peer_b, a.service.client_context, timeout=5).status().reachable
        assert time.monotonic() - started < 5
    finally:
        release.set()
        worker.join(30)
    assert answers == [{"engine": "bind", "kind": "zones"}]


def test_installer_plans_do_not_wait_for_the_backend_lock():
    import threading

    from pelagos.core.registry import ConnectorRegistry

    class Runner:
        def apply(self, plan):
            return NodeApplyResult(node_id="x", ok=True, message=plan.scope.value)

    registry = ConnectorRegistry("n1")
    registry.register(Engine.D2, Runner())
    held, done = threading.Event(), threading.Event()

    def hold():
        with registry.lock:
            held.set()
            done.wait(20)

    holder = threading.Thread(target=hold)
    holder.start()
    try:
        assert held.wait(5)
        plan = Plan(scope=PlanScope.SECURITY, node_id="n2", summary="s", engine=Engine.D2)
        assert registry.apply(plan).ok
    finally:
        done.set()
        holder.join(10)


def test_internal_errors_do_not_leak_details_to_peers(pair, monkeypatch):
    a, b = pair

    def boom():
        raise RuntimeError("/var/lib/pelagos/secret-path exploded")

    monkeypatch.setattr(b.service.app, "status_payload", boom)
    with pytest.raises(ReplicationError) as err:
        ReplicationClient(a.ctx.cluster().peer(b.id), a.service.client_context).status()
    assert err.value.status == 500 and err.value.code == "internal_error"
    assert "secret-path" not in str(err.value)


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
        data["config_digest"] = "sha256:newer"
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
    assert a.paths.replication_state_file.read_text().split()[0] == "ready"
    assert a.ctx.replication_state == "ready"
    a.ctx.replication_state_override = "syncing"
    assert a.ctx.replication_state == "syncing"
    a.ctx.replication_state_override = None
    a.service.stop()
    assert not a.paths.replication_state_file.exists()
    assert read_replication_state(a.paths) == "ready"
    assert not os.path.exists(a.paths.collector_sock)


def test_stale_or_orphan_syncing_state_is_ready(tmp_root):
    paths = dev_paths(tmp_root / "n")
    write_replication_state(paths, "syncing")
    assert read_replication_state(paths) == "syncing"  # this process wrote it and lives
    state = paths.replication_state_file
    state.write_text(f"syncing 999999999 {socket.gethostname()}\n")  # writer gone
    assert read_replication_state(paths) == "ready"
    state.write_text("syncing 999999999 another-host\n")  # another pid namespace: age only
    assert read_replication_state(paths) == "syncing"
    old = time.time() - SYNCING_STALE_SECONDS - 5
    os.utime(state, (old, old))
    assert read_replication_state(paths) == "ready"


def test_long_initial_pull_keeps_the_syncing_state_fresh(pair, monkeypatch):
    """A pull longer than the stale limit still reads `syncing`: the writer refreshes the file."""
    from pelagos.core import context as context_mod

    a, _b = pair
    a.service.stop()
    monkeypatch.setattr(context_mod, "SYNCING_STALE_SECONDS", 0.6)
    monkeypatch.setattr(context_mod, "SYNCING_HEARTBEAT_SECONDS", 0.1)
    seen: list[str] = []
    svc = ReplicationService(a.ctx, peer_poll_seconds=300)

    def slow_pull():
        for _ in range(15):
            time.sleep(0.1)
            seen.append(read_replication_state(a.paths))
        return []

    monkeypatch.setattr(svc.replicator, "pull_all", slow_pull)
    svc.start()
    try:
        assert seen and all(s == "syncing" for s in seen)
        assert read_replication_state(a.paths) == "ready"
    finally:
        svc.stop()


def test_start_failure_leaves_the_node_writable(pair):
    a, _b = pair
    a.service.stop()
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen()
    try:
        svc = ReplicationService(a.ctx, listen=f"127.0.0.1:{busy.getsockname()[1]}", peer_poll_seconds=300)
        with pytest.raises(ReplicationError):
            svc.start()
    finally:
        busy.close()
    assert read_replication_state(a.paths) == "ready"


# Live events and isolation -----------------------------------------------------------


def test_relayed_events_are_checked_and_stamped_with_the_caller(pair):
    a, b = pair
    seen: list[tuple[str, list[dict]]] = []
    b.service.app.on_peer_events = lambda caller, msgs: seen.append((caller, msgs))
    client = ReplicationClient(a.ctx.cluster().peer(b.id), a.service.client_context)
    events = [
        {"topic": "ha", "event": "heartbeat", "node_id": "forged", "data": {"family": "v4"}},
        {"topic": "alerts", "event": "opened", "data": {"id": "x"}},  # not relayable
        {"topic": "zones", "event": "transfer", "data": "not a dict"},
    ]
    assert client.push_events(events) == 1
    assert seen[0][0] == a.id and seen[0][1][0]["node_id"] == a.id and seen[0][1][0]["relayed"] is True
    with pytest.raises(ReplicationError) as err:
        client.push_events([events[0]] * 101)
    assert err.value.status == 400


def test_plan_hook_sees_each_remote_step(pair):
    a, b = pair
    b.service.registry.register(Engine.BIND, FakeBindBackend())
    steps: list[tuple[str, str, str, bool | None]] = []
    b.service.app.on_plan = lambda plan, origin, verb, phase, result: steps.append(
        (origin, verb, phase, None if result is None else result.ok)
    )
    client = ReplicationClient(a.ctx.cluster().peer(b.id), a.service.client_context)
    plan = _plan(a)
    assert client.apply_plan(plan).ok
    assert client.rollback_plan(plan).ok
    assert steps == [
        (a.id, "apply", "running", None),
        (a.id, "apply", "done", True),
        (a.id, "rollback", "running", None),
        (a.id, "rollback", "done", True),
    ]


def test_a_node_every_peer_refuses_reports_isolated(pair):
    a, b = pair
    assert b.service.steady_state() == "ready"
    a.service.enrollment.revoke(b.id, f"user:admin@node:{a.id}")
    b.service._after_exchange(b.service.replicator.pull_all())
    assert b.service.state == "isolated" and read_replication_state(b.paths) == "isolated"
    status = b.service.replicator.statuses[a.id]
    assert status.reachable is False and status.code == "revoked"
    # The remaining node is fine: it simply has no peer left.
    a.service._after_exchange(a.service.replicator.pull_all())
    assert a.service.state == "ready"
