# SPDX-License-Identifier: Apache-2.0
"""Three and four live nodes on localhost over real mTLS: enrollment of a third and a fourth node
(one through a node other than the first), convergence of cluster.toml and the audit log from writes
on every node, catch-up of a node that was down, and removal of a node seen by every other one."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from pelagos.core.replication import ReplicationClient, ReplicationError
from pelagos.domain import Role, User
from pelagos.domain.common import new_id
from tests.fixtures.ports import wait_for
from tests.unit.core.test_replication import Cluster, LiveNode, _entry, _same_audit, _same_config, _write

pytestmark = pytest.mark.unit


@pytest.fixture
def nodes(tmp_root: Path) -> Iterator[Cluster]:
    c = Cluster(tmp_root)
    try:
        yield c
    finally:
        c.stop_all()


def _converge(*nodes: LiveNode) -> None:
    """Two anti-entropy rounds: every node pulls from every peer, then once more."""
    for _ in range(2):
        for node in nodes:
            node.service.replicator.pull_all()


def _four(cluster: Cluster) -> tuple[LiveNode, LiveNode, LiveNode, LiveNode]:
    a = cluster.first("ns1")
    b = cluster.enroll(a, "ns2", ca=True)  # b holds the CA key from now on
    c = cluster.enroll(a, "ns3")
    d = cluster.enroll(b, "ns4")  # enrolled through the second node
    _converge(a, b, c, d)
    return a, b, c, d


def test_third_node_enrolls_and_every_node_knows_every_other(nodes):
    a = nodes.first("ns1")
    b = nodes.enroll(a, "ns2")
    c = nodes.enroll(a, "ns3")
    _converge(a, b, c)
    assert _same_config(a, b, c)
    for node in (a, b, c):
        names = sorted(p.name for p in node.ctx.cluster().nodes)
        assert names == ["ns1", "ns2", "ns3"], (node.ctx.node.name, names)
        statuses = {s.node_id: s for s in node.service.replicator.peer_statuses()}
        assert set(statuses) == {n.id for n in (a, b, c)} - {node.id}
        assert all(s.reachable for s in statuses.values())
    # The third node reaches the second directly, though it enrolled through the first.
    client = ReplicationClient(c.ctx.cluster().peer(b.id), c.service.client_context)
    assert client.status().node_id == b.id


def test_four_nodes_converge_from_writes_on_every_node(nodes):
    a, b, c, d = _four(nodes)
    assert _same_config(a, b, c, d)
    assert len(a.ctx.cluster().nodes) == 4
    _write(a, lambda cfg: cfg.users.append(User(id=new_id(), username="ann", password_hash="x")))
    _write(b, lambda cfg: cfg.roles.append(Role(name="dhcp-ops", permissions=["read:dhcp"])))
    _write(c, lambda cfg: cfg.settings["collector"].__setitem__("poll_seconds", 15))
    _write(d, lambda cfg: cfg.modules.__setitem__("advanced_editor", False))
    for node in (a, b, c, d):
        node.ctx.audit_log.append(_entry(node, f"written.on.{node.ctx.node.name}"))
    # Push on write reaches every peer; anti-entropy settles what crossed in flight.
    wait_for(lambda: _same_config(a, b, c, d) or _converge(a, b, c, d), timeout=20, what="config push")
    _converge(a, b, c, d)
    assert _same_config(a, b, c, d)
    assert all(_same_audit(a, n) for n in (b, c, d))
    for node in (a, b, c, d):
        cfg = node.ctx.cluster()
        assert cfg.user("ann") is not None and any(r.name == "dhcp-ops" for r in cfg.roles)
        assert cfg.settings["collector"]["poll_seconds"] == 15 and cfg.modules["advanced_editor"] is False
        actions = {e.action for e in node.ctx.audit_log.read()}
        assert {f"written.on.ns{i}" for i in (1, 2, 3, 4)} <= actions
    assert len({n.ctx.cluster().version for n in (a, b, c, d)}) == 1


def test_a_node_down_catches_up_from_any_peer(nodes):
    a, b, c, d = _four(nodes)
    d.service.stop()
    _write(b, lambda cfg: cfg.roles.append(Role(name="late", permissions=["read:dns"])))
    c.ctx.audit_log.append(_entry(c, "while.d.was.down"))
    _converge(a, b, c)
    # Three failed polls make the other nodes report it offline.
    for _ in range(3):
        a.service.replicator.pull_all()
    assert a.service.replicator.offline_peers() == [d.id]
    d.restart()  # pulls from every peer on start
    _converge(a, b, c, d)
    assert _same_config(a, b, c, d) and all(_same_audit(a, n) for n in (b, c, d))
    assert any(r.name == "late" for r in d.ctx.cluster().roles)
    assert a.service.replicator.offline_peers() == []


def test_a_removed_node_is_refused_by_every_other_node(nodes):
    a, b, c, d = _four(nodes)
    clients = {
        n.id: ReplicationClient(c.ctx.cluster().peer(n.id), c.service.client_context) for n in (a, b, d)
    }
    assert all(cl.status().reachable for cl in clients.values())
    a.service.enrollment.revoke(c.id, f"user:admin@node:{a.id}")
    _converge(a, b, d)
    for node in (a, b, d):
        cfg = node.ctx.cluster()
        assert cfg.peer(c.id) is None and len(cfg.revoked) == 1, node.ctx.node.name
        assert c.id not in {s.node_id for s in node.service.replicator.peer_statuses()}
    for node_id, client in clients.items():
        with pytest.raises(ReplicationError) as err:
            client.status()
        assert err.value.status == 403 and err.value.code == "revoked", node_id
    # The three left keep converging without it.
    _write(d, lambda cfg: cfg.roles.append(Role(name="after-removal", permissions=["read:dns"])))
    _converge(a, b, d)
    assert _same_config(a, b, d)
    assert all(any(r.name == "after-removal" for r in n.ctx.cluster().roles) for n in (a, b, d))
