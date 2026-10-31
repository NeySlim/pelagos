# SPDX-License-Identifier: Apache-2.0
"""ConfigStore bases file and conflict callbacks; replication.conflict audit entries (section 13)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from pelagos.core import cluster_merge as cm
from pelagos.core import collections as colls
from pelagos.core import replication as repl
from pelagos.core.audit_log import AuditLog
from pelagos.core.config_store import ConfigStore, NodeConfig, bases_payload
from pelagos.core.replication import CONFLICT_LIMITER, ConflictReporter, ReplicationClient
from pelagos.domain import User
from pelagos.domain.cluster import Peer
from tests.unit.core.test_replication import cluster, pair  # noqa: F401 (fixtures)

pytestmark = pytest.mark.unit

HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2VjcmV0LWhhc2gtdmFsdWU"


@pytest.fixture(autouse=True)
def fresh_limiter():
    CONFLICT_LIMITER.reset()
    yield
    CONFLICT_LIMITER.reset()


@pytest.fixture
def two(node_paths, tmp_root) -> tuple[ConfigStore, ConfigStore]:
    """Store A (bootstrapped) and store B, a second node holding the same file."""
    a = ConfigStore(node_paths.node_toml, node_paths.cluster_toml)
    bdir = tmp_root / "b"
    bdir.mkdir()
    shutil.copy(node_paths.cluster_toml, bdir / "cluster.toml")
    b = ConfigStore(bdir / "node.toml", bdir / "cluster.toml")
    b.save_node(NodeConfig(id="NODEB", name="ns2"))
    # Both nodes know each other by name in [[nodes]].
    a.update_cluster(
        lambda c: c.nodes.append(
            Peer(id="NODEB", name="ns2", url="https://ns2.example.lan:8444", cert_fingerprint="sha256:b")
        ),
        "x",
    )
    b.merge_remote(a.cluster_path.read_text(), bases_payload(a.read_bases()))
    return a, b


def _alice(a: ConfigStore) -> str:
    return f"user:alice@node:{a.local_node_id()}"


def _roles(*roles: str):
    def mutate(cfg):
        cfg.users[0].roles = list(roles)

    return mutate


def _send(src: ConfigStore, dst: ConfigStore, on_conflict=None) -> bool:
    return dst.merge_remote(
        src.cluster_path.read_text(), bases_payload(src.read_bases()), on_conflict=on_conflict
    )


def _bump(store: ConfigStore, times: int) -> None:
    for i in range(times):
        store.update_cluster(lambda c, i=i: c.settings["plans"].__setitem__("ttl_seconds", 100 + i), "x")


def _conflict(a: ConfigStore, b: ConfigStore, audit: AuditLog, mutate_a=None, mutate_b=None) -> None:
    """A and B write users[0] concurrently, B's clock ahead; B's file then reaches A."""
    a.update_cluster(mutate_a or _roles("admin", "dns"), _alice(a))
    _bump(b, 2)
    b.update_cluster(mutate_b or _roles("viewer"), "user:bob@node:NODEB")
    assert _send(b, a, ConflictReporter(audit, a))


def test_bases_file_follows_writes_and_merges(two):
    a, b = two
    before = a.load_cluster().stamps["users/" + a.load_cluster().users[0].id + "/roles"]
    after = a.update_cluster(_roles("viewer"), _alice(a))
    path = f"users/{after.users[0].id}/roles"
    raw = json.loads(a.bases_path.read_text())
    assert raw[path] == [cm.stamp_text(after.stamps[path]), cm.stamp_text(before), _alice(a)]
    assert oct(a.bases_path.stat().st_mode & 0o777) == "0o640"
    # The winner's base travels with the merge; items not current any more are dropped.
    assert _send(a, b)
    assert b.read_bases()[path] == a.read_bases()[path]
    a.update_cluster(_roles("admin"), f"user:carol@node:{a.local_node_id()}")
    assert a.read_bases()[path][2] == f"user:carol@node:{a.local_node_id()}"
    assert all(cm.current_stamp(a.load_cluster().state(), p) == item[0] for p, item in a.read_bases().items())


def test_bases_are_bounded(monkeypatch):
    monkeypatch.setattr(cm, "BASES_MAX", 2)
    bases = {f"p{i}": ((i, "A"), cm.ZERO, None) for i in range(5)}
    assert sorted(cm.bound_bases(bases)) == ["p3", "p4"]


def test_damaged_bases_file_reads_as_empty(two, tmp_path):
    a, b = two
    a.bases_path.write_text("{not json")
    assert a.read_bases() == {}
    a.update_cluster(_roles("viewer"), _alice(a))
    assert a.read_bases()  # rewritten with the new write's items
    audit = AuditLog(tmp_path / "audit.jsonl")
    b.bases_path.write_text("[1, 2]")
    _bump(b, 3)
    b.update_cluster(_roles("ops"), "x")
    b.bases_path.unlink()  # B's bases lost: its write's base is unknown
    assert _send(b, a, ConflictReporter(audit, a))
    assert audit.read() == []


def test_stale_bases_items_are_inert_after_a_crash(two, tmp_path):
    a, b = two
    audit = AuditLog(tmp_path / "audit.jsonl")
    a.update_cluster(_roles("admin", "dns"), _alice(a))
    _bump(b, 2)
    old_bases = b.bases_path.read_text()
    b.update_cluster(_roles("viewer"), "user:bob@node:NODEB")
    b.bases_path.write_text(old_bases)  # crash between cluster.toml and cluster.bases.json
    assert _send(b, a, ConflictReporter(audit, a))
    assert audit.read() == []


def test_merge_remote_calls_on_conflict_once_per_discarded_entry(two, tmp_path):
    a, b = two
    calls: list[list[cm.Discarded]] = []
    a.update_cluster(_roles("admin", "dns"), _alice(a))
    _bump(b, 2)
    b.update_cluster(_roles("viewer"), "user:bob@node:NODEB")
    assert _send(b, a, calls.append)
    assert len(calls) == 1 and [d.reason for d in calls[0]] == ["stamp"]
    assert not _send(b, a, calls.append)  # nothing changes: no call
    assert len(calls) == 1
    _send(a, b, calls.append)  # B's write won: nothing to report on B
    assert len(calls) == 1


def test_conflict_audit_entry_shape(two, tmp_path):
    a, b = two
    audit = AuditLog(tmp_path / "audit.jsonl")
    _conflict(a, b, audit)
    [entry] = audit.read()
    uid = a.load_cluster().users[0].id
    path = f"users/{uid}/roles"
    data = entry.to_dict()
    assert data["action"] == "replication.conflict" and data["user"] == "system"
    assert data["target"] == f"config:{path}" and data["node_id"] == a.local_node_id()
    assert data["client_ip"] is None and data["engine"] is None and data["result"] == "ok"
    req = data["request"]
    assert (req["path"], req["section"], req["record"], req["reason"], req["suppressed"]) == (
        path, "users", uid, "stamp", 0,
    )  # fmt: skip
    assert req["local"] == {
        "stamp": req["local"]["stamp"], "by": _alice(a),
        "value": ["admin", "dns"], "deleted": False,
    }  # fmt: skip
    assert req["remote"]["by"] == "user:bob@node:NODEB" and req["remote"]["value"] == ["viewer"]
    assert req["remote"]["stamp"].endswith("@NODEB") and req["remote"]["base"]
    assert data["message"] == f"Concurrent write of {path}: bob on ns2 replaced alice on ns1"


def test_conflict_audit_masks_secrets_and_hashes(monkeypatch):
    monkeypatch.setitem(colls.COLLECTIONS, "widgets", colls.Collection(secret_fields=("token_hash",)))
    for path in (
        "secrets/tsig%2Fddi-admin",
        "users/U1/password_hash",
        "users/U1/totp_secret",
        "users/U1/webauthn/cred1/name",
        "api_tokens/T1/secret_hash",
        "widgets/w1/token_hash",
    ):
        assert repl.masked(path, "x") == "***", path
    for path in ("users/U1/roles", "widgets/w1/name", "settings/plans/ttl_seconds"):
        assert repl.masked(path, "x") == "x", path
    record = {"password_hash": "h", "roles": ["a"], "webauthn/k/sign_count": 1}
    assert repl.masked("users/U1", record, True) == {
        "password_hash": "***", "roles": ["a"], "webauthn/k/sign_count": "***",
    }  # fmt: skip


def test_a_masked_value_never_reaches_the_audit_line(two, tmp_path):
    a, b = two
    audit = AuditLog(tmp_path / "audit.jsonl")

    def set_hash(value: str):
        def mutate(cfg):
            cfg.users[0].password_hash = value

        return mutate

    _conflict(a, b, audit, set_hash(HASH), set_hash(HASH + "other"))
    [entry] = audit.read()
    assert entry.request["local"]["value"] == "***" and entry.request["remote"]["value"] == "***"
    assert "c2VjcmV0" not in (tmp_path / "audit.jsonl").read_text()


def test_conflict_audit_is_rate_limited_per_path_and_minute(monkeypatch, two, tmp_path):
    now = [1000.0]
    monkeypatch.setattr(repl.time, "monotonic", lambda: now[0])
    a, b = two
    audit = AuditLog(tmp_path / "audit.jsonl")
    _conflict(a, b, audit)
    _conflict(a, b, audit, _roles("again"), _roles("bee"))
    assert len(audit.read()) == 1
    now[0] += 61
    _conflict(a, b, audit, _roles("third"), _roles("cee"))
    entries = audit.read()
    assert len(entries) == 2 and entries[-1].request["suppressed"] == 1


def test_migrate_settings_leaves_bases_alone(two):
    a, _ = two
    a.update_cluster(_roles("viewer"), _alice(a))
    text = a.cluster_path.read_text()
    a.cluster_path.write_text(
        text.replace("[settings.plans]\nttl_seconds", "[settings.plans]\nplan_ttl_x = 1\nttl_seconds")
    )
    before = a.bases_path.read_bytes()
    a.migrate_settings("system")
    assert a.bases_path.read_bytes() == before


def _client(a, b) -> ReplicationClient:
    peer = a.ctx.config_store.load_cluster().peer(b.id)
    return ReplicationClient(peer, a.service.replicator.ssl_context)


def test_repl_config_exchanges_bases_and_tolerates_their_absence(pair):  # noqa: F811
    a, b = pair
    b.ctx.config_store.update_cluster(
        lambda c: c.users.append(User(id="u9", username="dora", password_hash="h")), "user:bob@node:x"
    )
    payload = b.service.app.config_payload()
    assert payload["bases"]["users/u9"][2] == "user:bob@node:x"
    # An older node's PUT carries no bases: the merge goes on.
    status, _body = a.service.app._put_config({"toml": payload["toml"]})
    assert status == 200 and a.ctx.config_store.load_cluster().user("dora") is not None
    client = _client(a, b)
    assert client.fetch_config()["bases"] == payload["bases"]


def test_status_lists_known_collections(pair, monkeypatch):  # noqa: F811
    a, b = pair
    monkeypatch.setitem(colls.COLLECTIONS, "widgets", colls.Collection())
    assert b.service.app.status_payload()["collections"] == ["widgets"]
    client = _client(a, b)
    assert client.status().collections == ["widgets"]
    assert client.status().to_dict()["collections"] == ["widgets"]


def test_status_parses_missing_collections_as_none(pair, monkeypatch):  # noqa: F811
    a, b = pair
    real = b.service.app.status_payload

    def older():
        data = real()
        data.pop("collections")
        return data

    monkeypatch.setattr(b.service.app, "status_payload", older)
    client = _client(a, b)
    assert client.status().collections is None


def test_bases_path_sits_next_to_cluster_toml(tmp_path: Path):
    store = ConfigStore(tmp_path / "node.toml", tmp_path / "cluster.toml")
    assert store.bases_path == tmp_path / "cluster.bases.json"


def test_a_failing_reporter_never_reaches_the_merge_and_keeps_the_slot(monkeypatch, two, tmp_path):
    a, b = two
    audit = AuditLog(tmp_path / "audit.jsonl")
    real = audit.append

    def broken(entry):
        raise ValueError("boom")

    monkeypatch.setattr(audit, "append", broken)
    _conflict(a, b, audit)  # merge_remote still returns True
    assert audit.read() == []
    monkeypatch.setattr(audit, "append", real)
    _conflict(a, b, audit, _roles("again"), _roles("bee"))
    [entry] = audit.read()  # the failed entry did not take the minute's slot
    assert entry.request["suppressed"] == 0
