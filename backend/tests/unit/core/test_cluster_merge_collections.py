# SPDX-License-Identifier: Apache-2.0
"""Generic collections through the merge, mixed versions and conflict reports (sections 10 and 13)."""

from __future__ import annotations

import contextlib
import tomllib
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from pelagos.core import cluster_merge as cm
from pelagos.core import collections as colls
from pelagos.core.config_store import ClusterConfig, merge_configs
from pelagos.domain import Role, User
from tests.unit.core.test_cluster_merge import _base, _roundtrip, _write

pytestmark = pytest.mark.unit

Node = tuple[ClusterConfig, cm.Bases]


@pytest.fixture(autouse=True)
def widgets(monkeypatch):
    monkeypatch.setitem(colls.COLLECTIONS, "widgets", colls.Collection())


@contextlib.contextmanager
def older_node(*names: str) -> Iterator[None]:
    """The registry of a node that does not know `names` (an older release)."""
    saved = {n: colls.COLLECTIONS.pop(n) for n in names if n in colls.COLLECTIONS}
    try:
        yield
    finally:
        colls.COLLECTIONS.update(saved)


def _seen_by_older(cfg: ClusterConfig, *names: str) -> ClusterConfig:
    """`cfg` as an older node reads it: through the TOML text under its reduced registry."""
    text = cfg.dumps()
    with older_node(*names):
        return ClusterConfig.from_toml(tomllib.loads(text))


def _w(node: Node, writer: str, mutate: Callable[[ClusterConfig], Any], by: str | None = None) -> Node:
    """A write on `writer` with the bases it records (ConfigStore.update_cluster does the same)."""
    cfg, bases = node
    before = ClusterConfig.from_toml(_roundtrip(cfg)).state()
    out = _write(cfg, writer, mutate)
    after = out.state()
    return out, {**cm.valid_bases(after, bases), **cm.write_bases(before, after, by or f"user:u{writer}")}


def _m(local: Node, remote: Node, node_id: str | None) -> tuple[Node, list[cm.Discarded]]:
    report = cm.merge_report(local[0].state(), remote[0].state(), local[1], remote[1], node_id=node_id)
    return (merge_configs(local[0], remote[0]), report.bases), report.discarded


def _start(mutate: Callable[[ClusterConfig], Any] | None = None) -> Node:
    node: Node = (_base(), {})
    return _w(node, "A", mutate) if mutate else node


def _add_widget(rid: str, **fields: Any) -> Callable[[ClusterConfig], None]:
    return lambda c: c.collection("widgets").append({"id": rid, **fields})


def _roles(*roles: str) -> Callable[[ClusterConfig], None]:
    return lambda c: setattr(c.users[0], "roles", list(roles))


def _bump(node: Node, writer: str, times: int) -> Node:
    for i in range(times):
        node = _w(node, writer, lambda c, i=i: c.settings["plans"].__setitem__("ttl_seconds", 100 + i))
    return node


def test_collection_records_merge_like_users():
    base = _start(_add_widget("w0", name="zero"))
    a = _w(base, "A", _add_widget("w1", name="one"))
    b = _w(base, "B", _add_widget("w2", name="two"))
    ab, ba = merge_configs(a[0], b[0]), merge_configs(b[0], a[0])
    assert ab.digest() == ba.digest()
    assert sorted(w["id"] for w in ab.collection("widgets")) == ["w0", "w1", "w2"]
    gone = _w(base, "A", lambda c: c.collection("widgets").clear())
    edited = _w(base, "B", lambda c: c.collection("widgets")[0].update(name="edited"))
    for merged in (merge_configs(gone[0], edited[0]), merge_configs(edited[0], gone[0])):
        assert merged.collection("widgets") == [] and "widgets/w0" in merged.tombstones


def test_a_recreated_record_drops_the_fields_of_its_earlier_incarnation():
    base = _start(_add_widget("w1", name="a", color="red"))
    stale = _w(base, "C", lambda c: c.settings["plans"].__setitem__("ttl_seconds", 900))
    gone = _w(base, "A", lambda c: c.collection("widgets").clear())
    again = _w(gone, "A", _add_widget("w1", name="b"))
    for merged in (merge_configs(stale[0], again[0]), merge_configs(again[0], stale[0])):
        assert merged.collection("widgets") == [{"id": "w1", "name": "b"}]


def test_an_older_node_ignores_a_collection_and_never_tombstones_it():
    new = _start(_add_widget("w1", name="a"))[0]
    old = _seen_by_older(new, "widgets")
    with older_node("widgets"):
        old = _write(old, "B", lambda c: c.secrets.__setitem__("tsig/other", "enc:v1:b"))
        raw = tomllib.loads(old.dumps())
    assert "widgets" not in raw
    assert not [p for p in raw["replication"]["tombstones"] if p.startswith("widgets/")]


def test_records_come_back_after_merging_through_an_older_node():
    new = _start(_add_widget("w1", name="a"))[0]
    with older_node("widgets"):
        old = _write(_seen_by_older(new, "widgets"), "B", lambda c: c.secrets.__setitem__("tsig/o", "x"))
        old_text = old.dumps()
    back = merge_configs(new, ClusterConfig.from_toml(tomllib.loads(old_text)))
    assert back.collection("widgets") == [{"id": "w1", "name": "a"}]
    assert back.stamps["widgets/w1/name"] == new.stamps["widgets/w1/name"]
    assert back.secrets["tsig/o"] == "x"
    # A deletion made on a new node reaches another new node through the older one.
    deleted = _write(back, "A", lambda c: c.collection("widgets").clear())
    with older_node("widgets"):
        relayed = merge_configs(_seen_by_older(old, "widgets"), _seen_by_older(deleted, "widgets"))
        relayed_text = relayed.dumps()
    assert "widgets/w1" in tomllib.loads(relayed_text)["replication"]["tombstones"]
    third = merge_configs(new, ClusterConfig.from_toml(tomllib.loads(relayed_text)))
    assert third.collection("widgets") == []


def test_unknown_section_from_a_newer_release_is_ignored_the_same_way():
    base = _base()
    data = _roundtrip(base)
    data["gadgets"] = [{"id": "g1", "name": "x"}]
    data["replication"]["stamps"]["gadgets/g1"] = "9@Z"
    data["replication"]["tombstones"]["gadgets/g0"] = "8@Z"
    here = ClusterConfig.from_toml(data)
    written = _write(here, "A", lambda c: c.secrets.__setitem__("tsig/x", "y"))
    raw = tomllib.loads(written.dumps())
    assert "gadgets" not in raw
    assert raw["replication"]["tombstones"]["gadgets/g0"] == "8@Z"
    assert not [p for p in raw["replication"]["tombstones"] if p.startswith("gadgets/g1")]


def test_concurrent_write_of_the_same_field_is_reported_once():
    base = _start()
    a = _w(base, "A", _roles("admin", "dns"))
    b = _w(_bump(base, "B", 3), "B", _roles("viewer"))  # B's clock runs ahead
    on_a, found_a = _m(a, b, "A")
    on_b, found_b = _m(b, a, "B")
    assert found_b == []
    assert len(found_a) == 1
    item = found_a[0]
    assert (item.path, item.reason) == ("users/U1/roles", "stamp")
    assert item.local == ["admin", "dns"] and item.remote == ["viewer"]
    assert (item.local_by, item.remote_by) == ("user:uA", "user:uB")
    assert item.local_stamp[1] == "A" and item.remote_stamp[1] == "B"
    assert on_a[0].digest() == on_b[0].digest()
    # Merging again changes nothing and reports nothing.
    assert _m(on_a, b, "A")[1] == []


def test_an_ordinary_edit_of_another_nodes_value_is_not_a_conflict():
    base = _start()
    a = _w(base, "A", _roles("admin", "dns"))
    b, _ = _m(_bump(base, "B", 1), a, "B")
    b = _w(b, "B", _roles("viewer"))
    assert b[1]["users/U1/roles"][1] == a[0].stamps["users/U1/roles"]
    assert _m(a, b, "A")[1] == []


def test_unknown_base_is_not_reported():
    base = _start()
    a = _w(base, "A", _roles("admin", "dns"))
    b = _w(base, "B", _roles("viewer"))
    assert _m(a, (b[0], {}), "A")[1] == []


def test_local_deletion_lost_to_a_concurrent_write_is_reported():
    base = _start()
    a = _w(base, "A", lambda c: c.secrets.clear())
    b = _w(_bump(base, "B", 2), "B", lambda c: c.secrets.__setitem__("tsig/ddi-admin", "enc:v1:b"))
    _, found = _m(a, b, "A")
    assert [(d.path, d.reason, d.local_deleted, d.remote_deleted) for d in found] == [
        ("secrets/tsig%2Fddi-admin", "stamp", True, False)
    ]


def test_field_edit_lost_to_a_concurrent_record_deletion_is_reported():
    base = _start(_add_widget("w1", name="a", color="red"))
    gone = _w(base, "B", lambda c: c.collection("widgets").clear())
    late = _w(_bump(base, "A", 3), "A", lambda c: c.collection("widgets")[0].update(name="b"))
    early = _w(base, "A", lambda c: c.collection("widgets")[0].update(name="b"))
    _, found = _m(late, gone, "A")
    assert [(d.path, d.reason, d.local, d.remote_deleted) for d in found] == [
        ("widgets/w1", "record_deleted", {"name": "b"}, True)
    ]
    assert _m(early, gone, "A")[1] == []  # field not newer than the tombstone: maybe seen


def test_record_deleted_gives_one_entry_per_record_with_masked_fields():
    from pelagos.core.replication import conflict_entry

    base = _start()
    gone = _w(base, "B", lambda c: setattr(c, "users", []))

    def edit(c: ClusterConfig) -> None:
        c.users[0].password_hash = "$argon2id$secret-hash"
        c.users[0].roles = ["viewer"]
        c.users[0].enabled = False

    late = _w(_bump(base, "A", 3), "A", edit)
    _, found = _m(late, gone, "A")
    assert len(found) == 1 and found[0].reason == "record_deleted"
    entry = conflict_entry(found[0], "A", {"A": "ns1", "B": "ns2"}, 0)
    assert entry.request["local"]["value"] == {"enabled": False, "password_hash": "***", "roles": ["viewer"]}
    assert "secret-hash" not in str(entry.to_dict())


def test_record_recreated_reports_concurrent_creation_of_a_natural_key():
    base = _start()
    a = _w(base, "A", lambda c: c.roles.append(Role(name="ops", permissions=["read:dns"])))
    b = _w(_bump(base, "B", 2), "B", lambda c: c.roles.append(Role(name="ops", description="b")))
    merged, found = _m(a, b, "A")
    assert [(d.path, d.reason, d.remote) for d in found] == [("roles/ops", "record_recreated", True)]
    assert found[0].local == {"builtin": False, "permissions": ["read:dns"]}
    assert merged[0].roles[0].description == "b" and merged[0].roles[0].permissions == []
    assert _m(b, a, "B")[1] == []


def test_causal_recreation_after_a_seen_tombstone_is_not_reported():
    base = _start()
    a = _w(base, "A", lambda c: c.roles.append(Role(name="ops", permissions=["read:dns"])))
    b, _ = _m(base, a, "B")
    b = _w(b, "B", lambda c: setattr(c, "roles", []))
    b = _w(b, "B", lambda c: c.roles.append(Role(name="ops", description="b")))
    assert _m(a, b, "A")[1] == []


def test_concurrent_username_is_reported_with_reason_username():
    base = _start()
    a = _w(base, "A", lambda c: c.users.append(User(id="C1", username="carol", password_hash="h")))
    b = _w(
        _bump(base, "B", 1), "B", lambda c: c.users.append(User(id="C2", username="carol", password_hash="h"))
    )
    merged, found = _m(a, b, "A")
    assert [(d.path, d.reason) for d in found] == [("users/C1", "username")]
    assert [u.id for u in merged[0].users if u.username == "carol"] == ["C2"]
    assert _m(b, a, "B")[1] == []


def test_merge_report_keeps_merge_commutative():
    base = _start(_add_widget("w1", name="a"))
    a = _w(base, "A", _roles("admin", "dns"))
    b = _w(_bump(base, "B", 2), "B", lambda c: c.collection("widgets")[0].update(name="b"))
    ab = cm.merge_report(a[0].state(), b[0].state(), a[1], b[1], node_id="A")
    ba = cm.merge_report(b[0].state(), a[0].state(), b[1], a[1], node_id="B")
    plain = cm.merge_states(a[0].state(), b[0].state())
    assert ab.state.digest() == ba.state.digest() == plain.digest()


def test_merge_report_bases_are_commutative():
    base = _start(_add_widget("w1", name="a"))
    a = _w(base, "A", _roles("admin", "dns"))
    b = _w(_bump(base, "B", 2), "B", lambda c: c.collection("widgets")[0].update(name="b"))
    ab = cm.merge_report(a[0].state(), b[0].state(), a[1], b[1])
    ba = cm.merge_report(b[0].state(), a[0].state(), b[1], a[1])
    assert ab.bases == ba.bases
    assert ab.bases["widgets/w1/name"][2] == "user:uB" and ab.bases["users/U1/roles"][2] == "user:uA"


def test_digest_without_a_collection_equals_an_older_nodes_digest():
    new = _start(_add_widget("w0", name="zero"))
    new = _w(new, "A", _add_widget("w1", name="a"))
    new = _w(new, "A", lambda c: c.collection("widgets").pop(0))  # a tombstone the old node relays
    with older_node("widgets"):
        old = _write(_seen_by_older(new[0], "widgets"), "B", lambda c: c.secrets.__setitem__("tsig/o", "x"))
        old_text = old.dumps()
    merged_new = merge_configs(new[0], ClusterConfig.from_toml(tomllib.loads(old_text)))
    with older_node("widgets"):
        merged_old = merge_configs(
            ClusterConfig.from_toml(tomllib.loads(old_text)), _seen_by_older(merged_new)
        )
        old_digest = merged_old.digest()
    assert merged_new.digest() != old_digest
    assert merged_new.digest(without=["widgets"]) == old_digest


def test_two_write_sequence_on_one_node_is_reported_once_on_the_other():
    base = _start()
    a1 = _w(base, "A", _roles("one"))
    b = _w(_bump(base, "B", 1), "B", _roles("bee"))  # between A's two writes
    a2 = _w(_bump(a1, "A", 1), "A", _roles("two"))
    assert a1[0].stamps["users/U1/roles"] < b[0].stamps["users/U1/roles"] < a2[0].stamps["users/U1/roles"]
    assert [(d.path, d.reason) for d in _m(b, a2, "B")[1]] == [("users/U1/roles", "stamp")]
    assert _m(a2, b, "A")[1] == []


def test_stale_bases_items_are_ignored_when_read():
    base = _start()
    a = _w(base, "A", _roles("admin", "dns"))
    stale = {"users/U1/roles": ((99, "Z"), (0, ""), "user:ghost")}
    assert cm.valid_bases(a[0].state(), stale) == {}
    assert cm.merge_report(a[0].state(), a[0].state(), stale, {}).bases == {}


def test_remote_bases_with_foreign_stamps_are_ignored():
    base = _start()
    a = _w(base, "A", _roles("admin", "dns"))
    b = _w(_bump(base, "B", 3), "B", _roles("viewer"))
    forged = {"users/U1/roles": ((1, "B"), (0, ""), "user:x")}  # not the stamp B holds
    assert _m(a, (b[0], forged), "A")[1] == []
