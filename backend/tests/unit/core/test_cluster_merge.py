# SPDX-License-Identifier: Apache-2.0
"""cluster_merge: per-entry stamps, tombstones, commutative and idempotent merge."""

from __future__ import annotations

import pytest

from pelagos.core import cluster_merge as cm
from pelagos.core.config_store import ClusterConfig, merge_configs
from pelagos.domain import Peer, Role, User

pytestmark = pytest.mark.unit


def _base() -> ClusterConfig:
    cfg = ClusterConfig.new("node:A")
    cfg.users.append(User(id="U1", username="admin", password_hash="h", roles=["admin"]))
    cfg.nodes.append(
        Peer(id="A", name="ns1", url="https://ns1.example.lan:8444", cert_fingerprint="sha256:a")
    )
    cfg.secrets["tsig/ddi-admin"] = "enc:v1:a"
    state, _ = cm.record_write(cm.State(), cm.flatten(cfg.document()), "A")
    cfg.stamped, cfg.stamps, cfg.version = True, state.stamps, 1
    return cfg


def _write(cfg: ClusterConfig, node: str, mutate) -> ClusterConfig:
    out = ClusterConfig.from_toml(_roundtrip(cfg))
    before = out.state()
    mutate(out)
    state, counter = cm.record_write(before, cm.flatten(out.document()), node, floor=out.version)
    out.stamps, out.tombstones, out.version, out.updated_by = (
        state.stamps,
        state.tombstones,
        counter,
        f"node:{node}",
    )
    return ClusterConfig.from_toml(_roundtrip(out))


def _roundtrip(cfg: ClusterConfig) -> dict:
    import tomllib

    return tomllib.loads(cfg.dumps())


def test_flatten_paths_and_round_trip():
    cfg = _base()
    values = cm.flatten(cfg.document())
    assert values["users/U1"] is cm.RECORD
    assert values["users/U1/roles"] == ["admin"]
    assert values["secrets/tsig%2Fddi-admin"] == "enc:v1:a"
    assert values["settings/collector/poll_seconds"] == 60
    assert values["nodes/A/modules/bind"] is False
    doc = cm.unflatten(values, cfg.stamps)
    assert cm.flatten(doc) == values


def test_merge_is_commutative_and_idempotent():
    base = _base()
    a = _write(base, "A", lambda c: c.settings.__setitem__("plan_ttl_seconds", 1))
    b = _write(base, "B", lambda c: c.roles.append(Role(name="ops", permissions=["read:dns"])))
    b = _write(b, "B", lambda c: c.users[0].roles.append("viewer"))
    ab, ba = merge_configs(a, b), merge_configs(b, a)
    assert ab.digest() == ba.digest() and ab.version == ba.version
    assert merge_configs(ab, ab).digest() == ab.digest()
    assert merge_configs(ab, a).digest() == ab.digest()
    assert ab.settings["plan_ttl_seconds"] == 1
    assert [r.name for r in ab.roles] == ["ops"]
    assert ab.users[0].roles == ["admin", "viewer"]


def test_same_key_conflict_greater_stamp_then_node_wins():
    base = _base()
    a = _write(base, "A", lambda c: c.settings.__setitem__("plan_ttl_seconds", 1))
    b = _write(base, "B", lambda c: c.settings.__setitem__("plan_ttl_seconds", 2))
    assert merge_configs(a, b).settings["plan_ttl_seconds"] == 2  # same counter, "B" > "A"
    a2 = _write(a, "A", lambda c: c.settings.__setitem__("plan_ttl_seconds", 3))
    assert merge_configs(b, a2).settings["plan_ttl_seconds"] == 3  # higher counter


def test_tombstones_delete_wins_and_prunes_fields():
    base = _base()
    base = _write(base, "A", lambda c: c.roles.append(Role(name="ops", permissions=["read:dns"])))
    deleted = _write(base, "A", lambda c: setattr(c, "roles", []))
    edited = _write(base, "B", lambda c: setattr(c.roles[0], "description", "x"))
    edited = _write(edited, "B", lambda c: setattr(c.roles[0], "description", "y"))
    merged = merge_configs(edited, deleted)
    assert merged.roles == []
    assert "roles/ops" in merged.tombstones
    assert not [p for p in {**merged.stamps, **merged.tombstones} if p.startswith("roles/ops/")]
    # A removed secret stays removed when the other side still has it.
    gone = _write(base, "A", lambda c: c.secrets.clear())
    assert merge_configs(base, gone).secrets == {}
    assert merge_configs(gone, base).secrets == {}


def test_recreated_record_does_not_get_fields_of_its_former_incarnation():
    """Delete then re-create a role on A; C still holds the old role and missed both writes."""
    base = _base()
    base = _write(
        base,
        "A",
        lambda c: c.roles.append(Role(name="ops", description="old", permissions=["read:dns"])),
    )
    stale = _write(base, "C", lambda c: c.settings.__setitem__("plan_ttl_seconds", 900))
    deleted = _write(base, "A", lambda c: setattr(c, "roles", []))
    recreated = _write(deleted, "A", lambda c: c.roles.append(Role(name="ops")))
    third = _write(recreated, "B", lambda c: c.settings["collector"].__setitem__("poll_seconds", 15))
    final = merge_configs(merge_configs(stale, recreated), third)
    other = merge_configs(third, merge_configs(recreated, stale))
    for cfg in (final, other):
        assert [r.name for r in cfg.roles] == ["ops"]
        assert cfg.roles[0].description is None and cfg.roles[0].permissions == []
        assert cfg.settings["plan_ttl_seconds"] == 900
        assert cfg.settings["collector"]["poll_seconds"] == 15
    assert final.state().digest() == other.state().digest()
    stamps = {**final.stamps, **final.tombstones}
    created = final.stamps["roles/ops"]
    assert all(s >= created for p, s in stamps.items() if p.startswith("roles/ops/"))


def test_recreated_record_pure_states():
    """Same scenario on bare states: nested keys absent from the new record stay gone."""
    before, _ = cm.record_write(
        cm.State(),
        {
            "roles/ops": cm.RECORD,
            "roles/ops/description": "old",
            "roles/ops/extra/a": 1,
            "roles/ops/extra/b": 2,
        },
        "A",
    )
    gone, _ = cm.record_write(before, {}, "A")
    again, _ = cm.record_write(gone, {"roles/ops": cm.RECORD, "roles/ops/extra/a": 5}, "A")
    for merged in (cm.merge_states(before, again), cm.merge_states(again, before)):
        assert merged.values == {"roles/ops": cm.RECORD, "roles/ops/extra/a": 5}
        assert cm.unflatten(merged.values, merged.stamps)["roles"] == [{"name": "ops", "extra": {"a": 5}}]
    assert cm.merge_states(before, again).digest() == cm.merge_states(again, before).digest()


def test_concurrent_same_username_keeps_one_record():
    base = _base()
    a = _write(base, "A", lambda c: c.users.append(User(id="U2", username="bob", password_hash="a")))
    b = _write(base, "B", lambda c: c.users.append(User(id="U3", username="bob", password_hash="b")))
    ab, ba = merge_configs(a, b), merge_configs(b, a)
    assert [u.id for u in ab.users if u.username == "bob"] == ["U3"]
    assert ab.digest() == ba.digest()


def test_revoked_is_a_set_and_records_keep_creation_order():
    base = _base()
    a = _write(base, "A", lambda c: c.revoked.append("sha256:zz"))
    b = _write(base, "B", lambda c: c.revoked.append("sha256:aa"))
    b = _write(b, "B", lambda c: c.users.append(User(id="U9", username="carol", password_hash="c")))
    merged = merge_configs(a, b)
    assert merged.revoked == ["sha256:aa", "sha256:zz"]
    assert [u.username for u in merged.users] == ["admin", "carol"]


def test_stamp_helpers():
    assert cm.parse_stamp("12@01ABC") == (12, "01ABC")
    assert cm.parse_stamp("bad") == cm.ZERO
    assert cm.writer_node("user:admin@node:01ABC") == "01ABC"
    assert cm.writer_node("system") == "system"


def _exception(eid: str, key: str) -> dict:
    return {
        "id": eid,
        "kind": "ptr_mismatch",
        "key": key,
        "comment": "kept on purpose",
        "created_by": "admin",
        "created_at": "2026-10-26T10:00:00Z",
    }


def _revoke(eid: str):
    return lambda c: c.exceptions.__setitem__(slice(None), [e for e in c.exceptions if e["id"] != eid])


def test_exceptions_are_records_created_and_revoked_across_nodes():
    base = _base()
    assert "exceptions" not in base.dumps()  # an empty list leaves the file as before
    a = _write(base, "A", lambda c: c.exceptions.append(_exception("E1", "192.0.2.90|mail.example.net.")))
    b = _write(base, "B", lambda c: c.exceptions.append(_exception("E2", "192.0.2.40|printer.example.lan.")))
    ab, ba = merge_configs(a, b), merge_configs(b, a)
    assert ab.digest() == ba.digest()
    assert sorted(e["id"] for e in ab.exceptions) == ["E1", "E2"]
    assert cm.flatten(ab.document())["exceptions/E1/key"] == "192.0.2.90|mail.example.net."
    # Revoked on A while B still holds it: the tombstone wins and no field survives.
    revoked = _write(ab, "A", _revoke("E1"))
    merged = merge_configs(ab, revoked)
    assert [e["id"] for e in merged.exceptions] == ["E2"]
    assert not [p for p in merged.stamps if p.startswith("exceptions/E1")]
    assert merge_configs(revoked, ab).digest() == merged.digest()
