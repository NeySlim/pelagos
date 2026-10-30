# SPDX-License-Identifier: Apache-2.0
"""The replicated Kea migration record (section 28): read with every key, written without nulls,
moved only along the state machine, and the phases each state allows."""

from __future__ import annotations

import os

import pytest

from pelagos.core import kea_migration as km
from pelagos.core.config_store import ClusterConfig, ConfigStore

pytestmark = pytest.mark.unit

MID = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"


def record(state: str = km.PREPARED, ready: bool = True) -> dict:
    return {
        "id": MID,
        "analysis_id": MID,
        "series": "3.2",
        "source": "isc",
        "target_version": "3.2.1-isc20260928103142",
        "from_series": "2.6",
        "state": state,
        "phase": km.PREPARE,
        "driver": "node-a",
        "nodes": [
            {
                "node_id": "node-b",
                "name": "ns2",
                "role": "standby",
                "order": 1,
                "engines": ["kea4", "d2"],
                "packages_before": [{"name": "kea-dhcp4-server", "version": "2.6.3-1+deb13u1"}],
                "rollback_ready": ready,
            },
            {"node_id": "node-a", "name": "ns1", "role": "primary", "order": 2, "rollback_ready": ready},
        ],
    }


def settings_with(rec: dict) -> dict:
    settings: dict = {}
    km.write(settings, km.read_migration({"kea": {"migration": km.to_toml(_raw(rec))}}))
    return settings


def _raw(rec: dict) -> dict:
    out = {k: v for k, v in rec.items() if k != "nodes"}
    out["nodes"] = {n["node_id"]: {k: v for k, v in n.items() if k != "node_id"} for n in rec["nodes"]}
    return out


def test_round_trip_through_cluster_toml(tmp_path) -> None:
    store = ConfigStore(tmp_path / "node.toml", tmp_path / "cluster.toml")
    store.init_cluster(ClusterConfig.new("node:node-a"))
    settings = settings_with(record())
    store.update_cluster(lambda c: c.settings.setdefault("kea", {}).update(settings["kea"]), "test")
    got = km.read_migration(store.load_cluster().settings)
    assert got is not None
    assert [n["name"] for n in got["nodes"]] == ["ns2", "ns1"]  # by order
    assert got["nodes"][0]["packages_before"] == [{"name": "kea-dhcp4-server", "version": "2.6.3-1+deb13u1"}]
    assert got["stage"] is None and got["outage_seconds"] is None and got["error"] is None
    assert got["options"] == {
        "response_delay_milliseconds": None,
        "auto_rollback": None,
    }
    assert "migration" not in ClusterConfig.new("x").settings.get("kea", {})


def test_partial_record_is_no_migration() -> None:
    assert km.read_migration({}) is None
    assert km.read_migration({"kea": {"migration": {"id": MID, "state": "prepared"}}}) is None
    assert km.read_migration({"kea": {"migration": {"id": MID, "series": "3.2", "state": "odd"}}}) is None


def test_moves_follow_the_state_machine() -> None:
    settings = settings_with(record(km.PREPARED))
    moved = km.move(settings, km.MIGRATING, phase=km.MIGRATE, stage="standby")
    assert km.read_migration(settings)["state"] == km.MIGRATING == moved["state"]
    assert km.read_migration(settings)["stage"] == "standby"
    with pytest.raises(km.MigrationStateError, match="cannot move"):
        km.move(settings, km.PREPARED)
    km.move(settings, km.MIGRATED, stage="done")
    km.move(settings, km.ROLLING_BACK, phase=km.ROLLBACK)
    km.move(settings, km.ROLLED_BACK)
    with pytest.raises(km.MigrationStateError):
        km.move(settings, km.MIGRATING)
    km.check_move(km.ROLLED_BACK, km.PREPARING)  # a new migration replaces a finished one
    with pytest.raises(km.MigrationStateError, match="starts with"):
        km.check_move(None, km.MIGRATING)
    with pytest.raises(km.MigrationStateError, match="no Kea migration"):
        km.move({}, km.PREPARED)


@pytest.mark.parametrize(
    "state, phase, ready, refused",
    [
        (None, km.PREPARE, True, False),
        (km.MIGRATING, km.PREPARE, True, True),
        (km.MIGRATED, km.PREPARE, True, False),
        (None, km.MIGRATE, True, True),
        (km.PREPARED, km.MIGRATE, True, False),
        (km.PREPARING, km.MIGRATE, True, True),
        (km.MIGRATED, km.ROLLBACK, True, False),
        (km.MIGRATED, km.ROLLBACK, False, True),
        (km.FAILED, km.ROLLBACK, True, False),
        (km.ROLLED_BACK, km.ROLLBACK, True, True),
        (km.PREPARED, "other", True, True),
    ],
)
def test_phases_allowed_by_state(state, phase, ready, refused) -> None:
    migration = None if state is None else km.read_migration(settings_with(record(state, ready)))
    assert (km.phase_allowed(migration, phase) is not None) is refused


def test_view_hides_packages_and_says_if_rollback_is_possible() -> None:
    migration = km.read_migration(settings_with(record(km.MIGRATED)))
    out = km.view(migration, 180)
    assert out["rollback_possible"] is True and out["outage_max_seconds"] == 180
    assert all(not k.startswith("packages_") for n in out["nodes"] for k in n)
    assert km.view(None) is None
    assert (
        km.view(km.read_migration(settings_with(record(km.MIGRATED, ready=False))))["rollback_possible"]
        is False
    )


def test_lease_copy_is_served_only_to_a_node_of_the_active_migration(tmp_path) -> None:
    settings = settings_with(record(km.MIGRATING))
    path = km.lease_copy_path(tmp_path, MID, "4")
    path.parent.mkdir(parents=True)
    path.write_text("address,hwaddr\n192.0.2.10,02:00:5e:00:53:01\n")
    fd, size = km.open_lease_copy(tmp_path, settings, "node-a", "node-b", MID, "4", 1 << 20)
    os.close(fd)
    assert size == path.stat().st_size
    with pytest.raises(PermissionError):
        km.open_lease_copy(tmp_path, settings, "node-a", "node-c", MID, "4", 1 << 20)
    with pytest.raises(LookupError, match="not part"):
        km.open_lease_copy(tmp_path, settings, "node-c", "node-b", MID, "4", 1 << 20)
    with pytest.raises(LookupError, match="no lease copy"):
        km.open_lease_copy(tmp_path, settings, "node-a", "node-b", MID, "6", 1 << 20)
    with pytest.raises(OverflowError):
        km.open_lease_copy(tmp_path, settings, "node-a", "node-b", MID, "4", 4)
    with pytest.raises(km.MigrationStateError):
        km.lease_copy_path(tmp_path, "../etc", "4")
    path.unlink()
    path.symlink_to(tmp_path / "elsewhere")
    (tmp_path / "elsewhere").write_text("x")
    with pytest.raises(LookupError):
        km.open_lease_copy(tmp_path, settings, "node-a", "node-b", MID, "4", 1 << 20)
    done = settings_with(record(km.MIGRATED))
    with pytest.raises(LookupError, match="no active"):
        km.open_lease_copy(tmp_path, done, "node-a", "node-b", MID, "4", 1 << 20)


def test_every_step_has_a_label() -> None:
    from pelagos.domain import messages

    for step in km.ALL_STEPS:
        assert step_key(step) in messages.CATALOG
        assert km.target(step, "node-a") == f"kea-migration/{step}/node-a"


def step_key(step: str) -> str:
    return km.step_message(step, "ns1")["key"]
