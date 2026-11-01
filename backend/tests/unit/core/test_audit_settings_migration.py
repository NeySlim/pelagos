# SPDX-License-Identifier: Apache-2.0
"""Changed default of auth.api_token_audit_reads_enabled (decision D5): value migration in
settings_registry.migrate (section 10, "Changed defaults")."""

from __future__ import annotations

import copy
import tomllib
from typing import Any

import pytest
import tomli_w

from pelagos.core import cluster_merge as cm
from pelagos.core import settings_registry as reg
from pelagos.core.config_store import ClusterConfig

pytestmark = pytest.mark.unit

KEY = "auth.api_token_audit_reads_enabled"
ENTRY = cm.path_of("settings", "auth", "api_token_audit_reads_enabled")
OTHER = cm.path_of("settings", "auth", "session_ttl_seconds")
N1 = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"


def doc(value: Any = True, stamp: str | None = f"1@{N1}", others: dict[str, str] | None = None) -> dict:
    auth: dict[str, Any] = {"session_ttl_seconds": 43200}
    if value is not None:
        auth["api_token_audit_reads_enabled"] = value
    stamps = {OTHER: f"1@{N1}", **(others or {})}
    if stamp is not None:
        stamps[ENTRY] = stamp
    return {
        "schema_version": 1,
        "version": 5,
        "updated_by": f"node:{N1}",
        "cluster_id": "c",
        "settings": {"auth": auth},
        "replication": {"stamps": stamps, "tombstones": {}},
    }


def value_of(data: dict) -> Any:
    return data["settings"]["auth"].get("api_token_audit_reads_enabled")


def test_new_cluster_does_not_audit_token_reads():
    assert reg.BY_KEY[KEY].default is False
    assert reg.get({}, KEY) is False


def test_stored_true_from_cluster_creation_becomes_false():
    data = doc()
    assert reg.migrate(data) == [(KEY, KEY)]
    assert value_of(data) is False and data["replication"]["stamps"][ENTRY] == "1@~defaults"


def test_stored_true_filled_from_defaults_without_stamp_becomes_false():
    data = doc(stamp=None)
    assert reg.migrate(data) == [(KEY, KEY)]
    assert value_of(data) is False


def test_unstamped_setting_beside_the_creation_stamp_is_still_migrated():
    """The review's case: another setting stored without stamp (ZERO) must not lower c0."""
    data = doc(others={cm.path_of("settings", "auth", "require_totp"): "0@"})
    data["settings"]["auth"]["require_totp"] = False
    assert reg.migrate(data) == [(KEY, KEY)]
    assert value_of(data) is False


def test_pre_merge_file_true_becomes_false():
    data = doc()
    del data["replication"]
    assert reg.migrate(data) == [(KEY, KEY)]
    assert value_of(data) is False and "replication" not in data


def test_pre_merge_file_stamped_at_its_version_is_migrated():
    data = doc(stamp=f"42@{N1}", others={OTHER: f"42@{N1}"})
    assert reg.migrate(data) == [(KEY, KEY)]
    assert data["replication"]["stamps"][ENTRY] == "42@~defaults"


def test_absent_key_is_inserted_with_the_new_default():
    data = doc(value=None, stamp=None)
    assert reg.migrate(data) == [(KEY, KEY)]
    assert value_of(data) is False and data["replication"]["stamps"][ENTRY] == "1@~defaults"


def test_true_written_by_an_operator_is_kept():
    data = doc(stamp=f"2@{N1}")
    assert reg.migrate(data) == []
    assert value_of(data) is True


def test_false_is_always_kept():
    for stamp in (None, f"1@{N1}", f"7@{N1}"):
        data = doc(value=False, stamp=stamp)
        assert reg.migrate(data) == []
        assert value_of(data) is False


def test_migrate_is_idempotent():
    data = doc()
    reg.migrate(data)
    again = copy.deepcopy(data)
    assert reg.migrate(again) == [] and again == data


def _cfg(data: dict) -> ClusterConfig:
    return ClusterConfig.from_toml(tomllib.loads(tomli_w.dumps(data)))


def test_migrated_stamp_is_deterministic_and_sorts_after_the_old_one():
    a, b = _cfg(doc()), _cfg(doc())
    assert a.digest() == b.digest()
    assert cm.parse_stamp("1@~defaults") > cm.parse_stamp(f"1@{N1}")
    assert cm.parse_stamp("1@~defaults") < cm.parse_stamp(f"2@{N1}")


def _old_state(data: dict) -> cm.State:
    """What a 0.3.x node holds: the file read without any migration."""
    stamps = {k: cm.parse_stamp(v) for k, v in data["replication"]["stamps"].items()}
    body = {k: v for k, v in data.items() if k not in cm.HEADER}
    return cm.state_of(body, stamps, {}, cm.ZERO)


def test_older_node_merge_adopts_the_new_default():
    upgraded = _cfg(doc()).state()
    merged = cm.merge_states(_old_state(doc()), upgraded)
    assert merged.values[ENTRY] is False
    absent = cm.merge_states(
        _old_state(doc(value=None, stamp=None)), _cfg(doc(value=None, stamp=None)).state()
    )
    assert absent.values[ENTRY] is False


def test_operator_write_after_migration_wins_everywhere():
    upgraded = _cfg(doc()).state()
    later = doc(stamp=f"6@{N1}")  # a 0.3.x node turned it on after the upgrade
    merged = cm.merge_states(upgraded, _old_state(later))
    assert merged.values[ENTRY] is True
    assert reg.migrate(later) == [] and value_of(later) is True


def test_migrate_settings_writes_once_and_audits_the_value_migration(node_ctx):
    store = node_ctx.config_store

    def turn_on(cfg):
        cfg.settings["auth"]["api_token_audit_reads_enabled"] = True

    store.update_cluster(turn_on, updated_by=f"node:{node_ctx.node.id}")
    # Rewrite the entry's stamp to the creation counter, as a 0.3.x cluster that never chose it.
    text = store.cluster_path.read_text()
    data = tomllib.loads(text)
    stamps = data["replication"]["stamps"]
    c0 = min(cm.parse_stamp(v)[0] for v in stamps.values() if cm.parse_stamp(v)[0] > 0)
    stamps[ENTRY] = f"{c0}@{node_ctx.node.id}"
    store.cluster_path.write_text(tomli_w.dumps(data))
    version = store.load_cluster().version
    assert node_ctx.migrate_settings() == [(KEY, KEY)]
    assert store.load_cluster().settings["auth"]["api_token_audit_reads_enabled"] is False
    assert store.load_cluster().version == version
    (entry,) = node_ctx.audit_log.query(action="admin.settings.op")[0]
    assert entry.request == {"op": "migrate", "renamed": {KEY: KEY}}
    assert "defaults" in (entry.message or "")
    assert node_ctx.migrate_settings() == []
    assert len(node_ctx.audit_log.query(action="admin.settings.op")[0]) == 1
