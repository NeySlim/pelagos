# SPDX-License-Identifier: Apache-2.0
"""Changed default of auth.api_token_audit_reads_enabled (decision D5): value migration in
settings_registry.migrate (section 10, "Changed defaults"). Contract skeleton."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

TODO = "B1-AUDIT: contract skeleton, implemented after the contract review"


@pytest.mark.skip(reason=TODO)
def test_new_cluster_does_not_audit_token_reads():
    """Registry default false; a GET with a token writes no auth.token_call, a POST still does."""


@pytest.mark.skip(reason=TODO)
def test_stored_true_from_cluster_creation_becomes_false():
    """Stamp equal to the creation stamp: migrated, returned as (key, key)."""


@pytest.mark.skip(reason=TODO)
def test_stored_true_filled_from_defaults_without_stamp_becomes_false():
    """A setting added by a later release (no stamp) counts as never chosen."""


@pytest.mark.skip(reason=TODO)
def test_pre_merge_file_true_becomes_false():
    """No [replication] table: migrated, no stamp written."""


@pytest.mark.skip(reason=TODO)
def test_true_written_by_an_operator_is_kept():
    """Turned off then on again after creation (later stamp): stays true, nothing returned."""


@pytest.mark.skip(reason=TODO)
def test_false_is_always_kept():
    """Explicit false: untouched."""


@pytest.mark.skip(reason=TODO)
def test_migrated_stamp_is_deterministic_and_sorts_after_the_old_one():
    """<oldest settings counter>@~defaults on every node: same digest on two nodes without a write."""


@pytest.mark.skip(reason=TODO)
def test_older_node_merge_adopts_the_new_default():
    """Migrated file merged into an unmigrated 0.3.x state (merge_states, no migrate): false wins."""


@pytest.mark.skip(reason=TODO)
def test_operator_write_after_migration_wins_everywhere():
    """A later true from a 0.3.x node or an upgraded one beats the ~defaults stamp and is kept on reload."""


@pytest.mark.skip(reason=TODO)
def test_migrate_settings_writes_once_and_audits_the_value_migration():
    """migrate_settings: one write, admin.settings.op with renamed {key: key}; a second call: nothing."""


@pytest.mark.skip(reason=TODO)
def test_migration_does_not_bump_the_version():
    """Version and header unchanged, like the renames, so peers migrating on their own converge."""
