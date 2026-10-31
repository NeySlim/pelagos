# SPDX-License-Identifier: Apache-2.0
"""core.collections: the registry of generic replicated collections (section 10)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

SKIP = pytest.mark.skip(reason="F0-REPL: contract, implemented next")


@SKIP
def test_registry_names_follow_the_rules():
    """snake_case plural, never a core section or a header key, identity key a plain field name."""


@SKIP
def test_records_include_core_lists_and_every_collection():
    """cluster_merge.records() = RECORDS plus each COLLECTIONS key; RECORDS itself unchanged."""


@SKIP
def test_cluster_config_loads_and_writes_a_collection():
    """from_toml keeps records with their identity, drops the others; to_toml writes it after api_tokens."""


@SKIP
def test_collection_accessors():
    """collection(name) is the live list, KeyError when unregistered; record(name, rid) finds one."""


@SKIP
def test_update_collection_stamps_and_tombstones():
    """ConfigStore.update_collection: new records stamped, edited fields restamped, removed tombstoned."""


@SKIP
def test_peers_missing_counts_older_and_unaware_peers():
    """No collections member or a list without the name: missing; unreachable peers do not block."""
