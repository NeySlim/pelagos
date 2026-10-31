# SPDX-License-Identifier: Apache-2.0
"""ConfigStore bases file and conflict callbacks; replication.conflict audit entries (section 13)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

SKIP = pytest.mark.skip(reason="F0-REPL: contract, implemented next")


@SKIP
def test_bases_file_follows_writes_and_merges():
    """update_cluster records [stamp, base, by]; merge keeps the winner's base; stale items pruned."""


@SKIP
def test_damaged_bases_file_reads_as_empty():
    """A broken cluster.bases.json disables detection only; writes and merges go on."""


@SKIP
def test_merge_remote_calls_on_conflict_once_per_discarded_entry():
    """on_conflict gets the Discarded list of a merge that changed the file, nothing otherwise."""


@SKIP
def test_conflict_audit_entry_shape():
    """replication.conflict, target config:<path>, user system, request local/remote with by, base."""


@SKIP
def test_conflict_audit_masks_secrets_and_hashes():
    """secrets/*, password_hash, totp_secret, secret_hash, public_key and collection secret_fields: ***."""


@SKIP
def test_conflict_audit_is_rate_limited_per_path_and_minute():
    """Second conflict of a path within a minute: no entry; the next one carries suppressed = 1."""


@SKIP
def test_repl_config_exchanges_bases_and_tolerates_their_absence():
    """GET /repl/v1/config answers bases; PUT without bases (older node) merges, reports nothing."""


@SKIP
def test_status_lists_known_collections():
    """/repl/v1/status answers collections, sorted; a status without it reads as none."""


@SKIP
def test_a_masked_value_never_reaches_the_audit_line():
    """grep of the password hash on the JSONL written."""


@SKIP
def test_status_parses_missing_collections_as_none():
    """PeerStatus.collections is None for an older node's status."""


@SKIP
def test_migrate_settings_leaves_bases_alone():
    """migrate_settings does not touch cluster.bases.json."""
