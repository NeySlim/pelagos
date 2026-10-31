# SPDX-License-Identifier: Apache-2.0
"""Generic collections through the merge, mixed versions and conflict reports (sections 10 and 13)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

SKIP = pytest.mark.skip(reason="F0-REPL: contract, implemented next")


@SKIP
def test_collection_records_merge_like_users():
    """Concurrent creations on two nodes both kept; a deletion wins over a concurrent field edit."""


@SKIP
def test_a_recreated_record_drops_the_fields_of_its_earlier_incarnation():
    """Fields stamped before the record's new creation never come back."""


@SKIP
def test_an_older_node_ignores_a_collection_and_never_tombstones_it():
    """Simulated older node (name not registered): drops the section, its writes tombstone nothing."""


@SKIP
def test_records_come_back_after_merging_through_an_older_node():
    """New, old, new: records and stamps intact; a deletion on a new node reaches through the old one."""


@SKIP
def test_unknown_section_from_a_newer_release_is_ignored_the_same_way():
    """A section no release here knows: dropped on read, relayed tombstones, never tombstoned."""


@SKIP
def test_concurrent_write_of_the_same_field_is_reported_once():
    """users[alice].roles written on A and B with diverging clocks: one Discarded, on the losing author."""


@SKIP
def test_an_ordinary_edit_of_another_nodes_value_is_not_a_conflict():
    """B edits what A wrote after merging it: the winner's base equals the local stamp, nothing reported."""


@SKIP
def test_unknown_base_is_not_reported():
    """A winner without a base (older node, lost bases file): no conflict."""


@SKIP
def test_field_edit_lost_to_a_concurrent_record_deletion_is_reported():
    """Field stamped after the record tombstone: reason record_deleted; older field: nothing."""


@SKIP
def test_concurrent_username_is_reported_with_reason_username():
    """Two users with one username created on two nodes: the losing author gets reason username."""


@SKIP
def test_merge_report_keeps_merge_commutative():
    """merge_report(a, b).state and merge_report(b, a).state have the same digest as merge_states."""


@SKIP
def test_record_recreated_reports_concurrent_creation_of_a_natural_key():
    """roles/ops created on A and B: the loser gets one record_recreated report."""


@SKIP
def test_causal_recreation_after_a_seen_tombstone_is_not_reported():
    """Re-creation whose base is the tombstone it saw: nothing."""


@SKIP
def test_local_deletion_lost_to_a_concurrent_write_is_reported():
    """Local tombstone against a remote value whose base sorts below it: reason stamp."""


@SKIP
def test_record_deleted_gives_one_entry_per_record_with_masked_fields():
    """Ten fields lost under a deleted record: one report, fields masked one by one."""


@SKIP
def test_merge_report_bases_are_commutative():
    """merge_report(a, b).bases equals merge_report(b, a).bases."""


@SKIP
def test_digest_without_a_collection_equals_an_older_nodes_digest():
    """Older node simulated through TOML text: its digest equals digest(without=[name])."""


@SKIP
def test_two_write_sequence_on_one_node_is_reported_once_on_the_other():
    """40@A, 42@A against 41@B: reported on B only."""


@SKIP
def test_stale_bases_items_are_ignored_when_read():
    """Bases file behind cluster.toml (crash between writes): stale items inert."""


@SKIP
def test_remote_bases_with_foreign_stamps_are_ignored():
    """Received bases whose stamp is not the path's current one: ignored."""
