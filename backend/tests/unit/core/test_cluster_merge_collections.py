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
