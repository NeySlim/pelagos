# SPDX-License-Identifier: Apache-2.0
"""Sealed yearly audit segments: rotation, seal, verification, reads over the union, followers,
retention (section 11, "Sealed segments"). Contract skeleton: each test names one rule."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

TODO = "B1-AUDIT: contract skeleton, implemented after the contract review"


# Rotation -------------------------------------------------------------------------------------


@pytest.mark.skip(reason=TODO)
def test_rotation_renames_the_live_file_and_starts_an_empty_one():
    """audit.jsonl becomes audit-<year>.jsonl with the same bytes and inode; a new empty live file."""


@pytest.mark.skip(reason=TODO)
def test_scheduled_rotation_names_the_closed_year_and_on_demand_the_current_one():
    """Due on 2027-01-01 with entries of 2026: audit-2026.jsonl; on demand in 2026: audit-2026.jsonl."""


@pytest.mark.skip(reason=TODO)
def test_a_second_rotation_in_a_year_gets_the_next_suffix():
    """audit-2026.jsonl taken: audit-2026-2.jsonl, then audit-2026-3.jsonl."""


@pytest.mark.skip(reason=TODO)
def test_rotation_is_due_only_when_the_oldest_live_entry_is_from_an_earlier_year():
    """Empty live file or entries of this UTC year only: not due; one entry of last year: due."""


@pytest.mark.skip(reason=TODO)
def test_rotation_writes_an_audit_rotate_entry_with_the_chain():
    """audit.rotate on audit:<segment>, request {segment, year, entries, bytes, first_id, last_id, chain}."""


@pytest.mark.skip(reason=TODO)
def test_append_waiting_on_the_lock_during_rotation_lands_in_the_new_live_file():
    """A concurrent append is neither lost nor written to the segment."""


@pytest.mark.skip(reason=TODO)
def test_crash_after_rename_leaves_an_unsealed_segment_that_the_next_run_seals():
    """Segment without seal: read like any segment, sealed by the next task run, same chain."""


# Seal and verification ------------------------------------------------------------------------


@pytest.mark.skip(reason=TODO)
def test_seal_records_bytes_lines_entries_range_node_and_chain():
    """Seal fields match the segment; chain is h_n of the documented recurrence (vector test)."""


@pytest.mark.skip(reason=TODO)
def test_seal_covers_a_damaged_line():
    """A line damaged by a crash is chained as bytes and counted in lines, not in entries."""


@pytest.mark.skip(reason=TODO)
def test_verify_passes_on_an_untouched_segment():
    """verify(segment) is ok, reason None."""


@pytest.mark.skip(reason=TODO)
@pytest.mark.parametrize(
    "tamper, reason",
    [
        ("flip_one_byte", "chain"),
        ("drop_last_line", "length"),
        ("append_a_line", "length"),
        ("delete_seal", "missing_seal"),
        ("garble_seal", "seal_damaged"),
        ("seal_of_another_segment", "seal_damaged"),
        ("rewrite_segment_and_seal", "anchor"),
    ],
)
def test_verify_detects_each_alteration(tamper, reason):
    """Each alteration fails with its reason; segment and seal rewritten together fail on the anchor."""


@pytest.mark.skip(reason=TODO)
def test_verify_without_an_anchor_entry_reports_it_without_failing():
    """No audit.rotate entry for the segment (crash before step 3): ok, with a note."""


@pytest.mark.skip(reason=TODO)
def test_anchor_is_matched_on_the_seal_node_only():
    """Another node's audit.rotate for a segment of the same name is not this seal's anchor."""


# Reads over the union -------------------------------------------------------------------------


@pytest.mark.skip(reason=TODO)
def test_get_audit_pages_across_two_segments_and_the_live_file_in_order():
    """query() newest first over 2025, 2026 segments and live file: pages, total, order by (ts, id)."""


@pytest.mark.skip(reason=TODO)
def test_read_after_id_ids_head_and_get_many_cover_the_segments():
    """Replication reads (read, ids, sorted_ids, head, get_many) are the same before and after rotation."""


@pytest.mark.skip(reason=TODO)
def test_query_filters_cover_the_segments():
    """plan_id (F0-PLANS), action prefix with since (replication_conflict check), user, target."""


@pytest.mark.skip(reason=TODO)
def test_plan_summary_entry_shape_is_unchanged():
    """The summary entry of an applied plan reads back with the same keys and values after rotation."""


@pytest.mark.skip(reason=TODO)
def test_merge_skips_ids_held_by_a_segment_and_writes_new_ones_to_the_live_file():
    """An entry of a rotated year merged later goes to the live file, never to the segment."""


@pytest.mark.skip(reason=TODO)
def test_an_id_present_in_two_files_counts_once():
    """head() count and ids() dedupe; the first file in name order wins on get()."""


@pytest.mark.skip(reason=TODO)
def test_segment_index_is_built_once_and_survives_the_rename():
    """A second process' reader keeps its index items across a rotation (by inode), no full rebuild."""


@pytest.mark.skip(reason=TODO)
def test_export_of_a_segment_range_is_byte_identical_before_and_after_rotation():
    """export_lines(since, until) over the year rotated: same bytes; full export too."""


@pytest.mark.skip(reason=TODO)
def test_export_skips_segments_outside_the_range_by_their_seal():
    """A range in 2026 never opens audit-2024.jsonl (seal range checked first)."""


# Followers ------------------------------------------------------------------------------------


@pytest.mark.skip(reason=TODO)
def test_scan_returns_each_entry_once_across_a_rotation():
    """Cursor on the old live file: its tail from the renamed segment, then the new live file."""


@pytest.mark.skip(reason=TODO)
def test_scan_with_an_unknown_inode_reads_the_live_file_from_the_start():
    """Segment purged or file replaced by a restore: the pre-0.4.0 behaviour."""


@pytest.mark.skip(reason=TODO)
def test_scan_sees_a_merged_entry_of_a_rotated_year():
    """A peer's auth.logout dated 31 December merged after the rotation is returned by scan."""


@pytest.mark.skip(reason=TODO)
def test_tail_since_spans_the_last_segment_and_hands_a_cursor_to_scan():
    """tail(now - ttl, needle) on 1 January returns December entries; scan from its cursor misses nothing."""


# Retention, disk alert ------------------------------------------------------------------------


@pytest.mark.skip(reason=TODO)
def test_segments_are_never_purged_by_default():
    """retention.audit_sealed_years = 0: every segment stays, whatever its age."""


@pytest.mark.skip(reason=TODO)
def test_purge_deletes_old_segments_after_an_audit_purge_entry():
    """N = 2 in 2030: audit-2027 and older go, with their seals, each after one audit.purge entry."""


@pytest.mark.skip(reason=TODO)
def test_merge_drops_entries_older_than_the_purge_horizon():
    """With N > 0 a peer cannot bring purged entries back; with N = 0 nothing is dropped."""


@pytest.mark.skip(reason=TODO)
def test_audit_growth_alert_watches_the_live_file_only():
    """checks.audit_max_mb: large segments do not raise audit_growth, a large live file does."""


# CLI ------------------------------------------------------------------------------------------


@pytest.mark.skip(reason=TODO)
def test_cli_verify_exits_1_on_a_failed_seal_and_prints_the_reason():
    """pelagos audit-log verify: 0 when every segment passes, 1 and the reason otherwise."""


@pytest.mark.skip(reason=TODO)
def test_cli_rotate_marks_its_entry_on_demand():
    """pelagos audit-log rotate: audit.rotate with on_demand true, user local:<name>."""


@pytest.mark.skip(reason=TODO)
def test_security_audit_command_is_unchanged():
    """pelagos audit (security audit) keeps its arguments; the log has its own command."""
