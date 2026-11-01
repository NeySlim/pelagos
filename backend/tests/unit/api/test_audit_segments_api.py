# SPDX-License-Identifier: Apache-2.0
"""GET /audit/segments, POST /audit/segments/{name}/verify and the export over segments
(section 17, Audit). Contract skeleton."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

TODO = "B1-AUDIT: contract skeleton, implemented after the contract review"


@pytest.mark.skip(reason=TODO)
def test_segments_lists_segments_live_file_and_retention():
    """Two segments and the live file, each with its size; seal content inline; read:audit required."""


@pytest.mark.skip(reason=TODO)
def test_segments_route_is_not_taken_for_an_entry_id():
    """GET /audit/segments never answers as GET /audit/{id}."""


@pytest.mark.skip(reason=TODO)
def test_verify_answers_ok_then_chain_after_a_flipped_byte():
    """200 {ok: true, reason: null}, then {ok: false, reason: "chain"}; no audit entry written."""


@pytest.mark.skip(reason=TODO)
def test_verify_unknown_segment_is_404_and_a_path_is_refused():
    """Unknown name: 404 not_found; "../cluster.toml" or any name outside the pattern: 404, nothing read."""


@pytest.mark.skip(reason=TODO)
def test_verify_and_segments_need_read_audit():
    """403 without read:audit."""


@pytest.mark.skip(reason=TODO)
def test_audit_get_pages_across_segments():
    """GET /audit after a rotation: total and pages span the segment and the live file."""


@pytest.mark.skip(reason=TODO)
def test_export_ndjson_is_identical_before_and_after_rotation():
    """GET /audit/export?from=&to= over the rotated year: same body."""
