# SPDX-License-Identifier: Apache-2.0
"""Sealed audit segments on a pair in mixed versions: ns1 and ns2 on the previous release, ns1
upgraded to the deb of this checkout (token reads default migrated, ns2 adopts it), ns1 rotated on
demand while ns2 still runs the previous release (audit replicated both ways, entries of the
rotated year merged after it, the export of the segment unchanged, a tampered segment detected),
then ns2 upgraded and rotated too. Contract skeleton (B1-AUDIT)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.lab

TODO = "B1-AUDIT: contract skeleton, implemented after the contract review"


@pytest.mark.skip(reason=TODO)
class TestAuditSegmentsOnThePair:
    def test_00_rollback_and_provision(self):
        """Roll back ns1 and ns2, install the previous release on both, init ns1, enroll ns2."""

    def test_01_writes_and_token_reads_on_the_previous_release(self):
        """A record written on each node, an API token GET on ns1: auth.token_call audited; counts equal."""

    def test_02_upgrade_ns1_migrates_the_token_reads_default(self):
        """ns1 on this deb: admin.settings.op migrate entry; the setting reads false on ns1 and on ns2
        (0.3.x adopted it at the next merge); a token GET on ns1 and on ns2 is no longer audited."""

    def test_03_rotate_on_ns1_while_ns2_is_on_the_previous_release(self):
        """Export NDJSON of ns1 saved; `pelagos audit-log rotate`; GET /audit/segments lists a sealed
        segment, verify ok; the export of the same range is byte-identical; ns2 holds audit.rotate."""

    def test_04_audit_replicates_both_ways_after_the_rotation(self):
        """Writes on both nodes; counts and heads equal; no error in either journal; ns2 receives the
        unknown action without complaint; GET /audit on ns1 pages across segment and live file."""

    def test_05_ns2_stopped_then_caught_up_after_the_rotation(self):
        """ns2 stopped, writes on ns1, rotation on ns1 again (-2 suffix), ns2 started: it gets every entry."""

    def test_06_tampered_segment_is_detected(self):
        """One byte flipped in a segment on ns1: verify fails with chain, CLI exits 1; byte restored."""

    def test_07_upgrade_ns2_and_rotate_there(self):
        """ns2 on this deb, rotated on demand; both nodes converge; the anchors of both nodes verify."""
