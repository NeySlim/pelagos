# SPDX-License-Identifier: Apache-2.0
"""Partial apply on a real Kea HA pair over real mTLS (B1-KEAOFFLINE): the partner node stops,
a reservation is applied on the survivor only, the divergence alert opens, the partner comes back,
the reconcile plan applies, the divergence closes and both config-get agree."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.daemon
# Contract skeleton: leaves xfail as B1-KEAOFFLINE implements it.
TODO = pytest.mark.xfail(strict=True, reason="B1-KEAOFFLINE not implemented yet")


@TODO
def test_partner_offline_partial_apply_then_reconcile(tmp_root):
    """Two Pelagos nodes, each with its kea-dhcp4 of one hot-standby relationship (ha_pair). Steps:
    1. stop node 2's replication service and its kea-dhcp4 (node 2 offline as Pelagos sees it);
    2. reservation plan on node 1: apply answers 409 node_unreachable naming node 2;
    3. apply with partial and confirm: applied on node 1, plan partial, skipped [node 2];
    4. collector pass on node 1: config_divergence kea4:config-hash with expected_from_plan;
    5. a second reservation plan to both, node 2 still down: node_unreachable again;
    6. restart node 2: a plan to both answers 409 config_divergence with reconcile;
    7. reconcile plan from node 1 to node 2, applied: config-get shared views equal, alert gone;
    8. without partial, the same scenario at step 2 leaves node 1 untouched (non-regression)."""
    raise NotImplementedError
