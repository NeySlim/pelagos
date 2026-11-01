# SPDX-License-Identifier: Apache-2.0
"""Partial apply on a real Kea HA pair over real mTLS (B1-KEAOFFLINE, sections 6 and 9)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.daemon
# Contract skeleton: each test leaves xfail as B1-KEAOFFLINE implements it.
TODO = pytest.mark.xfail(strict=True, reason="B1-KEAOFFLINE not implemented yet")


@TODO
def test_partner_offline_partial_apply_then_reconcile(tmp_root):
    """Two Pelagos nodes, each with its kea-dhcp4 of one hot-standby relationship (ha_pair):
    1. stop node 2's replication service and its kea-dhcp4; wait for node 1's Kea to see the
       partner lost; a reservation plan answers 409 node_unreachable (partial_allowed);
    2. apply with partial and confirm: applied on node 1, plan partial, skipped [node 2], the
       kea_partials record written, alert kea4:config-hash warning with expected_from_plan;
    3. a second plan with node 2 still away: node_unreachable, then a second partial (one record);
    4. restart node 2: the record has reached it; a plan built on node 2 answers reconcile_required;
       the alert turns critical;
    5. reconcile plan from node 1 to node 2 applied: shared views equal, settled_by set, alert gone;
    6. rollback of the partial plan: 409 plan_state;
    7. non-regression: the same step 1 without partial leaves node 1 untouched."""
    raise NotImplementedError


@TODO
def test_kea_stopped_pelagos_running_opens_the_partial(tmp_root):
    """Node 2's kea-dhcp4 stopped, its Pelagos up: preflight code engine_down, skippable once node
    1's Kea sees the partner lost; skipped reason engine_down."""
    raise NotImplementedError


@TODO
def test_pelagos_stopped_kea_running_refuses_the_partial(tmp_root):
    """Node 2's replication service stopped, its Kea up and in touch: 409 node_unreachable with
    partial_allowed false and reason ha_partner_in_touch, even with partial: true."""
    raise NotImplementedError


@TODO
def test_partial_subnet_with_a_lease_then_partner_back(tmp_root):
    """A subnet added in partial on node 1, a lease obtained there, node 2 back: HA state watched for
    two minutes with a renewing client. If the relationship terminates, reconcile then the HA repair
    plan bring it back to hot-standby. Outcome (terminated or not, after how many rejected updates)
    recorded for docs/user/dhcp.md; config-get shared views equal at the end."""
    raise NotImplementedError


@TODO
def test_kea3_partial_reservation_goes_through_host_cmds_without_reload(tmp_root):
    """Kea 3.x with host_cmds: the partial reservation is applied by commands (no config-set in the
    result), the survivor's HA state never leaves partner-down, no ha_restart impact."""
    raise NotImplementedError
