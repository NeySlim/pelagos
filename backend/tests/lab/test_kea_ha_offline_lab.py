# SPDX-License-Identifier: Apache-2.0
"""Partial apply on the reference pair with ns2 powered off (B1-KEAOFFLINE, run before merge).

lab-ns2 is stopped through the Proxmox API (pve_vm), not only Kea; the pair runs Debian's Kea 2.6.3
(config-set path). The survivor's DHCP gap is measured from lab-client with a client that retries.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.lab
# Contract skeleton: leaves xfail as B1-KEAOFFLINE implements it.
TODO = pytest.mark.xfail(strict=True, reason="B1-KEAOFFLINE not implemented yet")


@TODO
class TestKeaHaOffline:
    def test_00_rollback_and_provision(self):
        raise NotImplementedError

    def test_01_ns2_powered_off_apply_answers_node_unreachable(self):
        """After ns1's Kea sees the partner lost: partial_allowed true, reason unreachable."""
        raise NotImplementedError

    def test_02_partial_reservation_on_ns1_and_dhcp_gap_measured(self):
        """Gap expected near max-response-delay + heartbeat-delay; again with max-unacked-clients 0."""
        raise NotImplementedError

    def test_03_divergence_alert_names_the_plan(self):
        raise NotImplementedError

    def test_04_ns2_powered_on_writes_answer_reconcile_required(self):
        raise NotImplementedError

    def test_05_reconcile_from_ns1_then_config_get_identical(self):
        raise NotImplementedError

    def test_06_rollback_of_the_reconciled_partial_is_refused(self):
        """plan_state after a reconcile from ns1; variant reconcile from ns2: precondition_failed."""
        raise NotImplementedError

    def test_07_ns2_back_with_a_lease_of_the_partial_subnet(self):
        """HA state recorded until the reconciliation; the pair ends in hot-standby, no ha_terminated,
        no config-write on a file with includes."""
        raise NotImplementedError
