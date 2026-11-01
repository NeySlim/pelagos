# SPDX-License-Identifier: Apache-2.0
"""Partial apply on the reference pair with ns2 powered off (B1-KEAOFFLINE, run before merge).

lab-ns2 is stopped through the Proxmox API (pve_vm), not only Kea: the survivor's DHCP service is
measured from lab-client while the partial plan reloads Kea on ns1 (HA waiting then partner-down).
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
        raise NotImplementedError

    def test_02_partial_reservation_on_ns1_and_dhcp_service_gap_measured(self):
        raise NotImplementedError

    def test_03_divergence_alert_names_the_plan(self):
        raise NotImplementedError

    def test_04_ns2_powered_on_writes_wait_for_reconciliation(self):
        raise NotImplementedError

    def test_05_reconcile_from_ns1_then_config_get_identical(self):
        raise NotImplementedError

    def test_06_partial_plan_rolled_back_after_reconcile_is_refused_by_the_hash_guard(self):
        raise NotImplementedError
