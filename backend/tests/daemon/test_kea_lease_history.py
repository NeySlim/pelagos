# SPDX-License-Identifier: Apache-2.0
"""Lease history against a real kea-dhcp4: add, renew, delete, reassign; live pass cost with 5000 leases."""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.daemon, pytest.mark.skip(reason="B1-LEASEHIST contract: tests land with the code")]


def test_contract_placeholder() -> None:
    raise AssertionError("not implemented")
