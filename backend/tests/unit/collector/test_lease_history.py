# SPDX-License-Identifier: Apache-2.0
"""Lease history in the collector: the walk diff, the lease_events table, retention, schema migration."""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.skip(reason="B1-LEASEHIST contract: tests land with the code")]


def test_contract_placeholder() -> None:
    raise AssertionError("not implemented")
