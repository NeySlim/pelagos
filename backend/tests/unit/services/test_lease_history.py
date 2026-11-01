# SPDX-License-Identifier: Apache-2.0
"""Lease history reads: filters, merge of local and peer rows, the API routes."""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.skip(reason="B1-LEASEHIST contract: tests land with the code")]


def test_contract_placeholder() -> None:
    raise AssertionError("not implemented")
