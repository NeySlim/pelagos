# SPDX-License-Identifier: Apache-2.0
"""Discovery pass, `unknown_device` and the OUI table (section 27, IPv4 neighbors and discovery)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

PENDING = "B1-DISCOVERY: contract first, implementation next"


@pytest.mark.skip(reason=PENDING)
def test_unknown_device_opens_after_the_delay_and_resolves_with_a_lease(): ...


@pytest.mark.skip(reason=PENDING)
def test_vendor_of_a_raspberry_pi(): ...


@pytest.mark.skip(reason=PENDING)
def test_oui_table_is_not_read_at_import(): ...
