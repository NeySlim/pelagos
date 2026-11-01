# SPDX-License-Identifier: Apache-2.0
"""IPv4 neighbor source and table (section 27, IPv4 neighbors and discovery)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

PENDING = "B1-DISCOVERY: contract first, implementation next"


@pytest.mark.skip(reason=PENDING)
def test_parse_ip_4_neigh_keeps_reachable_and_stale_entries(): ...


@pytest.mark.skip(reason=PENDING)
def test_ipv6_neighbors_module_is_the_generic_one(): ...


@pytest.mark.skip(reason=PENDING)
def test_record_moves_last_seen_but_not_for_stale(): ...
