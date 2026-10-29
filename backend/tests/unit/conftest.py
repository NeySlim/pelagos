# SPDX-License-Identifier: Apache-2.0
"""Unit tier: the test host's own IPv6 addresses never become watched prefixes."""

from __future__ import annotations

import pytest

from pelagos.collector.ipv6 import prefixes


@pytest.fixture(autouse=True)
def _no_node_prefixes(monkeypatch):
    monkeypatch.setattr(prefixes, "interface_networks", lambda runner=None: [])
