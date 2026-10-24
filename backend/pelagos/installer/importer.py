# SPDX-License-Identifier: Apache-2.0
"""Adopt an existing configuration without rewriting it (POST /install/import/plan).

The plan lists what was read (named-checkconf -p, config-get), the two include
lines to add, the Kea control sockets and statistics-channel to add when
missing, and the Pelagos TSIG keys to create. Nothing else is touched.
"""

from __future__ import annotations

from pelagos.domain import Plan
from pelagos.platform import PlatformPaths


def plan_import(paths: PlatformPaths, engines: list[str], created_by: str, node_id: str) -> Plan:
    raise NotImplementedError("WP-INSTALLER")


def verify_import(paths: PlatformPaths, engines: list[str]) -> dict[str, bool]:
    """Gate 1 of the design: the configuration read back equals the configuration adopted."""
    raise NotImplementedError("WP-INSTALLER")
