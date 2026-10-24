# SPDX-License-Identifier: Apache-2.0
"""Install BIND and/or Kea from the distro or the ISC Cloudsmith repositories (POST /install/plan)."""

from __future__ import annotations

from typing import Any

from pelagos.domain import Job, Plan
from pelagos.platform import Distro, PlatformPaths


def plan_install(
    distro: Distro,
    paths: PlatformPaths,
    engines: list[str],
    source: str,
    isc_series: str | None,
    created_by: str,
    node_id: str,
) -> Plan:
    """Scope INSTALL: packages, repositories, sockets, statistics-channel and include files to lay down."""
    raise NotImplementedError("WP-INSTALLER")


def run_install(plan: Plan, job: Job, progress: Any) -> Job:
    """Long-running apply; reports steps through `progress(job)` for the jobs WebSocket topic."""
    raise NotImplementedError("WP-INSTALLER")
