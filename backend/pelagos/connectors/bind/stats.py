# SPDX-License-Identifier: Apache-2.0
"""statistics-channel JSON client (BIND 9 /json/v1), reduced into BindInstanceStats."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from pelagos.connectors.base import ConnectorTimeout, ConnectorUnavailable
from pelagos.domain.common import from_rfc3339, utcnow
from pelagos.domain.dns import BindInstanceStats


class StatsClient:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def fetch(self, path: str = "") -> dict[str, Any]:
        # BIND answers /json/v1 and /json/v1/server but not /json/v1/ (trailing slash is a 404).
        url = self.base_url + path
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:  # noqa: S310 (local http only)
                return json.load(resp)
        except TimeoutError as exc:
            raise ConnectorTimeout(f"statistics channel timed out: {url}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ConnectorUnavailable(f"statistics channel unreachable: {exc}") from exc

    def instance_stats(self, node_id: str) -> BindInstanceStats:
        data = self.fetch("")
        views = data.get("views", {})
        zones: dict[str, dict[str, int]] = {}
        for view_name, view in views.items():
            for zone in view.get("zones", []):
                key = f"{view_name}/{zone.get('name')}"
                counters = {k: v for k, v in zone.items() if isinstance(v, int)}
                counters.update({k: v for k, v in zone.get("rcodes", {}).items()})
                zones[key] = counters
        return BindInstanceStats(
            node_id=node_id,
            collected_at=utcnow(),
            version=data.get("version"),
            boot_time=from_rfc3339(data["boot-time"]) if data.get("boot-time") else None,
            config_time=from_rfc3339(data["config-time"]) if data.get("config-time") else None,
            opcodes=data.get("opcodes", {}),
            rcodes=data.get("rcodes", {}),
            qtypes=data.get("qtypes", {}),
            nsstats=data.get("nsstats", {}),
            zonestats=data.get("zonestats", {}),
            resstats=data.get("resstats", {}),
            sockstats=data.get("sockstats", {}),
            memory=data.get("memory", {}).get("TotalUse", {}) if isinstance(data.get("memory"), dict) else {},
            zones=zones,
            raw=data,
        )
