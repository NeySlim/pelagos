# SPDX-License-Identifier: Apache-2.0
"""Advanced editor description of the Dhcp4, Dhcp6 and DhcpDdns objects, per Kea series.

The JSON files in `schemas/` are hand-written from the Kea ARM and checked
against real config-get output; `GET /advanced/kea/{family}/schema` serves
`config_schema()` for the version the server reports.
"""

from __future__ import annotations

import copy
import json
from functools import cache
from pathlib import Path
from typing import Any

from pelagos.connectors.kea.config import version_tuple

SCHEMA_DIR = Path(__file__).with_name("schemas")
SERIES = ("2.6", "3")
DAEMONS = {
    "v4": "Dhcp4",
    "v6": "Dhcp6",
    "d2": "DhcpDdns",
    "Dhcp4": "Dhcp4",
    "Dhcp6": "Dhcp6",
    "DhcpDdns": "DhcpDdns",
}


def series_for(version: str | None) -> str:
    """2.6 and older 2.x servers use the 2.6 description; 3.x and unknown versions the 3 one."""
    return "2.6" if version_tuple(version) < (3,) else "3"


@cache
def _load(series: str) -> dict[str, Any]:
    return json.loads((SCHEMA_DIR / f"kea-{series}.json").read_text())


def config_schema(daemon: str, version: str | None = None) -> dict[str, Any]:
    """Keys of one daemon object plus the shared object shapes; `daemon` is v4, v6, d2 or a root key."""
    root = DAEMONS.get(daemon)
    if root is None:
        raise KeyError(f"unknown Kea daemon {daemon!r}")
    series = series_for(version)
    data = _load(series)
    return {
        "root": root,
        "series": series,
        "version": version,
        "applies_to": data["applies_to"],
        "doc": data["daemons"][root]["doc"],
        "keys": copy.deepcopy(data["daemons"][root]["keys"]),
        "objects": copy.deepcopy(data["objects"]),
        "notes": data["notes"],
    }


def unknown_keys(config: dict[str, Any], daemon: str, version: str | None = None) -> list[str]:
    """Top-level keys the description does not know; they are preserved, the editor flags them."""
    known = config_schema(daemon, version)["keys"]
    return sorted(k for k in config if k not in known)
