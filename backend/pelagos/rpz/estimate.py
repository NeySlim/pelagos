# SPDX-License-Identifier: Apache-2.0
"""Memory estimate of named for RPZ subscriptions, and the warning for a small node."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pelagos.rpz import model

MB = 1_000_000


def entries_mb(entries: int, bytes_per_entry: int) -> float:
    return round(entries * bytes_per_entry / MB, 1)


def node_ram_mb(meminfo: Path = Path("/proc/meminfo")) -> int | None:
    try:
        for line in meminfo.read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def assess(entries: list[int], ram_mb: int | None, cfg: dict[str, Any]) -> dict[str, Any]:
    """Estimate for lists of the given sizes on a node with `ram_mb` of memory.

    named loads the new copy of a zone before dropping the old one, so the peak adds the largest list.
    """
    per = int(cfg.get("bytes_per_entry", model.DEFAULTS["bytes_per_entry"]))
    total = sum(entries)
    steady = entries_mb(total, per)
    peak = entries_mb(total + (max(entries) if entries else 0), per)
    out: dict[str, Any] = {
        "entries": total,
        "memory_mb": steady,
        "peak_mb": peak,
        "ram_mb": ram_mb,
        "percent_of_ram": None,
        "level": "ok",
    }
    if not ram_mb:
        return out
    percent = round(peak * 100 / ram_mb, 1)
    out["percent_of_ram"] = percent
    warn = float(cfg.get("memory_warn_percent", model.DEFAULTS["memory_warn_percent"]))
    small = ram_mb <= int(cfg.get("small_node_mb", model.DEFAULTS["small_node_mb"]))
    if percent >= warn:
        out["level"] = "high"
    elif small and percent >= warn / 2:
        out["level"] = "caution"
    return out
