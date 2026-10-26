# SPDX-License-Identifier: Apache-2.0
"""Thresholds of the health checks: cluster.toml [settings.checks] over the shipped defaults."""

from __future__ import annotations

from typing import Any

from pelagos.core.config_store import DEFAULT_SETTINGS

DEFAULTS: dict[str, Any] = dict(DEFAULT_SETTINGS["checks"])


class CheckSettings:
    """Read-only view: unknown or missing keys fall back to the default."""

    def __init__(self, settings: dict[str, Any] | None = None) -> None:
        own = (settings or {}).get("checks") or {}
        self._values = {**DEFAULTS, **{k: v for k, v in own.items() if k in DEFAULTS}}

    def __getattr__(self, name: str) -> Any:
        try:
            return self._values[name]
        except KeyError:
            raise AttributeError(name) from None
