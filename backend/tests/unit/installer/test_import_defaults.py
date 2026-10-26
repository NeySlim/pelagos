# SPDX-License-Identifier: Apache-2.0
"""Which engines `import` adopts when none is named."""

from __future__ import annotations

import pytest

from pelagos.installer.detect import import_defaults

pytestmark = pytest.mark.unit


def _d(installed=True, config=True, running=False, enabled=False):
    return {"installed": installed, "config_exists": config, "running": running, "enabled": enabled}


def test_inactive_daemon_with_only_the_package_config_is_skipped():
    found = {
        "bind": _d(running=True, enabled=True),
        "kea4": _d(running=True),
        "kea6": _d(),
        "d2": _d(enabled=True),
    }
    selected, skipped = import_defaults(found)
    assert selected == ["bind", "kea4", "d2"]
    assert list(skipped) == ["kea6"] and "neither running nor enabled" in skipped["kea6"]


def test_missing_config_is_reported_and_missing_package_is_silent():
    selected, skipped = import_defaults({"bind": _d(config=False, running=True), "kea4": _d(installed=False)})
    assert selected == []
    assert skipped == {"bind": "no configuration file"}
