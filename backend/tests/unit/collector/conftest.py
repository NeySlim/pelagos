# SPDX-License-Identifier: Apache-2.0
"""The unit tier never reads the host's package database nor fetches the Debian tracker."""

from __future__ import annotations

import pytest

from pelagos.collector.checks import distro


@pytest.fixture(autouse=True)
def _no_host_packages(monkeypatch):
    monkeypatch.setattr(distro, "read_package", lambda engine, run=None: None)
    monkeypatch.setattr(distro, "fetch_debian_tracker", lambda url, var_dir, timeout=60.0: False)
