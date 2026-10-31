# SPDX-License-Identifier: Apache-2.0
"""The lab VM constants: defaults unchanged, overridable by PELAGOS_LAB_<ROLE>[_ADDR]."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


def test_defaults_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.lab import labkit

    for role in ("NS1", "PKG_RPM"):
        monkeypatch.delenv(f"PELAGOS_LAB_{role}", raising=False)
        monkeypatch.delenv(f"PELAGOS_LAB_{role}_ADDR", raising=False)
    assert labkit._vm("NS1", "lab-ns1", "10.99.0.11") == ("lab-ns1", "10.99.0.11")


def test_override_alias_and_address(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.lab import labkit

    monkeypatch.setenv("PELAGOS_LAB_PKG_RPM", "alt-pkg")
    monkeypatch.setenv("PELAGOS_LAB_PKG_RPM_ADDR", "192.0.2.9")
    assert labkit._vm("PKG_RPM", "lab-pkg-rpm", "10.99.0.16") == ("alt-pkg", "192.0.2.9")
    monkeypatch.delenv("PELAGOS_LAB_PKG_RPM_ADDR")
    assert labkit._vm("PKG_RPM", "lab-pkg-rpm", "10.99.0.16") == ("alt-pkg", "10.99.0.16")
