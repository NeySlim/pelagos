# SPDX-License-Identifier: Apache-2.0
"""Forward, hint, stub and static-stub zones: never transferred, never asked their SOA."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pelagos.connectors.base import ZoneWithoutRecords
from pelagos.connectors.bind.rndc import RndcNotFound
from pelagos.domain.dns import ZoneKind

from .test_bind_backend_unit import conf_tree, make_backend  # noqa: F401

pytestmark = pytest.mark.unit

ZONES = (
    'zone "fwd.example" { type forward; forward only; forwarders { 192.0.2.53; 192.0.2.54 port 5353; }; };\n'
    'zone "stub.example" { type stub; primaries { 192.0.2.60; }; file "stub.db"; };\n'
    'zone "sstub.example" { type static-stub; server-addresses { 192.0.2.61; }; };\n'
)


@pytest.fixture
def backend(tmp_root: Path, conf_tree: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: F811
    named = conf_tree / "named.conf"
    named.write_text(named.read_text() + ZONES)
    b, rec = make_backend(tmp_root, conf_tree)
    asked: list[tuple[str, str]] = []

    def forbidden(kind: str):
        def call(zone: str, *_: Any, **__: Any) -> Any:
            asked.append((kind, zone))
            raise AssertionError(f"{kind} of {zone}")

        return call

    monkeypatch.setattr(b.dns, "axfr", forbidden("axfr"))
    monkeypatch.setattr(b.dns, "soa_serial", forbidden("soa"))
    statuses = {
        "stub.example": {"type": "stub", "serial": "7"},
        "sstub.example": {"type": "static-stub"},
        ".": {"type": "hint"},
    }

    def zonestatus(zone: str, view: str | None = None) -> dict[str, str]:
        name = zone.rstrip(".") or "."
        if name not in statuses:
            raise RndcNotFound(f"no matching zone '{zone}' in any view")
        return statuses[name]

    rec.zonestatus = zonestatus  # type: ignore[method-assign]
    return b, asked


@pytest.mark.parametrize("zone", ["fwd.example", "stub.example.", "sstub.example"])
def test_read_zone_refuses_before_any_transfer(backend, zone: str) -> None:
    b, asked = backend
    with pytest.raises(ZoneWithoutRecords) as exc:
        b.read_zone(zone)
    assert exc.value.kind in ("forward", "stub", "static-stub")
    assert asked == []
    assert b._axfr_refused == {}


def test_zone_status_never_sends_an_soa_query(backend) -> None:
    b, asked = backend
    fwd = b.zone_status("fwd.example")
    assert fwd.kind is ZoneKind.FORWARD and fwd.error is None and fwd.serial is None
    stub = b.zone_status("stub.example")
    assert stub.kind is ZoneKind.STUB and stub.serial == 7
    sstub = b.zone_status("sstub.example")
    assert sstub.kind is ZoneKind.STATIC_STUB and sstub.serial is None and sstub.error is None
    assert b.zone_status(".").serial is None
    assert asked == []


def test_unknown_zone_status_is_still_an_error(backend) -> None:
    b, _ = backend
    assert "no matching zone" in (b.zone_status("absent.example").error or "")
