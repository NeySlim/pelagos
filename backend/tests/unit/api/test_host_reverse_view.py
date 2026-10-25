# SPDX-License-Identifier: Apache-2.0
"""Host plans: the PTR follows `view` unless `reverse_view` names another one, "_default" included."""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.unit

BODY = {"hostname": "pc", "ip": "192.0.2.33", "zone": "example.lan", "view": "inside"}


@pytest.fixture
def views(services, monkeypatch) -> list[tuple[str, str | None]]:
    """Records (zone, view) of each DNS part; the fake backend has no views, so parts build in the default."""
    seen: list[tuple[str, str | None]] = []
    hosts = services.hosts
    real_part, real_find = hosts._dns_part, hosts._find_reverse_zone

    def part(zone: str, changes: list[Any], created_by: str, view: str | None = None):
        seen.append((zone, view))
        return real_part(zone, changes, created_by, None)

    def find(ptr_name: str, view: str | None = None):
        seen.append(("find", view))
        return real_find(ptr_name, None)

    monkeypatch.setattr(hosts, "_dns_part", part)
    monkeypatch.setattr(hosts, "_find_reverse_zone", find)
    return seen


@pytest.mark.parametrize(
    ("reverse_view", "expected"),
    [(None, "inside"), ("", "inside"), ("_default", None), ("outside", "outside")],
)
def test_reverse_view(role_client, views, reverse_view, expected):
    body = dict(BODY) if reverse_view is None else {**BODY, "reverse_view": reverse_view}
    r = role_client("admin").post("/api/v1/hosts/plan", json=body)
    assert r.status_code == 200, r.get_json()
    assert views == [
        ("example.lan.", "inside"),
        ("find", expected),
        ("2.0.192.in-addr.arpa.", expected),
    ]
