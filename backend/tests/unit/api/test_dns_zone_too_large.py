# SPDX-License-Identifier: Apache-2.0
"""A zone above dns.zone_read_max_names: typed 409 on its records, named in the hosts errors."""

from __future__ import annotations

from typing import Any

import pytest

from pelagos.connectors.base import ZoneTooLarge
from pelagos.domain import RRset, Zone, ZoneKind

pytestmark = pytest.mark.unit

SOA = ["ns1.example.lan. hostmaster.example.lan. 1 3600 900 1209600 300"]


@pytest.fixture
def big_zone(fake_registry, monkeypatch: pytest.MonkeyPatch) -> None:
    dns = fake_registry.dns
    dns.add_zone(Zone(name="big.example.", kind=ZoneKind.PRIMARY), [RRset("big.example.", "SOA", 300, SOA)])
    read = dns.read_zone

    def read_zone(zone: str, view: str | None = None) -> Any:
        if zone.rstrip(".") == "big.example":
            raise ZoneTooLarge("big.example.", view or "_default", 829735, 50000)
        return read(zone, view)

    monkeypatch.setattr(dns, "read_zone", read_zone)


def test_records_of_a_large_zone_is_a_typed_409(admin, big_zone) -> None:
    r = admin.get("/api/v1/dns/zones/big.example/records")
    assert r.status_code == 409
    body = r.get_json()
    assert body["code"] == "zone_too_large"
    assert (body["zone"], body["size"], body["limit"]) == ("big.example.", 829735, 50000)
    assert body["detail_message"]["key"] == "problem.detail.zone_too_large"


def test_hosts_name_the_large_zone_and_answer(admin, big_zone) -> None:
    r = admin.get("/api/v1/hosts")
    assert r.status_code == 200
    assert "big.example." in r.get_json()["meta"]["errors"]["dns.zones"]
