# SPDX-License-Identifier: Apache-2.0
"""Views and catalog zones against real named: per-view keys select the view for AXFR and UPDATE;
a producer catalog member added by record plan reaches the consumer, which lists it."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.connectors.bind import catalog
from pelagos.domain.dns import ZoneSource
from pelagos.domain.plan import Change, ChangeOp, PlanState
from tests.daemon import bind_custom
from tests.daemon.test_bind_backend import make_backend
from tests.fixtures.ports import wait_for

pytestmark = pytest.mark.daemon

VIEWS = """
view "inside" {
\tmatch-clients { key ddi-inside; };
\tzone "split.lan" { type primary; file "split-inside.db";
\t\tupdate-policy { grant ddi-inside zonesub A TXT; }; allow-transfer { key ddi-inside; }; };
};
view "outside" {
\tmatch-clients { !key ddi-inside; any; };
\tzone "split.lan" { type primary; file "split-outside.db";
\t\tupdate-policy { grant ddi-admin zonesub A TXT; }; allow-transfer { key ddi-read; }; };
};
"""


def settings(view_keys: dict | None = None) -> dict:
    return {
        "plans": {"ttl_seconds": 600},
        "dns": {
            "read_key": "ddi-read",
            "admin_key": "ddi-admin",
            "update_types_admin": ["A", "AAAA", "PTR", "CNAME", "TXT", "SRV", "MX", "DHCID"],
            **({"view_keys": view_keys} if view_keys else {}),
        },
    }


@pytest.fixture
def split(tmp_root: Path):
    server = bind_custom.start(
        tmp_root / "views",
        VIEWS,
        extra_keys=("ddi-inside",),
        files={
            "split-inside.db": bind_custom.zone_text("split.lan").replace("192.0.2.10", "192.0.2.20"),
            "split-outside.db": bind_custom.zone_text("split.lan"),
        },
    )
    try:
        yield server
    finally:
        server.stop()


def records(backend, zone: str, view: str | None = None) -> dict:
    return {(r.name, r.rtype): r.rdata for r in backend.read_zone(zone, view)}


def test_records_per_view_with_view_keys(split, tmp_root):
    keys = {"inside": "ddi-inside", "outside": {"read": "ddi-read", "admin": "ddi-admin"}}
    backend = make_backend(split, tmp_root, settings(keys))
    zones = sorted((z.view, z.name) for z in backend.list_zones())
    assert zones == [("inside", "split.lan."), ("outside", "split.lan.")]
    assert records(backend, "split.lan", "inside")[("www.split.lan.", "A")] == ["192.0.2.20"]
    assert records(backend, "split.lan", "outside")[("www.split.lan.", "A")] == ["192.0.2.10"]

    plan = backend.plan_rrset_changes(
        "split.lan",
        [Change(ChangeOp.ADD, "split.lan/pc/A", after={"rdata": ["192.0.2.30"], "ttl": 60})],
        "inside",
    )
    assert plan.state is PlanState.VALIDATED, plan.validations
    assert plan.changes[0].target == "inside/split.lan./pc.split.lan./A"
    assert plan.preconditions[0].subject == "inside/pc.split.lan./A"
    result = backend.apply(plan)
    assert result.ok, result.message
    assert backend.details[plan.id]["apply"]["request"]["key"] == "ddi-inside."
    assert records(backend, "split.lan", "inside")[("pc.split.lan.", "A")] == ["192.0.2.30"]
    assert ("pc.split.lan.", "A") not in records(backend, "split.lan", "outside")
    assert backend.rollback(plan).ok
    assert ("pc.split.lan.", "A") not in records(backend, "split.lan", "inside")

    out = backend.plan_rrset_changes(
        "split.lan", [Change(ChangeOp.ADD, "split.lan/pc/A", after={"rdata": ["192.0.2.31"]})], "outside"
    )
    assert backend.apply(out).ok
    assert records(backend, "split.lan", "outside")[("pc.split.lan.", "A")] == ["192.0.2.31"]
    assert ("pc.split.lan.", "A") not in records(backend, "split.lan", "inside")


def test_view_without_key_is_refused(split, tmp_root):
    from pelagos.connectors.base import NotSupported

    backend = make_backend(split, tmp_root, settings())
    with pytest.raises(NotSupported, match="view_keys"):
        backend.plan_rrset_changes(
            "split.lan", [Change(ChangeOp.ADD, "split.lan/x/A", after={"rdata": ["192.0.2.1"]})], "inside"
        )


def catalog_text(members: list[str]) -> str:
    lines = [
        "$TTL 0",
        "@ IN SOA invalid. invalid. ( 1 3600 900 1209600 0 )",
        "@ IN NS invalid.",
        'version IN TXT "2"',
    ]
    lines += [f"{catalog.member_label(m)}.zones IN PTR {m}" for m in members]
    return "\n".join(lines) + "\n"


def test_catalog_producer_member_reaches_the_consumer(tmp_root):
    producer = bind_custom.start(
        tmp_root / "producer",
        """
zone "cat.lan" { type primary; file "cat.lan.db"; update-policy { grant ddi-admin zonesub PTR TXT; };
\tallow-transfer { key ddi-read; }; };
zone "member1.lan" { type primary; file "member1.lan.db"; allow-transfer { key ddi-read; }; };
zone "member2.lan" { type primary; file "member2.lan.db"; allow-transfer { key ddi-read; }; };
""",
        files={
            "cat.lan.db": catalog_text(["member1.lan."]),
            "member1.lan.db": bind_custom.zone_text("member1.lan"),
            "member2.lan.db": bind_custom.zone_text("member2.lan"),
        },
    )
    consumer = None
    try:
        primary = f"127.0.0.1 port {producer.dns_port} key ddi-read"
        consumer = bind_custom.start(
            tmp_root / "consumer",
            f"""
zone "cat.lan" {{ type secondary; file "cat.lan.db"; primaries {{ {primary}; }};
\tallow-transfer {{ key ddi-read; }}; }};
""",
            keys=producer.keys,
            options=f'\tcatalog-zones {{ zone "cat.lan" default-primaries {{ {primary}; }}; }};\n',
        )
        prod = make_backend(producer, tmp_root, settings())
        cons = make_backend(consumer, tmp_root / "c", settings())
        items = {c["zone"]: c for c in prod.catalog_zones()}
        assert items["cat.lan."]["role"] == "producer" and items["cat.lan."]["version"] == "2"
        assert [m["zone"] for m in items["cat.lan."]["members"]] == ["member1.lan."]

        wait_for(lambda: any(z.name == "member1.lan." for z in cons.list_zones()), timeout=20, what="member1")
        member1 = next(z for z in cons.list_zones() if z.name == "member1.lan.")
        assert member1.source is ZoneSource.CATALOG and member1.extra["catalog"] == "cat.lan."

        changes = catalog.member_changes(
            "cat.lan", ChangeOp.ADD, "member2.lan", prod.read_zone("cat.lan"), "lab"
        )
        plan = prod.plan_rrset_changes("cat.lan", changes, created_by="alice")
        assert plan.state is PlanState.VALIDATED, plan.validations
        assert prod.apply(plan).ok
        consumer.rndc("retransfer", "cat.lan")

        def listed() -> bool:
            cons.forget_extra_zones()
            return any(z.name == "member2.lan." for z in cons.list_zones())

        wait_for(listed, timeout=30, what="member2 on the consumer")
        consumed = {c["zone"]: c for c in cons.catalog_zones()}["cat.lan."]
        assert consumed["role"] == "consumer" and consumed["default_primaries"] == [primary]
        group = {m["zone"]: m["group"] for m in consumed["members"]}
        assert group == {"member1.lan.": None, "member2.lan.": "lab"}

        remove = catalog.member_changes("cat.lan", ChangeOp.DELETE, "member2.lan", prod.read_zone("cat.lan"))
        assert len(remove) == 2  # the PTR and the group TXT
        assert prod.apply(prod.plan_rrset_changes("cat.lan", remove)).ok
        assert [m["zone"] for m in prod.catalog_zones()[0]["members"]] == ["member1.lan."]
    finally:
        if consumer is not None:
            consumer.stop()
        producer.stop()
