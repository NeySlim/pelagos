# SPDX-License-Identifier: Apache-2.0
"""Rollback guards against real kea-dhcp4 and kea-dhcp-ddns (section 6): a hand edit refuses the
rollback with 409 and writes nothing, a D2 plan rolls back past the preview TTL, and a hot-standby
pair keeps the same configuration through a refused then an accepted rollback."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from pelagos.connectors.base import PreconditionFailed
from pelagos.core import settings_registry as reg
from pelagos.domain import Change, ChangeOp, Reservation, ReservationIdType, utcnow
from tests.daemon.api_node import V1, apply, login, make_app, make_node, planned
from tests.daemon.test_kea_backend import make_backend
from tests.daemon.test_kea_ha import ha_pair, local_state  # noqa: F401
from tests.fixtures.ports import wait_for

pytestmark = pytest.mark.daemon

RESERVATION = {
    "subnet_id": 1,
    "id_type": "hw-address",
    "identifier": "aa:bb:cc:dd:ee:71",
    "ip_address": "192.0.2.71",
    "hostname": "guarded",
}


@pytest.fixture
def api(tmp_root, kea_dhcp4, kea_d2):
    ctx = make_node(tmp_root / "node", dhcp4=kea_dhcp4, d2=kea_d2)
    yield login(make_app(ctx)), ctx
    from pelagos.services.container import Services

    Services.of(ctx).close()


def plan_entries(ctx, plan_id: str) -> int:
    return sum(1 for e in ctx.audit_log.read() if e.plan_id == plan_id)


def test_kea_hand_edit_refuses_the_rollback_with_409_and_writes_nothing(api, kea_dhcp4):
    client, ctx = api
    plan = planned(
        client.post(
            f"{V1}/dhcp/v4/reservations/plan",
            json={"change": {"op": "add", "target": "", "after": RESERVATION}},
        )
    )
    applied = apply(client, plan)
    assert applied["state"] == "applied" and applied["rollback_until"], applied

    # By hand: the file is edited and Kea reloads it.
    on_disk = json.loads(kea_dhcp4.config_path.read_text())
    on_disk["Dhcp4"]["valid-lifetime"] = 4321
    kea_dhcp4.config_path.write_text(json.dumps(on_disk, indent=2))
    kea_dhcp4.ok("config-reload")
    running = kea_dhcp4.ok("config-get")
    file_text = kea_dhcp4.config_path.read_text()
    audited = plan_entries(ctx, plan["id"])

    r = client.post(f"{V1}/plans/{plan['id']}/rollback")
    assert r.status_code == 409, r.get_json()
    assert r.get_json()["code"] == "precondition_failed"
    assert kea_dhcp4.ok("config-get") == running
    assert kea_dhcp4.config_path.read_text() == file_text
    held = client.get(f"{V1}/plans/{plan['id']}").get_json()
    assert held["state"] == "applied" and held["rollback_until"] == applied["rollback_until"]
    assert plan_entries(ctx, plan["id"]) == audited
    rows = client.get(f"{V1}/dhcp/v4/reservations?subnet_id=1").get_json()["items"]
    assert "aa:bb:cc:dd:ee:71" in {r["identifier"] for r in rows}


def test_d2_rollback_succeeds_past_the_preview_ttl(api, kea_d2, monkeypatch):
    client, ctx = api
    config = client.get(f"{V1}/dhcp/d2/config").get_json()["config"]
    before = config["dns-server-timeout"]
    config["dns-server-timeout"] = before + 250
    plan = planned(client.post(f"{V1}/dhcp/d2/config/plan", json={"config": config}))
    assert apply(client, plan)["state"] == "applied"
    assert kea_d2.ok("config-get")["DhcpDdns"]["dns-server-timeout"] == before + 250

    ttl = int(reg.get(ctx.settings(), "plans.ttl_seconds"))
    later = utcnow() + timedelta(seconds=ttl + 3600)
    monkeypatch.setattr("pelagos.connectors.kea.d2.utcnow", lambda: later)
    rb = client.post(f"{V1}/plans/{plan['id']}/rollback")
    assert rb.status_code == 200, rb.get_json()
    assert rb.get_json()["state"] == "rolled_back", rb.get_json()
    assert kea_d2.ok("config-get")["DhcpDdns"]["dns-server-timeout"] == before


def subnets(daemon) -> list:
    return daemon.ok("config-get")["Dhcp4"]["subnet4"]


def test_ha_pair_keeps_one_configuration_through_guarded_rollbacks(ha_pair, tmp_root):  # noqa: F811
    primary, standby = ha_pair
    wait_for(
        lambda: local_state(primary) == local_state(standby) == "hot-standby", timeout=30, what="HA pair"
    )
    backends = [make_backend(primary, tmp_root / "n1"), make_backend(standby, tmp_root / "n2")]
    res = Reservation(
        subnet_id=1,
        id_type=ReservationIdType.HW_ADDRESS,
        identifier="aa:bb:cc:dd:ee:72",
        ip_address="192.0.2.72",
    )
    target = "subnet4/1/reservations/hw-address=aa:bb:cc:dd:ee:72"
    plans = [b.plan_reservation_change(Change(ChangeOp.ADD, target, after=res.to_dict())) for b in backends]
    for b, p in zip(backends, plans, strict=True):
        assert b.apply(p).ok
    assert subnets(primary) == subnets(standby)

    # The same hand edit on both partners: each guard refuses, nothing moves.
    for d in ha_pair:
        cfg = d.ok("config-get")
        cfg.pop("hash", None)
        cfg["Dhcp4"]["valid-lifetime"] = 4321
        d.ok("config-set", cfg)
    edited = [d.ok("config-get") for d in ha_pair]
    for b, p in zip(backends, plans, strict=True):
        with pytest.raises(PreconditionFailed):
            b.check_rollback(p)
    assert [d.ok("config-get") for d in ha_pair] == edited
    assert subnets(primary) == subnets(standby)

    # Hand edit undone: both guards hold, both roll back, the pair agrees again.
    for d in ha_pair:
        cfg = d.ok("config-get")
        cfg.pop("hash", None)
        cfg["Dhcp4"]["valid-lifetime"] = 3600
        d.ok("config-set", cfg)
    for b, p in zip(backends, plans, strict=True):
        b.check_rollback(p)
        assert b.rollback(p).ok
    assert subnets(primary) == subnets(standby)
    assert all(r["hw-address"] != "aa:bb:cc:dd:ee:72" for r in subnets(primary)[0].get("reservations", []))


# FIX-PEERROLLBACK: the PlanService of node 1 rolls back a plan of a real hot-standby pair whose
# node 2 runs behind the in-process gateway of tests.unit.services.kea_pair.


@pytest.fixture
def ha_lab(node_ctx, tmp_root):
    from tests.daemon.test_kea_ha_offline import Lab

    out = Lab(node_ctx, tmp_root)
    try:
        yield out
    finally:
        out.close()


def _reservation(pair, mac: str, ip: str):
    after = {"subnet_id": 1, "id_type": "hw-address", "identifier": mac, "ip_address": ip}
    return pair.dhcp.plan("reservation", {"change": {"op": "add", "target": "", "after": after}}, "admin")


def _hand_edit(daemon, lifetime: int) -> None:
    cfg = daemon.ok("config-get")
    cfg.pop("hash", None)
    cfg["Dhcp4"]["valid-lifetime"] = lifetime
    daemon.ok("config-set", cfg)


def _macs(daemon) -> set[str]:
    return {r["hw-address"] for r in subnets(daemon)[0].get("reservations", [])}


def test_hand_edit_on_the_peer_only_refuses_the_rollback_on_both_partners(ha_lab):
    from pelagos.domain import PlanState
    from pelagos.services.plan_service import PlanError
    from tests.unit.services.kea_pair import N2

    pair, (kea1, kea2) = ha_lab.pair, ha_lab.daemons
    plan = _reservation(pair, "aa:bb:cc:dd:ee:73", "192.0.2.73")
    assert plan.target_node_ids == [pair.n1, N2]
    assert pair.plans.apply(plan, "admin", True).state is PlanState.APPLIED
    assert "aa:bb:cc:dd:ee:73" in _macs(kea1) & _macs(kea2)

    original = kea2.ok("config-get")["Dhcp4"]["valid-lifetime"]
    _hand_edit(kea2, 4321)
    before = [d.ok("config-get") for d in ha_lab.daemons]
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(plan, "admin")
    assert exc.value.code == "precondition_failed" and exc.value.detail.startswith("ns2: ")
    assert [d.ok("config-get") for d in ha_lab.daemons] == before
    assert subnets(kea1) == subnets(kea2)
    assert plan.state is PlanState.APPLIED and pair.ctx.plan_store.get(plan.id).rollback_until

    _hand_edit(kea2, original)
    assert pair.plans.rollback(plan, "admin").state is PlanState.ROLLED_BACK
    assert subnets(kea1) == subnets(kea2) and "aa:bb:cc:dd:ee:73" not in _macs(kea1)


def test_host_part_without_a_record_on_the_peer_is_refused_there_and_nothing_moves(ha_lab):
    from pelagos.domain import Plan, PlanScope, PlanState
    from pelagos.services.plan_service import PlanError
    from tests.unit.services.kea_pair import N2

    pair, (kea1, kea2) = ha_lab.pair, ha_lab.daemons
    part = _reservation(pair, "aa:bb:cc:dd:ee:74", "192.0.2.74")
    top = Plan(scope=PlanScope.HOST, node_id=pair.n1, summary="host", target_node_ids=[pair.n1, N2])
    top.state = PlanState.VALIDATED
    pair.ctx.plan_store.put(top)
    pair.plans.register_composite(top, [part])
    assert pair.plans.apply(top, "admin", True).state is PlanState.APPLIED
    assert part.finished_at == top.finished_at is not None

    pair.k2._forget(part.id)  # the peer's guard record is gone
    before = [d.ok("config-get") for d in ha_lab.daemons]
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(top, "admin")
    assert exc.value.code == "precondition_failed" and "rollback guard lost" in exc.value.detail
    assert [d.ok("config-get") for d in ha_lab.daemons] == before
    assert top.state is PlanState.APPLIED

    # An older peer, without the pre-check: its rollback refuses the part by its finished_at, it
    # runs first, and this node is left as is.
    pair.gateway.old.add(N2)
    result = pair.plans.rollback(top, "admin")
    assert result.state is PlanState.FAILED
    assert [d.ok("config-get") for d in ha_lab.daemons] == before
    assert subnets(kea1) == subnets(kea2) and "aa:bb:cc:dd:ee:74" in _macs(kea1)
    by_node = {r.node_id: r for r in result.results}
    assert "rollback guard lost" in by_node[N2].message and not by_node[pair.n1].ok
