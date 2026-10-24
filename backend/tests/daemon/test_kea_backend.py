# SPDX-License-Identifier: Apache-2.0
"""KeaBackend against real kea-dhcp4 / kea-dhcp6: both write paths, rollback, leases, preconditions."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from pelagos.connectors.base import ConnectorContext, NotSupported, PreconditionFailed
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.domain import (
    Change,
    ChangeOp,
    Family,
    PdPool,
    PlanScope,
    PlanState,
    Pool,
    Reservation,
    ReservationIdType,
    Subnet,
)
from tests.fixtures import kea as kea_fx

pytestmark = pytest.mark.daemon

DEGRADED_HOOKS = ("lease_cmds", "stat_cmds")


def make_backend(daemon: kea_fx.KeaDaemon, tmp_root: Path, family: Family = Family.V4) -> KeaBackend:
    n = 4 if family is Family.V4 else 6
    ctx = ConnectorContext(
        node_id="n1",
        engine_config={
            "socket_dir": str(daemon.socket_path.parent),
            f"dhcp{n}_socket": daemon.socket_path.name,
            f"dhcp{n}_conf": str(daemon.config_path),
        },
        backup_root=tmp_root / "backups",
        get_secret=lambda name: None,
        settings={},
    )
    return KeaBackend(ctx, family)


@pytest.fixture
def kea4_degraded(tmp_root: Path) -> Iterator[kea_fx.KeaDaemon]:
    """kea-dhcp4 without host_cmds and subnet_cmds: the Kea 2.6 write path."""
    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    root = tmp_root / "kea4d"
    daemon = kea_fx.start_kea("kea-dhcp4", root, kea_fx.dhcp4_config(root, hooks, hooks=DEGRADED_HOOKS))
    try:
        yield daemon
    finally:
        daemon.stop()


@pytest.fixture(params=["commands", "config-set"])
def kea4_any(request, tmp_root: Path) -> Iterator[tuple[str, kea_fx.KeaDaemon]]:
    """Both write paths: full 3.x hooks and the degraded hook set."""
    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    root = tmp_root / "kea4"
    chosen = kea_fx.HOOKS4 if request.param == "commands" else DEGRADED_HOOKS
    daemon = kea_fx.start_kea("kea-dhcp4", root, kea_fx.dhcp4_config(root, hooks, hooks=chosen))
    try:
        yield request.param, daemon
    finally:
        daemon.stop()


def file_config(daemon: kea_fx.KeaDaemon) -> dict:
    return json.loads(daemon.config_path.read_text())["Dhcp4" if "dhcp4" in daemon.name else "Dhcp6"]


def file_subnets(daemon: kea_fx.KeaDaemon, key: str = "subnet4") -> dict[int, dict]:
    return {s["id"]: s for s in file_config(daemon).get(key, [])}


def applied_through(result) -> str:
    return "commands" if "through commands" in result.message else "config-set"


def test_capabilities_reflect_hooks(kea4_degraded, kea_dhcp4, tmp_root):
    degraded = make_backend(kea4_degraded, tmp_root).capabilities()
    full = make_backend(kea_dhcp4, tmp_root).capabilities()
    assert degraded.running and degraded.degraded and not degraded.host_cmds and degraded.lease_cmds
    assert full.running and not full.degraded and full.subnet_cmds and full.version.startswith("3.")


def test_subnet_add_update_delete(kea4_any, tmp_root):
    path, daemon = kea4_any
    backend = make_backend(daemon, tmp_root)
    new = Subnet(
        id=0,
        subnet="198.51.100.0/24",
        family=Family.V4,
        pools=[Pool(pool="198.51.100.10 - 198.51.100.20")],
        valid_lifetime=1800,
        user_context={"pelagos": {"notes": "added by test"}, "site": "lab"},
    )
    plan = backend.plan_subnet_change(Change(ChangeOp.ADD, "subnet4/new", after=new.to_dict()), "tester")
    assert plan.state is PlanState.VALIDATED, plan.validations
    assert plan.changes[0].target == "subnet4/2"
    assert "198.51.100.0/24" in plan.diff
    result = backend.apply(plan)
    assert result.ok, result.message
    assert applied_through(result) == path
    added = backend.get_subnet(2)
    assert added.pools[0].pool == "198.51.100.10-198.51.100.20"
    assert added.user_context["site"] == "lab"
    assert file_subnets(daemon)[2]["valid-lifetime"] == 1800

    # Update: lifetime and a second pool; keys Pelagos does not model survive.
    edited = added.replace(valid_lifetime=900, pools=[*added.pools, Pool(pool="198.51.100.50 - 198.51.100.60")])
    plan = backend.plan_subnet_change(Change(ChangeOp.REPLACE, "subnet4/2", after=edited.to_dict()))
    assert plan.state is PlanState.VALIDATED, plan.validations
    result = backend.apply(plan)
    assert result.ok, result.message
    running = backend.get_subnet(2)
    assert running.valid_lifetime == 900 and len(running.pools) == 2
    assert running.user_context["pelagos"]["notes"] == "added by test"
    assert file_subnets(daemon)[2]["valid-lifetime"] == 900

    # Rollback of the update restores the previous lifetime.
    rb = backend.rollback(plan)
    assert rb.ok, rb.message
    assert backend.get_subnet(2).valid_lifetime == 1800

    plan = backend.plan_subnet_change(Change(ChangeOp.DELETE, "subnet4/2"))
    result = backend.apply(plan)
    assert result.ok, result.message
    assert [s.id for s in backend.list_subnets()] == [1]
    assert 2 not in file_subnets(daemon)

    # Rolling back the delete brings the subnet back with its pools.
    rb = backend.rollback(plan)
    assert rb.ok, rb.message
    assert len(backend.get_subnet(2).pools) == 1


def test_subnet_update_with_reservations(kea4_any, tmp_root):
    """Subnet 1 carries a reservation: an edit keeps it, adds one and drops none."""
    path, daemon = kea4_any
    backend = make_backend(daemon, tmp_root)
    subnet = backend.get_subnet(1)
    extra = Reservation(
        subnet_id=1, id_type=ReservationIdType.HW_ADDRESS, identifier="aa:bb:cc:dd:ee:77", ip_address="192.0.2.77"
    )
    edited = subnet.replace(
        options=[*subnet.options], reservations=[*subnet.reservations, extra], interface=None, valid_lifetime=7200
    )
    plan = backend.plan_subnet_change(Change(ChangeOp.REPLACE, "subnet4/1", after=edited.to_dict()))
    assert plan.state is PlanState.VALIDATED, plan.validations
    result = backend.apply(plan)
    assert result.ok, result.message
    assert applied_through(result) == path
    after = backend.get_subnet(1)
    assert after.valid_lifetime == 7200
    assert {r.identifier for r in after.reservations} == {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:77"}
    assert after.options[0].data == "192.0.2.1"
    assert after.user_context["pelagos"]["notes"] == "fixture subnet"
    assert len(file_subnets(daemon)[1]["reservations"]) == 2
    rb = backend.rollback(plan)
    assert rb.ok, rb.message
    assert {r.identifier for r in backend.get_subnet(1).reservations} == {"aa:bb:cc:dd:ee:01"}


def test_reservation_add_delete(kea4_any, tmp_root):
    path, daemon = kea4_any
    backend = make_backend(daemon, tmp_root)
    res = Reservation(
        subnet_id=1,
        id_type=ReservationIdType.HW_ADDRESS,
        identifier="AA:BB:CC:DD:EE:42",
        ip_address="192.0.2.42",
        hostname="pc42",
        user_context={"pelagos": {"owner": "tester"}},
    )
    target = "subnet4/1/reservations/hw-address=aa:bb:cc:dd:ee:42"
    plan = backend.plan_reservation_change(Change(ChangeOp.ADD, target, after=res.to_dict()))
    assert plan.state is PlanState.VALIDATED, plan.validations
    result = backend.apply(plan)
    assert result.ok, result.message
    assert applied_through(result) == path
    found = {r.identifier: r for r in backend.list_reservations(1)}
    assert found["aa:bb:cc:dd:ee:42"].ip_address == "192.0.2.42"
    assert found["aa:bb:cc:dd:ee:42"].user_context["pelagos"]["owner"] == "tester"
    in_file = [r for r in file_subnets(daemon)[1]["reservations"] if r.get("hw-address") == "aa:bb:cc:dd:ee:42"]
    assert in_file and in_file[0]["hostname"] == "pc42"

    plan = backend.plan_reservation_change(Change(ChangeOp.DELETE, target))
    assert plan.changes[0].before["ip_address"] == "192.0.2.42"
    result = backend.apply(plan)
    assert result.ok, result.message
    assert "aa:bb:cc:dd:ee:42" not in {r.identifier for r in backend.list_reservations(1)}
    assert all(r.get("hw-address") != "aa:bb:cc:dd:ee:42" for r in file_subnets(daemon)[1]["reservations"])
    # The fixture reservation is untouched.
    assert "aa:bb:cc:dd:ee:01" in {r.identifier for r in backend.list_reservations(1)}


def test_reservation_update_keeps_other_keys(kea_dhcp4, tmp_root):
    backend = make_backend(kea_dhcp4, tmp_root)
    printer = next(r for r in backend.list_reservations(1) if r.hostname == "printer")
    target = "subnet4/1/reservations/hw-address=aa:bb:cc:dd:ee:01"
    plan = backend.plan_reservation_change(
        Change(ChangeOp.REPLACE, target, after=printer.replace(ip_address="192.0.2.51", raw={}).to_dict())
    )
    result = backend.apply(plan)
    assert result.ok, result.message
    assert next(r for r in backend.list_reservations(1) if r.hostname == "printer").ip_address == "192.0.2.51"


def test_config_test_failure_leaves_hash_unchanged(kea4_any, tmp_root):
    _, daemon = kea4_any
    backend = make_backend(daemon, tmp_root)
    before_hash = backend.config_hash()
    before_file = daemon.config_path.read_bytes()
    broken = Subnet(id=7, subnet="203.0.113.0/24", family=Family.V4, pools=[Pool(pool="192.0.2.10 - 192.0.2.20")])
    plan = backend.plan_subnet_change(Change(ChangeOp.ADD, "subnet4/new", after=broken.to_dict()))
    assert plan.state is PlanState.FAILED
    assert plan.validations[0].tool == "config-test" and not plan.validations[0].ok
    # Applying anyway is refused by the daemon and leaves everything as it was.
    result = backend.apply(plan)
    assert not result.ok
    assert backend.config_hash() == before_hash
    assert daemon.config_path.read_bytes() == before_file


def test_config_replace_failure_and_rollback(kea_dhcp4, tmp_root):
    backend = make_backend(kea_dhcp4, tmp_root)
    before_hash = backend.config_hash()
    cfg = backend.config_get()
    cfg["subnet4"][0]["pools"].append({"pool": "10.0.0.1 - 10.0.0.9"})  # outside the subnet
    plan = backend.plan_config_replace({"Dhcp4": cfg})
    assert plan.state is PlanState.FAILED and plan.scope is PlanScope.DHCP_CONFIG
    result = backend.apply(plan)
    assert not result.ok and "config-test" in result.message
    assert backend.config_hash() == before_hash

    cfg = backend.config_get()
    cfg["valid-lifetime"] = 4321
    plan = backend.plan_config_replace(cfg)
    assert plan.state is PlanState.VALIDATED
    result = backend.apply(plan)
    assert result.ok, result.message
    assert backend.config_get()["valid-lifetime"] == 4321
    assert file_config(kea_dhcp4)["valid-lifetime"] == 4321
    rb = backend.rollback(plan)
    assert rb.ok, rb.message
    assert backend.config_get()["valid-lifetime"] == 3600
    assert backend.config_hash() == before_hash


def test_config_hash_precondition(kea_dhcp4, tmp_root):
    backend = make_backend(kea_dhcp4, tmp_root)
    plan = backend.plan_global_change([Change(ChangeOp.REPLACE, "valid-lifetime", after=7200)])
    assert plan.scope is PlanScope.DHCP_OPTIONS
    # Someone else changes the running configuration between plan and apply.
    other = backend.plan_global_change([Change(ChangeOp.REPLACE, "valid-lifetime", after=5000)])
    assert backend.apply(other).ok
    with pytest.raises(PreconditionFailed):
        backend.apply(plan)
    assert backend.config_get()["valid-lifetime"] == 5000


def test_global_option_change(kea_dhcp4, tmp_root):
    backend = make_backend(kea_dhcp4, tmp_root)
    change = Change(
        ChangeOp.ADD,
        "option-data/dhcp4/domain-name-servers",
        after={"name": "domain-name-servers", "data": "192.0.2.53"},
    )
    plan = backend.plan_global_change([change])
    assert backend.apply(plan).ok
    assert [o.data for o in backend.global_options() if o.name == "domain-name-servers"] == ["192.0.2.53"]
    assert backend.rollback(plan).ok
    assert not [o for o in backend.global_options() if o.name == "domain-name-servers"]


def test_leases_reads_and_delete(kea_dhcp4, tmp_root):
    backend = make_backend(kea_dhcp4, tmp_root)
    for i in range(5):
        kea_dhcp4.ok(
            "lease4-add",
            {
                "ip-address": f"192.0.2.{150 + i}",
                "hw-address": f"aa:bb:cc:dd:ee:{10 + i:02x}",
                "subnet-id": 1,
                "hostname": f"pc{i}",
            },
        )
    assert [lease.ip_address for lease in backend.leases()] == [f"192.0.2.{150 + i}" for i in range(5)]
    assert len(backend.leases(limit=2)) == 2
    assert [lease.ip_address for lease in backend.leases(from_address="192.0.2.152")] == [
        "192.0.2.153",
        "192.0.2.154",
    ]
    assert backend.leases(subnet_id=99) == []
    assert backend.lease("192.0.2.99") is None
    assert backend.leases_by_hw("aa:bb:cc:dd:ee:0b")[0].ip_address == "192.0.2.151"
    assert backend.leases_by_hostname("pc2")[0].ip_address == "192.0.2.152"

    plan = backend.plan_lease_delete("192.0.2.150", "tester")
    assert plan.requires_confirmation and plan.scope is PlanScope.DHCP_LEASE
    result = backend.apply(plan)
    assert result.ok, result.message
    assert backend.lease("192.0.2.150") is None
    rb = backend.rollback(plan)
    assert rb.ok, rb.message
    restored = backend.lease("192.0.2.150")
    assert restored is not None and restored.hw_address == "aa:bb:cc:dd:ee:0a" and restored.hostname == "pc0"


def test_statistics_and_utilization(kea_dhcp4, tmp_root):
    backend = make_backend(kea_dhcp4, tmp_root)
    kea_dhcp4.ok("lease4-add", {"ip-address": "192.0.2.150", "hw-address": "aa:bb:cc:dd:ee:02", "subnet-id": 1})
    rows = backend.pool_utilization()
    row = next(r for r in rows if r["subnet_id"] == 1)
    assert row["total"] == 100 and row["assigned"] == 1 and row["percent"] == 1.0
    assert "subnet[1].total-addresses" in backend.statistics()


def test_service_toggle_and_ha_without_hook(kea_dhcp4, tmp_root):
    backend = make_backend(kea_dhcp4, tmp_root)
    assert backend.ha_state().enabled is False
    with pytest.raises(NotSupported):
        backend.plan_ha_maintenance("start")
    plan = backend.plan_service_toggle(False, "tester")
    assert plan.requires_confirmation
    assert backend.apply(plan).ok
    assert backend.status()["dhcp-state"]["disabled-by-user"] is True
    assert backend.rollback(plan).ok
    assert backend.status()["dhcp-state"]["disabled-by-user"] is False


def test_dhcp6_subnet_with_pd_pools(kea_dhcp6, tmp_root):
    backend = make_backend(kea_dhcp6, tmp_root, Family.V6)
    assert not backend.capabilities().degraded
    subnet = Subnet(
        id=0,
        subnet="2001:db8:5::/64",
        family=Family.V6,
        pools=[Pool(pool="2001:db8:5::100 - 2001:db8:5::1ff")],
        pd_pools=[PdPool(prefix="2001:db8:50::", prefix_len=48, delegated_len=56)],
        preferred_lifetime=1800,
    )
    plan = backend.plan_subnet_change(Change(ChangeOp.ADD, "subnet6/new", after=subnet.to_dict()))
    assert plan.state is PlanState.VALIDATED, plan.validations
    result = backend.apply(plan)
    assert result.ok, result.message
    added = backend.get_subnet(2)
    assert added.pd_pools[0].delegated_len == 56 and added.preferred_lifetime == 1800
    assert file_subnets(kea_dhcp6, "subnet6")[2]["pd-pools"][0]["prefix"] == "2001:db8:50::"

    kea_dhcp6.ok(
        "lease6-add",
        {
            "ip-address": "2001:db8:50:100::",
            "prefix-len": 56,
            "type": "IA_PD",
            "duid": "00:01:00:01:aa:bb",
            "iaid": 3,
            "subnet-id": 2,
        },
    )
    pd = backend.lease("2001:db8:50:100::")
    assert pd is not None and pd.lease_type == "IA_PD" and pd.prefix_len == 56
    assert backend.leases_by_duid("00:01:00:01:aa:bb")[0].subnet_id == 2
    pd_rows = [r for r in backend.pool_utilization() if r["kind"] == "pd-pool" and r["subnet_id"] == 2]
    assert pd_rows and pd_rows[0]["total"] == 256 and pd_rows[0]["assigned"] == 1

    plan = backend.plan_lease_delete("2001:db8:50:100::")
    assert backend.apply(plan).ok
    assert backend.lease("2001:db8:50:100::") is None
    assert backend.rollback(plan).ok
    assert backend.lease("2001:db8:50:100::").prefix_len == 56

    plan = backend.plan_subnet_change(Change(ChangeOp.DELETE, "subnet6/2"))
    assert backend.apply(plan).ok
    assert [s.id for s in backend.list_subnets()] == [1]
