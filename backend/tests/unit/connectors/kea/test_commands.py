# SPDX-License-Identifier: Apache-2.0
"""Object commands of the 3.x path, lease and statistics parsing, HA state and D2 helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.connectors.base import ConnectorError
from pelagos.connectors.kea import commands as kc
from pelagos.connectors.kea import config as kcfg
from pelagos.connectors.kea.d2 import externalize_secrets, mask_secrets, reduce_d2_stats, secret_file_name
from pelagos.connectors.kea.ha import ha_configured, ha_state_from_status, is_healthy
from pelagos.domain import (
    Change,
    ChangeOp,
    ClientClass,
    DhcpCapabilities,
    Engine,
    Family,
    HAMode,
    LeaseState,
    Reservation,
    ReservationIdType,
    SharedNetwork,
    Subnet,
)
from tests.unit.connectors.kea.fake import config_of, load

pytestmark = pytest.mark.unit


def caps(hooks: list[str], degraded: bool = False) -> DhcpCapabilities:
    return DhcpCapabilities(engine=Engine.KEA4, running=True, hooks=hooks, degraded=degraded)


def test_command_path_selection():
    full = caps(["lease_cmds", "host_cmds", "subnet_cmds", "class_cmds"])
    subnet = Change(ChangeOp.ADD, "subnet4/3")
    assert kc.command_path_available([subnet], full)
    assert not kc.command_path_available([subnet], caps(full.hooks, degraded=True))
    assert not kc.command_path_available(
        [Change(ChangeOp.ADD, "client-classes/x")], caps(["subnet_cmds", "host_cmds"])
    )
    assert not kc.command_path_available([Change(ChangeOp.REPLACE, "valid-lifetime")], full)
    assert not kc.command_path_available([Change(ChangeOp.REPLACE, "shared-networks/a")], full)
    assert kc.command_path_available([Change(ChangeOp.DELETE, "shared-networks/a")], full)


def test_subnet_commands_split_reservations():
    cfg = config_of("kea32-dhcp4-config-get")
    res = Reservation(subnet_id=5, id_type=ReservationIdType.HW_ADDRESS, identifier="aa:00:00:00:00:05")
    subnet = Subnet(
        id=5, subnet="192.0.2.0/26", family=Family.V4, shared_network="office", reservations=[res]
    )
    cmds = kc.object_commands(
        Change(ChangeOp.ADD, "subnet4/5", after=subnet.to_dict()), Family.V4, cfg, "3.2.1"
    )
    assert [c for c, _ in cmds] == ["subnet4-add", "network4-subnet-add", "reservation-add"]
    assert "reservations" not in cmds[0][1]["subnet4"][0]
    assert cmds[1][1] == {"name": "office", "id": 5}
    assert cmds[2][1] == {
        "reservation": {"hw-address": "aa:00:00:00:00:05", "subnet-id": 5},
        "operation-target": "memory",
    }


def test_subnet_update_syncs_reservations_and_moves():
    cfg = config_of("kea32-dhcp4-config-get")
    s2 = kcfg.subnet_from_kea(cfg["subnet4"][1], Family.V4, None, "3.2.1")
    new_res = Reservation(subnet_id=2, id_type=ReservationIdType.HW_ADDRESS, identifier="aa:00:00:00:00:02")
    edited = s2.replace(shared_network="office", reservations=[new_res])
    cmds = kc.object_commands(
        Change(ChangeOp.REPLACE, "subnet4/2", after=edited.to_dict()), Family.V4, cfg, "3.2.1", hosts_db=True
    )
    assert [c for c, _ in cmds] == [
        "subnet4-update",
        "network4-subnet-add",
        "reservation-del",
        "reservation-add",
    ]
    # The identifier goes back as Kea printed it; subnet reservations stay in memory with a hosts db.
    assert cmds[2][1] == {
        "subnet-id": 2,
        "identifier-type": "client-id",
        "identifier": "010A0B0C0D0E0F",
        "operation-target": "memory",
    }
    s10 = kcfg.subnet_from_kea(cfg["shared-networks"][0]["subnet4"][0], Family.V4, "office", "3.2.1")
    cmds = kc.object_commands(
        Change(ChangeOp.REPLACE, "subnet4/10", after=s10.replace(shared_network=None).to_dict()),
        Family.V4,
        cfg,
        "3.2.1",
    )
    assert [c for c, _ in cmds] == ["network4-subnet-del", "subnet4-update"]
    # Unchanged reservations produce no host command.
    cmds = kc.object_commands(
        Change(
            ChangeOp.REPLACE, "subnet4/1", after=kcfg.subnet_from_kea(cfg["subnet4"][0], Family.V4).to_dict()
        ),
        Family.V4,
        cfg,
        "3.2.1",
    )
    assert [c for c, _ in cmds] == ["subnet4-update"]
    assert kc.object_commands(Change(ChangeOp.DELETE, "subnet4/2"), Family.V4, cfg, "3.2.1") == [
        ("subnet4-del", {"id": 2})
    ]


def test_network_reservation_and_class_commands():
    cfg = config_of("kea32-dhcp6-config-get")
    net = SharedNetwork(
        name="lab", family=Family.V6, subnets=[Subnet(id=40, subnet="2001:db8:40::/64", family=Family.V6)]
    )
    cmds = kc.object_commands(
        Change(ChangeOp.ADD, "shared-networks/lab", after=net.to_dict()), Family.V6, cfg, "3.2.1"
    )
    assert cmds[0][0] == "network6-add" and cmds[0][1]["shared-networks"][0]["subnet6"][0]["id"] == 40
    assert kc.object_commands(Change(ChangeOp.DELETE, "shared-networks/lab"), Family.V6, cfg, "3.2.1") == [
        ("network6-del", {"name": "lab", "subnets-action": "delete"})
    ]
    res = Reservation(
        subnet_id=None, id_type=ReservationIdType.DUID, identifier="01:02", ip_addresses=["2001:db8::9"]
    )
    cmds = kc.object_commands(
        Change(ChangeOp.REPLACE, "subnet6/1/reservations/duid=01:02", after=res.to_dict()),
        Family.V6,
        cfg,
        "3.2.1",
    )
    assert cmds == [
        (
            "reservation-update",
            {
                "reservation": {"duid": "01:02", "ip-addresses": ["2001:db8::9"], "subnet-id": 1},
                "operation-target": "memory",
            },
        )
    ]
    cmds = kc.object_commands(
        Change(ChangeOp.DELETE, "global/reservations/duid=01:02"), Family.V6, cfg, "3.2.1"
    )
    assert cmds[0] == (
        "reservation-del",
        {"subnet-id": 0, "identifier-type": "duid", "identifier": "01:02", "operation-target": "memory"},
    )
    cls = ClientClass(name="cpe", test="member('ALL')", only_in_additional_list=False)
    cmds = kc.object_commands(
        Change(ChangeOp.ADD, "client-classes/cpe", after=cls.to_dict()), Family.V6, cfg, "3.2.1"
    )
    assert cmds == [
        (
            "class-add",
            {"client-classes": [{"name": "cpe", "test": "member('ALL')", "only-in-additional-list": False}]},
        )
    ]
    with pytest.raises(ConnectorError):
        kc.object_commands(Change(ChangeOp.REPLACE, "valid-lifetime", after=1), Family.V6, cfg, "3.2.1")


def test_leases_from_captured_pages():
    v4 = [
        kc.lease_from_kea(x, Family.V4, "n1")
        for x in load("kea32-dhcp4-lease4-get-page")["arguments"]["leases"]
    ]
    assert [x.ip_address for x in v4] == ["192.0.2.150", "192.0.2.151", "203.0.113.20"]
    first = v4[0]
    assert first.hw_address == "aa:bb:cc:dd:ee:02" and first.client_id == "01:aa:bb:cc:dd:ee:02"
    assert first.hostname == "pc2" and first.valid_lft == 3600 and first.node_id == "n1"
    assert (first.expires_at - first.cltt).total_seconds() == 3600
    assert v4[1].fqdn_fwd and v4[1].user_context["ISC"]["relay-agent-info"]
    assert v4[2].state is LeaseState.DECLINED and v4[2].hostname is None
    v6 = [kc.lease_from_kea(x, Family.V6) for x in load("kea32-dhcp6-lease6-get-page")["arguments"]["leases"]]
    assert v6[0].lease_type == "IA_NA" and v6[0].iaid == 1 and v6[0].preferred_lft == 7200
    assert v6[1].lease_type == "IA_PD" and v6[1].prefix_len == 64


def test_lease_to_kea_add_round_trip():
    raw = load("kea32-dhcp4-lease4-get-page")["arguments"]["leases"][2]
    lease = kc.lease_from_kea(raw, Family.V4)
    assert kc.lease_to_kea_add(lease) == {
        "ip-address": "203.0.113.20",
        "subnet-id": 10,
        "hw-address": "aa:bb:cc:dd:ee:05",
        "valid-lft": 3600,
        "state": 1,
    }
    pd = kc.lease_from_kea(load("kea32-dhcp6-lease6-get-page")["arguments"]["leases"][1], Family.V6)
    args = kc.lease_to_kea_add(pd)
    assert args["type"] == "IA_PD" and args["prefix-len"] == 64 and args["iaid"] == 2


def test_pool_utilization_from_statistics():
    v4 = config_of("kea32-dhcp4-config-get")
    subnets = [kcfg.subnet_from_kea(o, Family.V4, n) for o, n in kcfg.iter_subnets(v4, Family.V4)]
    rows = kc.pool_utilization_from_stats(load("kea32-dhcp4-statistic-get-all")["arguments"], subnets, "n1")
    s1 = [r for r in rows if r["subnet_id"] == 1]
    # Both pools of subnet 1 have the default pool-id 0, so Kea counts them together.
    assert s1[0]["pool"] == "192.0.2.100-192.0.2.199, 192.0.2.200-192.0.2.220" and s1[0]["kind"] == "pool"
    assert s1[0]["total"] == 121 and s1[0]["assigned"] == 2 and s1[0]["percent"] == 1.7
    s10 = next(r for r in rows if r["subnet_id"] == 10)
    assert s10["declined"] == 1 and s10["node_id"] == "n1"
    v6 = config_of("kea32-dhcp6-config-get")
    subnets6 = [kcfg.subnet_from_kea(o, Family.V6, n) for o, n in kcfg.iter_subnets(v6, Family.V6)]
    rows6 = kc.pool_utilization_from_stats(load("kea32-dhcp6-statistic-get-all")["arguments"], subnets6)
    pd = next(r for r in rows6 if r["kind"] == "pd-pool")
    assert pd["pool"] == "2001:db8:1::/48" and pd["total"] == 65536 and pd["assigned"] == 1
    na = next(r for r in rows6 if r["kind"] == "pool" and r["subnet_id"] == 1)
    assert na["assigned"] == 1


def test_pool_utilization_from_stat_cmds_and_subnet_fallback():
    v4 = config_of("kea32-dhcp4-config-get")
    subnets = [kcfg.subnet_from_kea(o, Family.V4, n) for o, n in kcfg.iter_subnets(v4, Family.V4)]
    rows = kc.pool_utilization_from_stat_cmds(
        load("kea32-dhcp4-stat-lease4-get")["arguments"]["result-set"], subnets
    )
    assert {r["subnet_id"]: (r["total"], r["assigned"]) for r in rows}[10] == (91, 1)
    # Without pool statistics (Kea 2.6 memfile), rows fall back to subnets.
    stats = {"subnet[3].total-addresses": [[50, "t"]], "subnet[3].assigned-addresses": [[5, "t"]]}
    assert kc.pool_utilization_from_stats(stats, []) == [
        {
            "subnet_id": 3,
            "subnet": None,
            "pool": None,
            "kind": "subnet",
            "total": 50,
            "assigned": 5,
            "declined": 0,
            "percent": 10.0,
            "node_id": None,
        }
    ]
    assert kc.latest([]) == 0


def test_normalize_version():
    text = load("kea32-dhcp4-version-get")["text"]
    assert kc.normalize_version(text) == "3.2.1"
    assert kc.normalize_version("3.2.1 (isc20260928103142 deb)") == "3.2.1"
    assert kc.normalize_version("") is None


def test_ha_state_from_captured_status():
    state = ha_state_from_status("n1", Family.V4, load("kea32-dhcp4-status-get")["arguments"])
    assert state.enabled and state.mode is HAMode.HOT_STANDBY
    assert (state.server_name, state.role, state.state) == ("server1", "primary", "waiting")
    assert state.partner.role == "standby" and state.partner.in_touch is False and state.partner.state is None
    assert not is_healthy(state)
    assert is_healthy(state.replace(state="hot-standby"))
    none = ha_state_from_status("n1", Family.V6, load("kea32-dhcp6-status-get")["arguments"])
    assert not none.enabled and is_healthy(none)
    assert ha_configured(config_of("kea32-dhcp4-config-get"))
    assert not ha_configured(config_of("kea32-dhcp6-config-get"))


def test_d2_helpers():
    stats = reduce_d2_stats("n1", load("kea32-d2-statistic-get-all")["arguments"])
    assert stats.per_key == {
        "kea-ddns.": {"update-error": 0, "update-sent": 0, "update-success": 0, "update-timeout": 0}
    }
    assert stats.totals["ncr-received"] == 0 and "queue-mgr-queue-full" in stats.totals
    cfg = {
        "tsig-keys": [
            {"name": "ddi-admin.", "algorithm": "HMAC-SHA256", "secret": "c2VjcmV0"},
            {"name": "kea", "secret-file": "/etc/kea/kea.secret"},
        ]
    }
    out, files = externalize_secrets(cfg, Path("/etc/kea"))
    assert out["tsig-keys"][0] == {
        "name": "ddi-admin.",
        "algorithm": "HMAC-SHA256",
        "secret-file": "/etc/kea/ddi-admin.secret",
    }
    assert files == {Path("/etc/kea/ddi-admin.secret"): "c2VjcmV0"}
    assert out["tsig-keys"][1] == cfg["tsig-keys"][1] and "secret" in cfg["tsig-keys"][0]
    assert mask_secrets(cfg)["tsig-keys"][0]["secret"] == "***"
    assert secret_file_name("a/b key.") == "a_b_key.secret"
