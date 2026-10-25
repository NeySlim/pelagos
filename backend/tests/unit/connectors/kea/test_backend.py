# SPDX-License-Identifier: Apache-2.0
"""KeaBackend and D2Backend over an in-memory socket: path selection, Kea 2.6 mode, failures, rollback."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest

from pelagos.connectors.base import (
    ConnectorDenied,
    ConnectorError,
    NotSupported,
    PreconditionFailed,
)
from pelagos.connectors.kea import backend as kb
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.connectors.kea.d2 import D2Backend, externalize_secrets
from pelagos.domain import (
    Change,
    ChangeOp,
    Family,
    PlanScope,
    PlanState,
    Pool,
    Reservation,
    ReservationIdType,
    Subnet,
    utcnow,
)
from tests.unit.connectors.kea.fake import FakeKea, config_of, err, load, make_ctx, ok

pytestmark = pytest.mark.unit


def backend_with(
    tmp: Path, name: str, version: str, family: Family = Family.V4
) -> tuple[KeaBackend, FakeKea]:
    backend = KeaBackend(make_ctx(tmp), family)
    fake = FakeKea("Dhcp4" if family is Family.V4 else "Dhcp6", config_of(name), version)
    backend.socket = fake
    return backend, fake


@pytest.fixture
def kea3(tmp_root):
    return backend_with(tmp_root, "kea32-dhcp4-config-get", "3.2.1")


@pytest.fixture
def kea26(tmp_root):
    return backend_with(tmp_root, "kea26-dhcp4-config-get", "2.6.3")


def test_cached_config_reads_once_and_hands_out_copies(kea3):
    backend, fake = kea3
    with backend.cached_config():
        backend.capabilities()
        backend.list_subnets()
        first = backend.config_get()
        first["valid-lifetime"] = 1
        assert backend.config_get()["valid-lifetime"] != 1
    assert fake.commands().count("config-get") == 1
    backend.config_get()
    assert fake.commands().count("config-get") == 2


def test_capabilities(kea3, kea26, tmp_root):
    caps = kea3[0].capabilities()
    assert caps.running and caps.version == "3.2.1" and not caps.degraded
    assert caps.hooks == ["lease_cmds", "host_cmds", "subnet_cmds", "stat_cmds", "class_cmds", "ha"]
    assert caps.ha and caps.lease_backend == "memfile" and caps.multi_threading is True
    old = kea26[0].capabilities()
    assert old.version == "2.6.3" and old.degraded and old.lease_cmds and not old.host_cmds
    down = KeaBackend(make_ctx(tmp_root, dhcp4_socket="missing"), Family.V4).capabilities()
    assert not down.running and down.control_socket.endswith("missing")


def test_command_passthrough_refuses_writes(kea3):
    backend, fake = kea3
    for command in (
        "config-set",
        "config-write",
        "shutdown",
        "lease4-wipe",
        "lease4-del",
        "lease4-add",
        "reservation-del",
        "subnet4-del",
        "class-del",
        "dhcp-disable",
        "ha-maintenance-start",
        "ha-scopes",
        "statistic-reset-all",
        "server-tag-set",
        "config-backend-pull",
    ):
        with pytest.raises(ConnectorDenied):
            backend.command(command, {})
    assert backend.command("version-get")
    assert "Dhcp4" in backend.command("config-get")
    assert backend.command("status-get")["pid"] == 1
    fake.overrides["lease4-get"] = err("Lease not found.", 3)
    assert backend.command("lease4-get", {"ip-address": "192.0.2.1"}) == {}


def test_reads(kea3):
    backend, _fake = kea3
    assert [s.id for s in backend.list_subnets()] == [1, 2, 10, 11]
    assert backend.get_subnet(11).shared_network == "office"
    with pytest.raises(ConnectorError):
        backend.get_subnet(99)
    assert [n.name for n in backend.list_shared_networks()] == ["office"]
    assert {c.name for c in backend.list_client_classes()} == {"voip", "late"}
    assert {o.name for o in backend.global_options()} == {"domain-name", "domain-name-servers", "vendor-tag"}
    assert backend.option_defs()[0]["code"] == 224
    assert backend.config_schema()["series"] == "3"
    assert len(backend.config_hash()) == 64


def test_reservations_through_host_cmds_or_config(kea3, kea26):
    backend, fake = kea3
    found = backend.list_reservations()
    assert "reservation-get-page" in fake.commands()
    assert {(r.subnet_id, r.identifier) for r in found} == {
        (None, "aa:bb:cc:dd:ee:ff"),
        (1, "aa:bb:cc:dd:ee:01"),
        (2, "010A0B0C0D0E0F"),
    }
    assert [r.identifier for r in backend.list_reservations(1)] == ["aa:bb:cc:dd:ee:01"]
    old, fake26 = kea26
    assert [r.hostname for r in old.list_reservations()] == ["printer"]
    assert "reservation-get-page" not in fake26.commands()


def test_leases_paging(kea3, monkeypatch):
    backend, fake = kea3
    monkeypatch.setattr(kb, "LEASE_PAGE", 2)
    fake.leases = [
        {"ip-address": f"192.0.2.{i}", "subnet-id": 1 if i % 2 else 2, "cltt": 1792843949, "valid-lft": 60}
        for i in range(10, 17)
    ]
    assert [x.ip_address for x in backend.leases()] == [f"192.0.2.{i}" for i in range(10, 17)]
    assert [x.ip_address for x in backend.leases(subnet_id=2, limit=2)] == ["192.0.2.10", "192.0.2.12"]
    assert [x.ip_address for x in backend.leases(from_address="192.0.2.14")] == ["192.0.2.15", "192.0.2.16"]
    assert backend.leases(subnet_id=5) == []
    pages = [a for c, a in fake.sent if c == "lease4-get-page"]
    assert pages[0] == {"from": "start", "limit": 2}


def test_lease_reads_and_delete(kea3):
    backend, fake = kea3
    fake.leases = list(load("kea32-dhcp4-lease4-get-page")["arguments"]["leases"])
    assert backend.lease("192.0.2.150").hostname == "pc2"
    assert backend.lease("192.0.2.9") is None
    assert backend.leases_by_hw("aa:bb:cc:dd:ee:04")[0].ip_address == "192.0.2.151"
    assert backend.leases_by_hostname("nobody") == []
    with pytest.raises(NotSupported):
        backend.leases_by_duid("00:01")
    with pytest.raises(ConnectorError):
        backend.plan_lease_delete("192.0.2.9")
    plan = backend.plan_lease_delete("203.0.113.20", "tester")
    assert plan.requires_confirmation and plan.state is PlanState.VALIDATED
    assert plan.changes[0].before["state"] == "declined"
    assert backend.apply(plan).ok
    assert backend.lease("203.0.113.20") is None
    assert backend.rollback(plan).ok
    re_added = next(a for c, a in fake.sent if c == "lease4-add")
    assert re_added == {
        "ip-address": "203.0.113.20",
        "subnet-id": 10,
        "hw-address": "aa:bb:cc:dd:ee:05",
        "valid-lft": 3600,
        "state": 1,
    }


def test_command_path_for_reservation(kea3):
    backend, fake = kea3
    res = Reservation(
        subnet_id=1,
        id_type=ReservationIdType.HW_ADDRESS,
        identifier="aa:00:00:00:00:09",
        ip_address="192.0.2.9",
    )
    plan = backend.plan_reservation_change(
        Change(ChangeOp.ADD, "subnet4/1/reservations/hw-address=aa:00:00:00:00:09", after=res.to_dict()), "u"
    )
    assert plan.state is PlanState.VALIDATED and plan.preconditions[0].kind.value == "config_hash"
    assert '"ip-address": "192.0.2.9"' in plan.diff
    fake.sent.clear()
    result = backend.apply(plan)
    assert result.ok, result.message
    writes = [
        c for c in fake.commands() if c in ("reservation-add", "config-set", "config-write", "config-test")
    ]
    assert writes == ["reservation-add", "config-write"]
    assert fake.written[-1]["subnet4"][0]["reservations"][-1]["ip-address"] == "192.0.2.9"


def test_kea26_path_writes_26_names(kea26):
    backend, fake = kea26
    subnet = Subnet(
        id=0,
        subnet="203.0.113.0/26",
        family=Family.V4,
        pools=[Pool(pool="203.0.113.10 - 203.0.113.20", client_classes=["voip"])],
        client_classes=["voip"],
    )
    plan = backend.plan_subnet_change(Change(ChangeOp.ADD, "subnet4/new", after=subnet.to_dict()))
    assert plan.state is PlanState.VALIDATED
    fake.sent.clear()
    result = backend.apply(plan)
    assert result.ok, result.message
    writes = [
        c
        for c in fake.commands()
        if c in ("config-test", "config-set", "config-write") or c.startswith("subnet4")
    ]
    assert writes == ["config-test", "config-set", "config-write"]
    added = fake.cfg["subnet4"][-1]
    assert added["client-class"] == "voip" and added["pools"][0]["client-class"] == "voip"
    assert "client-classes" not in added and "client-classes" not in added["pools"][0]


def test_kea26_refuses_3x_only_keys(kea26):
    backend, _ = kea26
    two = Subnet(id=0, subnet="203.0.113.0/26", family=Family.V4, client_classes=["a", "b"])
    with pytest.raises(NotSupported):
        backend.plan_subnet_change(Change(ChangeOp.ADD, "subnet4/new", after=two.to_dict()))
    cfg = backend.config_get()
    cfg["control-sockets"] = [cfg.pop("control-socket")]
    with pytest.raises(NotSupported):
        backend.plan_config_replace(cfg)
    assert backend.config_schema()["series"] == "2.6"


def test_failed_config_test_marks_plan_failed(kea3):
    backend, fake = kea3
    fake.reject_test = lambda cfg: "bad pool" if any(s["id"] == 7 for s in cfg["subnet4"]) else None
    subnet = Subnet(id=7, subnet="203.0.113.0/26", family=Family.V4)
    plan = backend.plan_subnet_change(Change(ChangeOp.ADD, "subnet4/new", after=subnet.to_dict()))
    assert plan.state is PlanState.FAILED and plan.error == "bad pool"


def test_failure_mid_way_restores_running_config(kea3):
    backend, fake = kea3
    before = json.dumps(fake.cfg, sort_keys=True)
    res = Reservation(subnet_id=7, id_type=ReservationIdType.HW_ADDRESS, identifier="aa:00:00:00:00:07")
    subnet = Subnet(id=7, subnet="203.0.113.0/26", family=Family.V4, reservations=[res])
    plan = backend.plan_subnet_change(Change(ChangeOp.ADD, "subnet4/new", after=subnet.to_dict()))
    fake.overrides["reservation-add"] = err("database is down")
    result = backend.apply(plan)
    assert not result.ok and result.rolled_back
    assert "database is down" in result.message and "subnet4-add" in result.message
    assert json.dumps(fake.cfg, sort_keys=True) == before
    # The file was never written: only the running configuration goes back.
    assert fake.commands()[-2:] == ["config-set", "config-hash-get"] and "config-write" not in fake.commands()


def test_verification_failure_restores(kea3):
    backend, fake = kea3
    plan = backend.plan_subnet_change(Change(ChangeOp.DELETE, "subnet4/2"))
    fake.overrides["subnet4-del"] = {"result": 0, "text": "pretended"}
    result = backend.apply(plan)
    assert not result.ok and "subnet4/2 still present" in result.message


def test_precondition_and_rollback_of_global_change(kea3):
    backend, fake = kea3
    plan = backend.plan_global_change([Change(ChangeOp.REPLACE, "valid-lifetime", after=60)])
    assert plan.scope is PlanScope.DHCP_OPTIONS and plan.changes[0].before == 3600
    fake.cfg["valid-lifetime"] = 100
    with pytest.raises(PreconditionFailed):
        backend.apply(plan)
    fake.cfg["valid-lifetime"] = 3600
    assert backend.apply(plan).ok and fake.cfg["valid-lifetime"] == 60
    assert backend.rollback(plan).ok and fake.cfg["valid-lifetime"] == 3600
    assert (
        backend.plan_global_change([Change(ChangeOp.REPLACE, "hooks-libraries", after=[])]).scope
        is PlanScope.DHCP_CONFIG
    )
    assert (
        backend.plan_global_change([Change(ChangeOp.REPLACE, "ddns-send-updates", after=False)]).scope
        is PlanScope.DHCP_DDNS
    )
    with pytest.raises(ConnectorError):
        backend.plan_global_change([])


def test_config_replace_and_exact_rollback(kea3):
    backend, fake = kea3
    original = backend.config_get()
    new = backend.config_get()
    new["valid-lifetime"] = 10
    del new["option-def"]
    plan = backend.plan_config_replace({"Dhcp4": new})
    assert plan.scope is PlanScope.DHCP_CONFIG and plan.changes[0].target == "config"
    assert backend.apply(plan).ok and "option-def" not in fake.cfg
    assert backend.rollback(plan).ok
    assert fake.cfg == original


def test_ha_maintenance_and_service_toggle(kea3):
    backend, fake = kea3
    fake.status_args = load("kea32-dhcp4-status-get")["arguments"]
    fake.status_args["high-availability"][0]["ha-servers"]["local"]["state"] = "hot-standby"
    with pytest.raises(ConnectorError):
        backend.plan_ha_maintenance("pause")
    with pytest.raises(ConnectorError):
        backend.plan_ha_maintenance("cancel")
    plan = backend.plan_ha_maintenance("start", "u")
    assert plan.requires_confirmation and "server2 goes in-maintenance" in plan.summary
    assert backend.apply(plan).ok and "ha-maintenance-start" in fake.commands()
    with pytest.raises(PreconditionFailed):
        backend.apply(plan)
    assert backend.rollback(plan).ok and fake.commands()[-1] == "ha-maintenance-cancel"
    fake.overrides["ha-maintenance-start"] = err("partner unreachable")
    result = backend.apply(plan)
    assert not result.ok and "partner unreachable" in result.message

    plan = backend.plan_service_toggle(False)
    assert plan.changes[0].before == {"enabled": True}
    assert backend.apply(plan).ok and fake.status_args["dhcp-state"]["disabled-by-user"] is True
    assert backend.rollback(plan).ok and fake.status_args["dhcp-state"]["disabled-by-user"] is False


def test_ha_heartbeat_window_from_age_and_kea_clock(kea3):
    from datetime import UTC, datetime, timedelta

    from pelagos.connectors.kea.ha import heartbeat_window, kea_time
    from pelagos.domain import from_rfc3339

    backend, fake = kea3
    fake.status_args = load("kea32-dhcp4-status-get")["arguments"]
    fake.status_args["high-availability"][0]["ha-servers"]["remote"]["age"] = 3
    fake.overrides["ha-heartbeat"] = ok(
        {"date-time": "Sun, 25 Oct 2026 15:21:25 GMT", "state": "hot-standby", "unsent-update-count": 0}
    )
    ha = backend.ha_state()
    hb = ha.heartbeat
    assert hb is not None and hb["age"] == 3 and hb["kea_time"] == "2026-10-25T15:21:25.000Z"
    assert ("ha-heartbeat", {"server-name": ha.server_name}) in fake.sent
    assert from_rfc3339(hb["lo"]) <= from_rfc3339(hb["hi"])
    # Pure bounds: (T - age - 1, T - age] with T inside the exchange, capped by Kea's clock + 1 s.
    sent = datetime(2026, 10, 25, 15, 21, 25, 400000, tzinfo=UTC)
    received = sent + timedelta(milliseconds=900)
    window = heartbeat_window(2, sent, received, kea_time({"date-time": "Sun, 25 Oct 2026 15:21:25 GMT"}))
    assert window["lo"] == "2026-10-25T15:21:22.400Z" and window["hi"] == "2026-10-25T15:21:24.000Z"
    assert heartbeat_window(2, sent, received)["hi"] == "2026-10-25T15:21:24.300Z"
    assert heartbeat_window(None, sent, received) is None and heartbeat_window(-1, sent, received) is None
    assert kea_time({"date-time": "garbage"}) is None and kea_time({}) is None
    # A hook without ha-heartbeat still gives the window from status-get alone.
    fake.overrides["ha-heartbeat"] = err("'ha-heartbeat' command not supported.", 2)
    assert backend.ha_state().heartbeat["kea_time"] is None


def test_ha_absent(kea3):
    backend, _fake = kea3
    assert backend.ha_state().enabled is False
    with pytest.raises(NotSupported):
        backend.plan_ha_maintenance("start")


def test_pool_utilization(kea3):
    backend, fake = kea3
    fake.stats = load("kea32-dhcp4-statistic-get-all")["arguments"]
    rows = backend.pool_utilization()
    assert {r["subnet_id"] for r in rows} == {1, 2, 10, 11} and all(r["node_id"] == "n1" for r in rows)


def test_dhcp6_reads(tmp_root):
    backend, fake = backend_with(tmp_root, "kea32-dhcp6-config-get", "3.2.1", Family.V6)
    fake.leases = list(load("kea32-dhcp6-lease6-get-page")["arguments"]["leases"])
    assert backend.lease("2001:db8:1:1::").lease_type == "IA_PD"
    assert [a.get("type") for c, a in fake.sent if c == "lease6-get"] == ["IA_NA", "IA_PD"]
    assert len(backend.leases_by_duid("00:01:00:01:aa:bb")) == 2
    plan = backend.plan_lease_delete("2001:db8:1:1::")
    assert backend.apply(plan).ok
    assert [a for c, a in fake.sent if c == "lease6-del"] == [
        {"ip-address": "2001:db8:1:1::", "type": "IA_PD"}
    ]
    subnet = backend.get_subnet(1)
    assert subnet.pd_pools[0].delegated_len == 64


def test_d2_plan_masks_and_externalizes(tmp_root):
    d2 = D2Backend(
        make_ctx(tmp_root, d2_conf=str(tmp_root / "kea-dhcp-ddns.conf"), d2_secret_dir=str(tmp_root))
    )
    fake = FakeKea("DhcpDdns", config_of("kea32-d2-config-get"))
    d2.socket = fake
    cfg = d2.config_get()
    cfg["tsig-keys"].append({"name": "extra", "algorithm": "HMAC-SHA256", "secret": "c2VjcmV0c2VjcmV0"})
    plan = d2.plan_config_replace({"DhcpDdns": cfg})
    assert "c2VjcmV0c2VjcmV0" not in json.dumps(plan.to_dict())
    assert plan.changes[1].target == "secret-file/extra.secret"
    result = d2.apply(plan)
    assert result.ok, result.message
    assert (tmp_root / "extra.secret").read_text() == "c2VjcmV0c2VjcmV0"
    assert fake.cfg["tsig-keys"][-1] == {
        "name": "extra",
        "algorithm": "HMAC-SHA256",
        "secret-file": str(tmp_root / "extra.secret"),
    }
    assert d2.rollback(plan).ok
    assert not (tmp_root / "extra.secret").exists()
    assert [k["name"] for k in fake.cfg["tsig-keys"]] == ["kea-ddns"]
    assert d2.config_schema()["root"] == "DhcpDdns"
    assert d2.stats().node_id == "n1"


def test_plans_only_touch_their_scope(kea3):
    backend, _ = kea3
    whole = Change(ChangeOp.REPLACE, "config", after={})
    with pytest.raises(ConnectorError, match=r"dhcp\.subnet plan"):
        backend.plan_subnet_change(whole)
    with pytest.raises(ConnectorError):
        backend.plan_reservation_change(Change(ChangeOp.DELETE, "subnet4/1"))
    with pytest.raises(ConnectorError):
        backend.plan_class_change(Change(ChangeOp.DELETE, "shared-networks/office"))
    with pytest.raises(ConnectorError, match="own plans"):
        backend.plan_global_change([Change(ChangeOp.REPLACE, "subnet4", after=[])])
    with pytest.raises(ConnectorError):
        backend.plan_global_change([whole])
    with pytest.raises(ConnectorError, match="not a kea4 subnet"):
        backend.plan_subnet_change(Change(ChangeOp.DELETE, "subnet6/1"))


def test_subnet_add_uses_the_target_id(kea3):
    backend, _ = kea3
    subnet = Subnet(id=0, subnet="203.0.113.0/26", family=Family.V4)
    plan = backend.plan_subnet_change(Change(ChangeOp.ADD, "subnet4/42", after=subnet.to_dict()))
    assert plan.changes[0].target == "subnet4/42" and plan.changes[0].after["id"] == 42
    with pytest.raises(ConnectorError, match="already exists"):
        backend.plan_subnet_change(Change(ChangeOp.ADD, "subnet4/2", after=subnet.to_dict()))


def test_rollback_removes_created_key_and_option(kea3):
    backend, fake = kea3
    original = json.dumps(fake.cfg, sort_keys=True)
    assert "cache-max-age" not in fake.cfg
    plan = backend.plan_global_change(
        [
            Change(ChangeOp.REPLACE, "cache-max-age", after=600),
            Change(
                ChangeOp.REPLACE,
                "option-data/dhcp4/ntp-servers",
                after={"name": "ntp-servers", "data": "192.0.2.123"},
            ),
        ]
    )
    assert plan.changes[0].before is None and plan.changes[1].before is None
    assert backend.apply(plan).ok and fake.cfg["cache-max-age"] == 600
    result = backend.rollback(plan)
    assert result.ok, result.message
    assert json.dumps(fake.cfg, sort_keys=True) == original


def hosts_db_backend(tmp_root):
    backend, fake = backend_with(tmp_root, "kea32-dhcp4-config-get", "3.2.1")
    fake.cfg["hosts-database"] = {"type": "postgresql", "name": "kea"}
    return backend, fake


def db_res(ip: str = "192.0.2.21") -> Reservation:
    return Reservation(
        subnet_id=1, id_type=ReservationIdType.HW_ADDRESS, identifier="aa:00:00:00:00:21", ip_address=ip
    )


TARGET21 = "subnet4/1/reservations/hw-address=aa:00:00:00:00:21"


def test_reservations_go_to_the_hosts_database(tmp_root):
    backend, fake = hosts_db_backend(tmp_root)
    config_before = json.dumps(fake.cfg, sort_keys=True)
    plan = backend.plan_reservation_change(Change(ChangeOp.ADD, TARGET21, after=db_res().to_dict()))
    assert plan.state is PlanState.VALIDATED and "hosts-database/" + TARGET21 in plan.diff
    result = backend.apply(plan)
    assert result.ok, result.message
    adds = [a for c, a in fake.sent if c == "reservation-add"]
    assert "operation-target" not in adds[-1]
    assert [h["ip-address"] for h in fake.db_hosts] == ["192.0.2.21"]
    assert json.dumps(fake.cfg, sort_keys=True) == config_before

    replace = backend.plan_reservation_change(
        Change(ChangeOp.REPLACE, TARGET21, after=db_res("192.0.2.22").to_dict())
    )
    assert replace.changes[0].before["ip_address"] == "192.0.2.21"
    assert backend.apply(replace).ok and fake.db_hosts[0]["ip-address"] == "192.0.2.22"
    assert backend.rollback(replace).ok and fake.db_hosts[0]["ip-address"] == "192.0.2.21"

    delete = backend.plan_reservation_change(Change(ChangeOp.DELETE, TARGET21))
    assert backend.apply(delete).ok and fake.db_hosts == []
    assert backend.rollback(delete).ok and fake.db_hosts[0]["ip-address"] == "192.0.2.21"
    assert backend.rollback(plan).ok and fake.db_hosts == []


def test_hosts_database_failure_undoes_the_host_commands(tmp_root):
    backend, fake = hosts_db_backend(tmp_root)
    fake.db_hosts.append({**kb.kcfg.reservation_to_kea(db_res(), with_subnet_id=True)})
    replace = backend.plan_reservation_change(
        Change(ChangeOp.REPLACE, TARGET21, after=db_res("192.0.2.22").to_dict())
    )
    add = Reservation(subnet_id=1, id_type=ReservationIdType.HW_ADDRESS, identifier="aa:00:00:00:00:23")
    target23 = "subnet4/1/reservations/hw-address=aa:00:00:00:00:23"
    plan = backend.plan_reservation_change(Change(ChangeOp.ADD, target23, after=add.to_dict()))
    # The host lands in the database but config-write fails: the add is undone with reservation-del.
    fake.overrides["config-write"] = err("disk full")
    result = backend.apply(plan)
    assert not result.ok and result.rolled_back and "disk full" in result.message
    assert [h["hw-address"] for h in fake.db_hosts] == ["aa:00:00:00:00:21"]
    result = backend.apply(replace)
    assert not result.ok and result.rolled_back
    assert fake.db_hosts[0]["ip-address"] == "192.0.2.21"
    del fake.overrides["config-write"]
    # A host command that reports success without writing fails verification.
    fake.overrides["reservation-add"] = {"result": 0, "text": "pretended"}
    plan = backend.plan_reservation_change(Change(ChangeOp.ADD, target23, after=add.to_dict()))
    result = backend.apply(plan)
    assert not result.ok and f"{target23} missing" in result.message


def test_subnet_reservations_stay_in_memory_with_a_hosts_database(tmp_root):
    backend, fake = hosts_db_backend(tmp_root)
    res = Reservation(subnet_id=7, id_type=ReservationIdType.HW_ADDRESS, identifier="aa:00:00:00:00:07")
    subnet = Subnet(id=7, subnet="203.0.113.0/26", family=Family.V4, reservations=[res])
    plan = backend.plan_subnet_change(Change(ChangeOp.ADD, "subnet4/new", after=subnet.to_dict()))
    result = backend.apply(plan)
    assert result.ok, result.message
    assert [a.get("operation-target") for c, a in fake.sent if c == "reservation-add"] == ["memory"]
    assert fake.db_hosts == [] and backend.get_subnet(7).reservations[0].identifier == "aa:00:00:00:00:07"


def test_backup_failure_is_reported(kea3, tmp_root):
    backend, fake = kea3
    backend.conf_path.write_text("{}")
    backend.backup_root = backend.file.backup_root = tmp_root / "not-a-dir"
    backend.backup_root.write_text("")
    plan = backend.plan_global_change([Change(ChangeOp.REPLACE, "valid-lifetime", after=60)])
    result = backend.apply(plan)
    assert not result.ok and result.message.startswith("backup failed")
    assert fake.cfg["valid-lifetime"] == 3600


def test_version_follows_an_upgrade(kea26):
    backend, fake = kea26
    assert backend.version() == "2.6.3"
    fake.version_text = "3.2.1"
    assert backend.capabilities().version == "3.2.1" and backend.version() == "3.2.1"


def d2_with(tmp_root):
    d2 = D2Backend(
        make_ctx(tmp_root, d2_conf=str(tmp_root / "kea-dhcp-ddns.conf"), d2_secret_dir=str(tmp_root))
    )
    fake = FakeKea("DhcpDdns", config_of("kea32-d2-config-get"))
    d2.socket = fake
    return d2, fake


def test_d2_running_clear_secret_stays_out_of_plans(tmp_root):
    d2, fake = d2_with(tmp_root)
    fake.cfg["tsig-keys"] = [{"name": "old", "algorithm": "HMAC-SHA256", "secret": "b2xkc2VjcmV0b2xk"}]
    original = json.loads(json.dumps(fake.cfg))
    new = d2.config_get()
    new["tsig-keys"] = [{"name": "old", "algorithm": "HMAC-SHA256", "secret-file": "/etc/kea/old.secret"}]
    plan = d2.plan_config_replace({"DhcpDdns": new})
    assert "b2xkc2VjcmV0b2xk" not in json.dumps(plan.to_dict())
    assert d2.apply(plan).ok
    assert d2.rollback(plan).ok and fake.cfg == original
    # Once the private copy is gone, a masked before state is never written back.
    plan = d2.plan_config_replace({"DhcpDdns": new})
    d2._private.clear()
    result = d2.rollback(plan)
    assert not result.ok and "backup" in result.message


def test_d2_rollback_refused_after_a_later_change(tmp_root):
    d2, fake = d2_with(tmp_root)
    a = d2.config_get()
    a["dns-server-timeout"] = 700
    plan_a = d2.plan_config_replace({"DhcpDdns": a})
    assert d2.apply(plan_a).ok
    b = d2.config_get()
    b["dns-server-timeout"] = 800
    plan_b = d2.plan_config_replace({"DhcpDdns": b})
    assert d2.apply(plan_b).ok
    with pytest.raises(PreconditionFailed):
        d2.rollback(plan_a)
    assert fake.cfg["dns-server-timeout"] == 800
    assert d2.rollback(plan_b).ok and fake.cfg["dns-server-timeout"] == 700
    assert d2.rollback(plan_a).ok and fake.cfg["dns-server-timeout"] != 700


def test_d2_expired_plans_drop_their_secrets(tmp_root):
    d2, _fake = d2_with(tmp_root)
    cfg = d2.config_get()
    cfg["tsig-keys"].append({"name": "extra", "algorithm": "HMAC-SHA256", "secret": "c2VjcmV0c2VjcmV0"})
    plan = d2.plan_config_replace({"DhcpDdns": cfg})
    assert plan.id in d2._private
    d2._private[plan.id].expires_at = utcnow() - timedelta(seconds=1)
    d2.plan_config_replace({"DhcpDdns": d2.config_get()})
    assert plan.id not in d2._private


def test_d2_secret_file_wins_over_clear_secret(tmp_root):
    cfg = {"tsig-keys": [{"name": "k", "secret": "c2VjcmV0", "secret-file": "/etc/kea/k.secret"}]}
    out, files = externalize_secrets(cfg, tmp_root)
    assert out["tsig-keys"] == [{"name": "k", "secret-file": "/etc/kea/k.secret"}] and files == {}


def test_d2_masked_secrets_take_the_running_value(tmp_root):
    from pelagos.services.dhcp_service import mask_d2_secrets

    d2, fake = d2_with(tmp_root)
    fake.cfg["tsig-keys"].append({"name": "legacy", "algorithm": "HMAC-SHA256", "secret": "bGVnYWN5"})
    edited = mask_d2_secrets(d2.config_get())
    plan = d2.plan_config_replace({"DhcpDdns": edited})
    masked = hashlib.sha256(b"***").hexdigest()
    files = {c.target: c.after["sha256"] for c in plan.changes if c.target.startswith("secret-file/")}
    assert masked not in files.values()
    assert files == {"secret-file/legacy.secret": hashlib.sha256(b"bGVnYWN5").hexdigest()}
    keys = {k["name"]: k for k in plan.changes[0].after["tsig-keys"]}
    assert "secret" not in keys["kea-ddns"] and keys["kea-ddns"]["secret-file"]
    edited["tsig-keys"].append({"name": "new", "algorithm": "HMAC-SHA256", "secret": "***"})
    with pytest.raises(ConnectorError, match="masked secret"):
        d2.plan_config_replace({"DhcpDdns": edited})


@pytest.mark.parametrize(
    "path",
    ["/etc/pelagos/x.secret", "{dir}/../x.secret", "{dir}/x.conf", "{dir}/a b.secret", "x.secret"],
)
def test_d2_refuses_peer_secrets_outside_the_secret_dir(tmp_root, path):
    d2, _fake = d2_with(tmp_root)
    path = path.format(dir=tmp_root)
    plan = d2.plan_config_replace({"DhcpDdns": d2.config_get()})
    digest = hashlib.sha256(b"c2VjcmV0").hexdigest()
    plan.changes.append(Change(ChangeOp.ADD, "secret-file/x.secret", after={"path": path, "sha256": digest}))
    with pytest.raises(ConnectorError, match="outside"):
        d2.accept_plan_secrets(plan, {path: "c2VjcmV0"})
    good = str(tmp_root / "x.secret")
    plan.changes.append(Change(ChangeOp.ADD, "secret-file/x.secret", after={"path": good, "sha256": digest}))
    d2.accept_plan_secrets(plan, {good: "c2VjcmV0"})
    assert d2.plan_secrets(plan.id) == {good: "c2VjcmV0"}
