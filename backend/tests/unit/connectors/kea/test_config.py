# SPDX-License-Identifier: Apache-2.0
"""Projections between config-get JSON and domain objects, on captured Kea 3.2 and 2.6 payloads."""

from __future__ import annotations

import copy

import pytest

from pelagos.connectors.base import ConnectorError, NotSupported
from pelagos.connectors.kea import config as kcfg
from pelagos.domain import (
    Change,
    ChangeOp,
    ClientClass,
    Family,
    OptionData,
    PdPool,
    Pool,
    Reservation,
    ReservationIdType,
    Subnet,
)
from tests.unit.connectors.kea.fake import config_of

pytestmark = pytest.mark.unit

PAYLOADS = [
    ("kea32-dhcp4-config-get", Family.V4, "3.2.1"),
    ("kea32-dhcp6-config-get", Family.V6, "3.2.1"),
    ("kea26-dhcp4-config-get", Family.V4, "2.6.3"),
    ("kea26-dhcp6-config-get", Family.V6, "2.6.3"),
]


@pytest.mark.parametrize(("name", "family", "version"), PAYLOADS)
def test_round_trip_is_identity(name, family, version):
    """Projecting then writing back every object of a real configuration changes nothing."""
    cfg = config_of(name)
    for obj, net in kcfg.iter_subnets(cfg, family):
        subnet = kcfg.subnet_from_kea(obj, family, net, version)
        assert kcfg.subnet_to_kea(subnet, version) == obj
        # Through JSON too, as the API sends it.
        again = Subnet.from_dict(subnet.to_dict())
        assert kcfg.subnet_to_kea(again, version) == obj
    for obj in cfg.get("shared-networks") or []:
        net = kcfg.shared_network_from_kea(obj, family, version)
        assert kcfg.shared_network_to_kea(net, version) == obj
    for obj in cfg.get("client-classes") or []:
        assert kcfg.client_class_to_kea(kcfg.client_class_from_kea(obj, version), version) == obj
    for obj in cfg.get("reservations") or []:
        assert kcfg.reservation_to_kea(kcfg.reservation_from_kea(obj, None)) == obj
    for obj in cfg.get("option-data") or []:
        opt = kcfg.option_from_kea(obj, "dhcp4" if family is Family.V4 else "dhcp6")
        assert kcfg.option_to_kea(OptionData.from_dict(opt.to_dict())) == obj


def test_dhcp4_projection_fields():
    cfg = config_of("kea32-dhcp4-config-get")
    subnets = {
        s.id: s
        for s in (
            kcfg.subnet_from_kea(o, Family.V4, n, "3.2.1") for o, n in kcfg.iter_subnets(cfg, Family.V4)
        )
    }
    assert sorted(subnets) == [1, 2, 10, 11]
    s1 = subnets[1]
    assert s1.subnet == "192.0.2.0/24" and s1.shared_network is None
    assert [p.pool for p in s1.pools] == ["192.0.2.100-192.0.2.199", "192.0.2.200-192.0.2.220"]
    assert s1.pools[1].client_classes == ["voip"]
    assert s1.options[0].name == "routers" and s1.options[0].data == "192.0.2.1"
    assert s1.reservations[0].identifier == "aa:bb:cc:dd:ee:01" and s1.reservations[0].subnet_id == 1
    assert s1.user_context["pelagos"]["notes"] == "fixture subnet"
    assert subnets[2].relay == ["198.51.100.254"]
    assert subnets[2].ddns["ddns-qualifying-suffix"] == "example.lan."
    assert subnets[2].reservations[0].id_type is ReservationIdType.CLIENT_ID
    assert subnets[10].shared_network == "office"
    classes = {c.name: c for c in (kcfg.client_class_from_kea(c, "3.2.1") for c in cfg["client-classes"])}
    assert classes["late"].only_in_additional_list is True
    assert classes["voip"].next_server is None


def test_dhcp6_projection_pd_pools():
    cfg = config_of("kea32-dhcp6-config-get")
    s1 = kcfg.subnet_from_kea(cfg["subnet6"][0], Family.V6, None, "3.2.1")
    pd = s1.pd_pools[0]
    assert (pd.prefix, pd.prefix_len, pd.delegated_len) == ("2001:db8:1::", 48, 64)
    assert (pd.excluded_prefix, pd.excluded_prefix_len) == ("2001:db8:1:0:ff00::", 72)
    res = s1.reservations[0]
    assert res.id_type is ReservationIdType.DUID
    assert res.ip_addresses == ["2001:db8::100"] and res.prefixes == ["2001:db8:1:100::/64"]
    assert res.hostname is None and kcfg.reservation_to_kea(res)["hostname"] == ""


def test_kea26_names_are_normalized():
    cfg = config_of("kea26-dhcp4-config-get")
    subnet = kcfg.subnet_from_kea(cfg["subnet4"][0], Family.V4, None, "2.6.3")
    assert subnet.pools[1].client_classes == ["voip"]
    assert cfg["subnet4"][0]["pools"][1]["client-class"] == "voip"
    late = kcfg.client_class_from_kea(cfg["client-classes"][1], "2.6.3")
    assert late.only_in_additional_list is True
    # Written for a 3.x server, the 2.6 names become the 3.x ones.
    v3 = kcfg.subnet_to_kea(subnet, "3.2.1")
    assert v3["pools"][1]["client-classes"] == ["voip"] and "client-class" not in v3["pools"][1]
    assert v3["evaluate-additional-classes"] == ["late"] and "require-client-classes" not in v3
    assert kcfg.client_class_to_kea(late, "3.2.1")["only-in-additional-list"] is True


def test_kea3_names_map_back_to_26():
    pool = Pool(
        pool="192.0.2.10 - 192.0.2.20", client_classes=["voip"], raw={"evaluate-additional-classes": ["x"]}
    )
    out = kcfg.pool_to_kea(pool, "2.6.3")
    assert out["client-class"] == "voip" and "client-classes" not in out
    assert out["require-client-classes"] == ["x"]
    with pytest.raises(NotSupported):
        kcfg.pool_to_kea(pool.replace(client_classes=["a", "b"]), "2.6.3")
    cls = ClientClass(name="late", only_in_additional_list=True)
    assert kcfg.client_class_to_kea(cls, "2.6.3") == {"name": "late", "only-if-required": True}


def test_check_version_support():
    kcfg.check_version_support({"control-sockets": []}, "3.2.1")
    with pytest.raises(NotSupported):
        kcfg.check_version_support({"control-sockets": []}, "2.6.3")
    with pytest.raises(NotSupported):
        kcfg.check_version_support({"subnet4": [{"subnet": "x", "client-classes": ["a"]}]}, "2.6.3")
    with pytest.raises(NotSupported):
        kcfg.check_version_support(
            {"shared-networks": [{"name": "n", "subnet4": [], "client-classes": []}]}, "2.6"
        )
    # Class definitions at the root and reservation classes exist on 2.6 too.
    kcfg.check_version_support(config_of("kea26-dhcp4-config-get"), "2.6.3")
    kcfg.check_version_support({"reservations": [{"hw-address": "aa", "client-classes": ["a"]}]}, "2.6.3")


def test_normalize_root_control_sockets():
    cfg = {"control-socket": {"socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket"}}
    assert kcfg.normalize_root(cfg, "3.2.1") is cfg
    assert kcfg.normalize_root(cfg, "3.3.1") == {"control-sockets": [cfg["control-socket"]]}
    assert kcfg.version_tuple("3.2.1 (isc deb)") == (3, 2, 1) and kcfg.version_tuple(None) > (3, 3)


def test_unmodeled_keys_survive_an_edit():
    cfg = config_of("kea32-dhcp4-config-get")
    obj = cfg["subnet4"][1]
    obj["future-key"] = {"x": 1}
    subnet = kcfg.subnet_from_kea(obj, Family.V4, None, "3.2.1")
    edited = subnet.replace(valid_lifetime=600, pools=[*subnet.pools, Pool(pool="198.51.100.200/29")])
    out = kcfg.subnet_to_kea(edited, "3.2.1")
    assert out["future-key"] == {"x": 1}
    assert out["valid-lifetime"] == 600 and out["pools"][-1] == {"pool": "198.51.100.200/29"}
    # Bounds Kea derived from the old lifetime are dropped so it derives them again.
    assert "min-valid-lifetime" not in out and "max-valid-lifetime" not in out
    assert out["relay"] == obj["relay"] and out["ddns-send-updates"] is True


def test_explicit_lifetime_bounds_are_kept():
    raw = {
        "id": 1,
        "subnet": "192.0.2.0/24",
        "valid-lifetime": 3600,
        "min-valid-lifetime": 600,
        "max-valid-lifetime": 3600,
    }
    subnet = kcfg.subnet_from_kea(raw, Family.V4)
    out = kcfg.subnet_to_kea(subnet.replace(valid_lifetime=1200), "3.2.1")
    assert out["min-valid-lifetime"] == 600 and "max-valid-lifetime" not in out


def test_pd_pool_and_reservation_to_kea():
    pd = PdPool(prefix="2001:db8:9::", prefix_len=48, delegated_len=56)
    assert kcfg.pd_pool_to_kea(pd, "3.2.1") == {
        "prefix": "2001:db8:9::",
        "prefix-len": 48,
        "delegated-len": 56,
    }
    res = Reservation(
        subnet_id=3,
        id_type=ReservationIdType.HW_ADDRESS,
        identifier="aa:bb:cc:dd:ee:ff",
        ip_address="192.0.2.5",
        hostname="h",
        user_context={"pelagos": {"notes": "n"}},
    )
    assert kcfg.reservation_to_kea(res, with_subnet_id=True) == {
        "hw-address": "aa:bb:cc:dd:ee:ff",
        "ip-address": "192.0.2.5",
        "hostname": "h",
        "user-context": {"pelagos": {"notes": "n"}},
        "subnet-id": 3,
    }
    with pytest.raises(ConnectorError):
        kcfg.reservation_from_kea({"ip-address": "192.0.2.1"}, 1)


def test_pelagos_context_helpers():
    ctx = {"site": "a", "pelagos": {"notes": "old", "tags": ["x"]}}
    out = kcfg.with_pelagos_context(ctx, notes="new", owner=None)
    assert out == {"site": "a", "pelagos": {"notes": "new", "tags": ["x"]}}
    assert kcfg.pelagos_context(out)["notes"] == "new" and ctx["pelagos"]["notes"] == "old"


@pytest.mark.parametrize(
    ("target", "kind", "fields"),
    [
        ("config", "config", {}),
        ("subnet4/12", "subnet", {"subnet_id": 12}),
        ("subnet6/new", "subnet", {"subnet_id": None}),
        (
            "subnet4/1/reservations/hw-address=AA:BB",
            "reservation",
            {"subnet_id": 1, "reservation_key": "hw-address=aa:bb"},
        ),
        ("global/reservations/duid=01:02", "reservation", {"global_reservation": True}),
        ("shared-networks/office", "shared_network", {"name": "office"}),
        ("client-classes/voip", "client_class", {"name": "voip"}),
        ("option-data/dhcp4/6", "option", {"space": "dhcp4", "name": "6"}),
        ("valid-lifetime", "key", {"name": "valid-lifetime"}),
        ("lease6/2001:db8::1", "lease", {"name": "2001:db8::1"}),
        ("ha/maintenance", "ha", {}),
        ("service", "service", {}),
    ],
)
def test_parse_target(target, kind, fields):
    t = kcfg.parse_target(target)
    assert t.kind == kind
    for key, value in fields.items():
        assert getattr(t, key) == value


def test_parse_target_rejects_garbage():
    with pytest.raises(ConnectorError):
        kcfg.parse_target("subnet4/x/y/z")


def test_apply_change_kinds():
    cfg = config_of("kea32-dhcp4-config-get")
    original = copy.deepcopy(cfg)
    new_subnet = Subnet(id=0, subnet="192.0.2.0/25", family=Family.V4, shared_network="office")
    out = kcfg.apply_change(
        cfg, Change(ChangeOp.ADD, "subnet4/new", after=new_subnet.to_dict()), Family.V4, "3.2.1"
    )
    assert cfg == original, "apply_change works on a copy"
    office = out["shared-networks"][0]["subnet4"]
    assert office[-1]["id"] == 12 and office[-1]["subnet"] == "192.0.2.0/25"
    assert kcfg.next_subnet_id(out, Family.V4) == 13

    out = kcfg.apply_change(cfg, Change(ChangeOp.DELETE, "subnet4/10"), Family.V4)
    assert [s["id"] for s in out["shared-networks"][0]["subnet4"]] == [11]
    with pytest.raises(ConnectorError):
        kcfg.apply_change(cfg, Change(ChangeOp.DELETE, "subnet4/99"), Family.V4)

    moved = kcfg.subnet_from_kea(cfg["subnet4"][1], Family.V4).replace(shared_network="office")
    out = kcfg.apply_change(
        cfg, Change(ChangeOp.REPLACE, "subnet4/2", after=moved.to_dict()), Family.V4, "3.2.1"
    )
    assert [s["id"] for s in out["subnet4"]] == [1]
    assert [s["id"] for s in out["shared-networks"][0]["subnet4"]] == [10, 11, 2]

    res = Reservation(subnet_id=0, id_type=ReservationIdType.HW_ADDRESS, identifier="aa:00:00:00:00:01")
    out = kcfg.apply_change(
        cfg,
        Change(ChangeOp.ADD, "global/reservations/hw-address=aa:00:00:00:00:01", after=res.to_dict()),
        Family.V4,
    )
    assert out["reservations"][-1] == {"hw-address": "aa:00:00:00:00:01"}
    with pytest.raises(ConnectorError):
        kcfg.apply_change(
            cfg,
            Change(ChangeOp.ADD, "global/reservations/hw-address=aa:bb:cc:dd:ee:ff", after=res.to_dict()),
            Family.V4,
        )

    opt = Change(
        ChangeOp.REPLACE, "option-data/dhcp4/domain-name", after={"name": "domain-name", "data": "x.lan"}
    )
    out = kcfg.apply_change(cfg, opt, Family.V4)
    assert next(o for o in out["option-data"] if o["name"] == "domain-name")["data"] == "x.lan"
    out = kcfg.apply_change(cfg, Change(ChangeOp.DELETE, "option-data/dhcp4/domain-name"), Family.V4)
    assert all(o.get("name") != "domain-name" for o in out["option-data"])

    out = kcfg.apply_change(cfg, Change(ChangeOp.REPLACE, "valid-lifetime", after=99), Family.V4)
    assert out["valid-lifetime"] == 99
    with pytest.raises(NotSupported):
        kcfg.apply_change(cfg, Change(ChangeOp.ADD, "control-sockets", after=[]), Family.V4, "2.6.3")

    cls = ClientClass(name="new", test="member('ALL')")
    out = kcfg.apply_change(cfg, Change(ChangeOp.ADD, "client-classes/new", after=cls.to_dict()), Family.V4)
    assert out["client-classes"][-1] == {"name": "new", "test": "member('ALL')"}
    with pytest.raises(ConnectorError):
        kcfg.apply_change(cfg, Change(ChangeOp.ADD, "client-classes/voip", after=cls.to_dict()), Family.V4)


def test_apply_change_replace_without_raw_keeps_existing_keys():
    cfg = config_of("kea32-dhcp4-config-get")
    bare = Subnet(id=2, subnet="198.51.100.0/24", family=Family.V4, valid_lifetime=60)
    out = kcfg.apply_change(
        cfg, Change(ChangeOp.REPLACE, "subnet4/2", after=bare.to_dict()), Family.V4, "3.2.1"
    )
    # A caller without `raw` starts from the current object: untyped keys survive, typed ones follow `after`.
    assert out["subnet4"][1]["valid-lifetime"] == 60
    typed = {"min-valid-lifetime", "max-valid-lifetime", "ddns-send-updates", "ddns-qualifying-suffix"}
    assert set(cfg["subnet4"][1]) - typed <= set(out["subnet4"][1])
    assert out["subnet4"][1]["pools"] == []


def test_config_diff():
    before = {"a": 1, "b": [1, 2]}
    diff = kcfg.config_diff(before, {"a": 2, "b": [1, 2]}, "/etc/kea/kea-dhcp4.conf")
    assert diff.startswith("--- a//etc/kea/kea-dhcp4.conf\n+++ b//etc/kea/kea-dhcp4.conf\n")
    assert '-  "a": 1,' in diff and '+  "a": 2,' in diff
    assert kcfg.config_diff(before, before, "x") == ""
