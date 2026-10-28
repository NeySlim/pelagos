# SPDX-License-Identifier: Apache-2.0
"""Return of an old DDNS primary and planned switchover (batch D4): the stale-primary decision from
ddns.roles and the epoch of the served file, the return plan (demotion, own D2 lists) and the
switchover parts (freeze, promotion waiting for the serial, demotion, D2 lists, ddns.roles)."""

from __future__ import annotations

from typing import Any

import pytest

from pelagos.domain import Change, PlanScope, ZoneKind
from pelagos.services import ddns_failover as df
from pelagos.services.errors import Conflict, ValidationError
from tests.unit.services.test_ddns_failover import N1, N2, N3, d2_config, dns_node, part, zone
from tests.unit.services.test_ddns_failover_promote import KEY, ROLE, service, three_nodes

pytestmark = pytest.mark.unit


def primary(file: str | None = None, view: str = "_default"):
    return zone("example.lan.", file=file, view=view)


@pytest.mark.parametrize(
    ("role", "zones", "expected"),
    [
        ({"primary": "me", "epoch": 2}, [primary()], []),  # this node holds the role
        ({"primary": N2, "epoch": 2}, [zone("example.lan.", ZoneKind.SECONDARY)], []),  # a copy already
        ({"primary": N2, "epoch": 2}, [primary("/z/example.lan.db")], [(None, True)]),  # original file
        ({"primary": N2, "epoch": 2}, [primary("/z/example.lan.e2.db")], [(2, False)]),  # same epoch
        ({"primary": N2, "epoch": 3}, [primary("/z/example.lan.e2.db")], [(2, True)]),
        ({"primary": N2, "epoch": 2}, [primary("/z/example.lan.e3.db")], []),  # roles not caught up
        ({"primary": N2, "epoch": 1}, [primary("/z/example.lan.db")], [(None, False)]),  # two originals
        ({"primary": N2, "epoch": 2}, [primary(view="inside")], []),  # another view
    ],
)
def test_stale_primaries(role, zones, expected):
    found = df.stale_primaries({KEY: role}, zones, "me")
    assert [(s.local_epoch, s.demotable) for s in found] == expected
    for s in found:
        assert (s.key, s.zone, s.view, s.primary) == (KEY, "example.lan.", "_default", N2)


class Local:
    """This node's BIND connector: the parts it builds are recorded."""

    def __init__(self) -> None:
        self.built: list[list[Change]] = []

    def plan_zone_changes(self, changes: list[Change], created_by: str = ""):
        self.built.append(changes)
        return part(PlanScope.DNS_ZONE, changes, N1)


class LocalD2:
    def __init__(self) -> None:
        self.configs: list[dict[str, Any]] = []

    def plan_config_replace(self, config: dict[str, Any], created_by: str = ""):
        self.configs.append(config)
        return part(PlanScope.D2_CONFIG, [], N1)


def returned(n1_file: str | None, d2_first: str = "192.0.2.2"):
    """N1 back after N2 was promoted at epoch 2; N1's D2 lists `d2_first` first."""
    inv = three_nodes(role={**ROLE, "primary": N2, "epoch": 2})
    inv.dns[N1] = dns_node(N1, [primary(n1_file)])
    inv.dns[N2] = dns_node(N2, [primary("/z/example.lan.e2.db")])
    others = [a for a in ("192.0.2.1", "192.0.2.2", "192.0.2.3") if a != d2_first]
    inv.d2 = {N1: df.D2Node(N1, "ns1", d2_config(*({"ip-address": a} for a in [d2_first, *others])))}
    return inv


def test_return_demotes_into_a_copy_of_the_recorded_primary(monkeypatch):
    svc, rec = service(returned("/z/example.lan.db"), monkeypatch=monkeypatch)
    local, d2 = Local(), LocalD2()
    svc.dns.local = local
    svc.registry.d2 = d2
    plan = svc.return_plan("system")
    assert plan is not None and plan.requires_confirmation
    assert plan.summary_message["key"] == "plan.ddns.demote"
    assert plan.summary_message["params"]["primary"] == "ns2"
    [[change]] = local.built
    assert change.target == KEY and change.after["kind"] == "secondary"
    assert change.after["primaries"] == ["192.0.2.2 key ddi-read"]
    assert change.after["demote"] == {"to": N2, "epoch": 2}
    assert "update_policy" not in change.after
    assert d2.configs == []  # its D2 already lists ns2 first
    assert [p.scope for p in rec.composites[plan.id]] == [PlanScope.DNS_ZONE]


def test_return_fixes_its_own_d2_lists(monkeypatch):
    svc, _rec = service(returned("/z/example.lan.e3.db", d2_first="192.0.2.1"), monkeypatch=monkeypatch)
    local, d2 = Local(), LocalD2()
    svc.dns.local = local
    svc.registry.d2 = d2
    # Its file is from a later promotion: not stale, but its D2 still puts itself first.
    plan = svc.return_plan("system")
    assert plan is not None and local.built == []
    [config] = d2.configs
    servers = config["forward-ddns"]["ddns-domains"][0]["dns-servers"]
    assert [s["ip-address"] for s in servers] == ["192.0.2.2", "192.0.2.1", "192.0.2.3"]
    assert svc.return_plan("system", d2=False) is None


def test_nothing_to_return(monkeypatch):
    svc, _rec = service(returned("/z/example.lan.e3.db"), monkeypatch=monkeypatch)
    svc.dns.local, svc.registry.d2 = Local(), LocalD2()
    assert svc.return_plan("system") is None


def test_switchover_parts(monkeypatch):
    svc, rec = service(three_nodes(), answers=True, monkeypatch=monkeypatch)
    local = Local()
    svc.dns.local = local
    plan = svc.switchover_plan({"to_node_id": N2}, "alice")
    assert plan.requires_confirmation and plan.summary_message["key"] == "plan.ddns.switchover"
    assert plan.summary_message["params"]["epoch"] == 2
    parts = rec.composites[plan.id]
    assert [(p.scope, p.target_node_ids) for p in parts] == [
        (PlanScope.DNS_ZONE, [N1]),  # freeze on the active primary
        (PlanScope.DNS_ZONE, [N2]),  # promotion
        (PlanScope.DNS_ZONE, [N1]),  # demotion
        (PlanScope.DNS_ZONE, [N3]),  # the other copy repointed
        (PlanScope.D2_CONFIG, [N2]),
        (PlanScope.DNS_FAILOVER, [N1]),
    ]
    [freeze] = parts[0].changes
    assert freeze.target == "op:freeze/_default/example.lan." and "rndc freeze example.lan\n" == parts[0].diff
    promote, _repoint, d2 = rec.peers.built
    assert promote[2]["change"]["after"]["promote"] == {
        "from": N1,
        "epoch": 2,
        "sync": {"address": "192.0.2.1", "port": 53},
    }
    [[demote]] = local.built
    assert demote.after["kind"] == "secondary" and demote.after["primaries"] == ["192.0.2.2 key ddi-read"]
    assert demote.after["demote"] == {"to": N2, "epoch": 2}
    servers = d2[2]["config"]["forward-ddns"]["ddns-domains"][0]["dns-servers"]
    assert [s["ip-address"] for s in servers] == ["192.0.2.2", "192.0.2.1", "192.0.2.3"]
    [roles] = parts[-1].changes
    assert roles.after["primary"] == N2 and roles.after["epoch"] == 2


def test_switchover_refusals(monkeypatch):
    svc, _rec = service(three_nodes(), answers=False, monkeypatch=monkeypatch)
    svc.dns.local = Local()
    with pytest.raises(Conflict, match="failover plan"):
        svc.switchover_plan({"to_node_id": N2}, "alice")
    svc, _rec = service(three_nodes(), answers=True, monkeypatch=monkeypatch)
    with pytest.raises(ValidationError, match="already the active primary"):
        svc.switchover_plan({"to_node_id": N1}, "alice")
    svc, _rec = service(three_nodes(role=None), answers=True, monkeypatch=monkeypatch)
    with pytest.raises(Conflict, match="no zone is prepared"):
        svc.switchover_plan({}, "alice")


def test_resilience_lists_the_stale_primary():
    inv = returned("/z/example.lan.db")
    [st] = df.assess(inv, {})
    assert st.primary == N2 and st.stale == [N1] and st.to_dict()["stale"] == [N1]
    assert N1 not in st.copies
