# SPDX-License-Identifier: Apache-2.0
"""HA relationships of more than two servers: roles per mode (Kea ARM 2.6 and 3.x), the hook entry
written per server, status-get of a backup, relationships seen across 3 and 4 nodes."""

from __future__ import annotations

import pytest

from pelagos.connectors.kea import ha
from pelagos.domain import Family, HAMode, HAPartner, HAPeer, HAState

pytestmark = pytest.mark.unit

HOOKS = "/usr/lib/x86_64-linux-gnu/kea/hooks"


def servers(*roles: str) -> list[dict]:
    return [
        {"name": f"s{i + 1}", "url": f"http://192.0.2.{i + 1}:8001/", "role": r} for i, r in enumerate(roles)
    ]


@pytest.mark.parametrize(
    ("mode", "roles"),
    [
        ("hot-standby", ("primary", "standby")),
        ("hot-standby", ("primary", "standby", "backup", "backup", "backup")),
        ("load-balancing", ("primary", "secondary")),
        ("load-balancing", ("secondary", "primary", "backup")),
        ("passive-backup", ("primary", "backup")),
        ("passive-backup", ("primary", "backup", "backup")),
    ],
)
def test_accepted_relationships(mode, roles):
    assert ha.validate_setup({"mode": mode, "servers": servers(*roles)}) == []


@pytest.mark.parametrize(
    ("mode", "roles", "problem"),
    [
        ("hot-standby", ("primary", "primary"), "needs 1 standby"),
        ("hot-standby", ("primary", "secondary"), "takes primary, standby, backup"),
        ("load-balancing", ("primary", "standby"), "takes primary, secondary, backup"),
        ("load-balancing", ("primary", "secondary", "secondary"), "needs 1 secondary"),
        ("passive-backup", ("primary", "standby"), "takes primary, backup"),
        ("passive-backup", ("primary",), "at least two"),
        ("hot-standby", ("backup", "backup"), "needs 1 primary"),
    ],
)
def test_refused_relationships(mode, roles, problem):
    problems = ha.validate_setup({"mode": mode, "servers": servers(*roles)})
    assert any(problem in msg for _field, msg in problems), problems


def test_names_urls_and_tunables_are_checked():
    body = {"mode": "hot-standby", "servers": servers("primary", "standby", "backup")}
    body["servers"][1]["name"] = "s1"
    body["servers"][2]["url"] = "ftp://192.0.2.3/"
    body["heartbeat_delay"] = -1
    body["wait_backup_ack"] = "yes"
    fields = {f for f, _ in ha.validate_setup(body)}
    assert fields == {"servers[1].name", "servers[2].url", "heartbeat_delay", "wait_backup_ack"}
    assert ha.validate_setup({"mode": "multi", "servers": []}) == [
        ("mode", "hot-standby, load-balancing or passive-backup")
    ]


def test_hook_entry_per_server_and_hooks_list():
    spec = {
        "mode": "hot-standby",
        "servers": [*servers("primary", "standby", "backup")],
        "heartbeat_delay": 10000,
        "wait_backup_ack": False,
    }
    spec["servers"][2]["auto_failover"] = False
    entry = ha.relationship_entry(spec, "s3")
    assert entry["this-server-name"] == "s3" and entry["heartbeat-delay"] == 10000
    assert entry["wait-backup-ack"] is False and "max-ack-delay" not in entry
    assert [p["role"] for p in entry["peers"]] == ["primary", "standby", "backup"]
    assert entry["peers"][2]["auto-failover"] is False and "auto-failover" not in entry["peers"][0]
    hooks = [{"library": f"{HOOKS}/libdhcp_host_cmds.so"}]
    out = ha.hooks_with_ha(hooks, entry, ha.hooks_dir_of(hooks))
    assert [h["library"].rsplit("/", 1)[1] for h in out] == [
        "libdhcp_host_cmds.so",
        "libdhcp_lease_cmds.so",
        "libdhcp_ha.so",
    ]
    assert out[-1]["parameters"]["high-availability"] == [entry]
    # Replacing keeps the library path in place and the other hooks; removing drops only the ha hook.
    again = ha.hooks_with_ha(out, ha.relationship_entry(spec, "s2"), None)
    assert len(again) == 3 and again[-1]["parameters"]["high-availability"][0]["this-server-name"] == "s2"
    assert ha.hooks_with_ha(again, None, None) == out[:2]
    with pytest.raises(ValueError, match="hooks directory"):
        ha.hooks_with_ha([], entry, ha.hooks_dir_of([]))
    cfg = {"hooks-libraries": out}
    assert [(p.name, p.role, p.auto_failover) for p in ha.ha_peers_from_config(cfg)] == [
        ("s1", "primary", None),
        ("s2", "standby", None),
        ("s3", "backup", False),
    ]


def test_status_get_of_a_backup_has_no_partner():
    status = {
        "high-availability": [
            {
                "ha-mode": "hot-standby",
                "ha-servers": {
                    "local": {"role": "backup", "scopes": [], "server-name": "s3", "state": "backup"}
                },
            }
        ]
    }
    st = ha.ha_state_from_status("n3", Family.V4, status)
    assert st.role == "backup" and st.state == "backup" and st.partner is None
    assert ha.partner_name(st) is None
    status["high-availability"][0]["ha-servers"]["remote"] = {
        "role": "standby",
        "server-name": "s2",
        "in-touch": True,
    }
    status["high-availability"][0]["ha-servers"]["local"].update(role="primary", **{"server-name": "s1"})
    st = ha.ha_state_from_status("n1", Family.V4, status)
    assert st.partner is not None and st.partner.server_name == "s2" and ha.partner_name(st) == "s2"


def state(
    node: str, name: str, role: str, st: str, partner: str | None = None, touch: bool = True
) -> HAState:
    peers = [
        HAPeer("s1", "primary", "http://192.0.2.1:8001/"),
        HAPeer("s2", "standby", "http://192.0.2.2:8001/"),
        HAPeer("s3", "backup", "http://192.0.2.3:8001/"),
        HAPeer("s4", "backup", "http://192.0.2.4:8001/"),
    ]
    p = HAPartner(role=None, server_name=partner, state="hot-standby", in_touch=touch) if partner else None
    return HAState(
        node_id=node, family=Family.V4, server_name=name, mode=HAMode.HOT_STANDBY, role=role, state=st,
        partner=p, peers=peers,
    )  # fmt: skip


def test_relationship_of_four_servers_one_without_a_node():
    states = [
        state("n1", "s1", "primary", "partner-down", "s2", touch=False),
        state("n3", "s3", "backup", "backup"),
        state("n4", "s4", "backup", "backup"),
    ]
    [rel] = ha.relationships(states, {"n1": "ns1", "n3": "ns3", "n4": "ns4"})
    assert rel["active"] == ["s1", "s2"] and rel["backups"] == ["s3", "s4"]
    by = {s["name"]: s for s in rel["servers"]}
    assert by["s1"]["node_name"] == "ns1" and by["s1"]["partner"] == "s2"
    # s2 runs on no node of this cluster: its state is what its partner last saw.
    assert by["s2"]["managed"] is False and by["s2"]["node_id"] is None
    assert by["s2"]["state"] == "hot-standby" and by["s2"]["in_touch"] is False
    assert by["s4"]["state"] == "backup" and by["s4"]["partner"] is None


def test_two_relationships_stay_apart():
    a = state("n1", "s1", "primary", "hot-standby", "s2")
    b = HAState(node_id="n5", family=Family.V4, server_name="x1", role="primary", state="passive-backup",
                peers=[HAPeer("x1", "primary"), HAPeer("x2", "backup")])  # fmt: skip
    rels = ha.relationships([a, b, HAState(node_id="n9", family=Family.V4, enabled=False)], {})
    assert sorted(len(r["servers"]) for r in rels) == [2, 4]


def test_setup_keeps_what_it_does_not_manage():
    old = {
        "this-server-name": "s1",
        "mode": "hot-standby",
        "multi-threading": {"enable-multi-threading": True, "http-dedicated-listener": True},
        "trust-anchor": "/etc/kea/ca.pem",
        "peers": [
            {
                "name": "s1",
                "url": "http://192.0.2.1:8001/",
                "role": "primary",
                "cert-file": "/etc/kea/s1.pem",
            },
            {"name": "s2", "url": "http://192.0.2.2:8001/", "role": "standby"},
        ],
    }
    hooks = [{"library": f"{HOOKS}/libdhcp_ha.so", "parameters": {"high-availability": [old], "x": 1}}]
    spec = {"mode": "load-balancing", "servers": servers("primary", "secondary", "backup")}
    out = ha.hooks_with_ha(hooks, ha.relationship_entry(spec, "s1"), HOOKS)
    params = out[-1]["parameters"]
    entry = params["high-availability"][0]
    assert params["x"] == 1 and entry["mode"] == "load-balancing"
    assert entry["multi-threading"]["http-dedicated-listener"] is True
    assert entry["trust-anchor"] == "/etc/kea/ca.pem"
    assert entry["peers"][0]["cert-file"] == "/etc/kea/s1.pem"
    assert [p["role"] for p in entry["peers"]] == ["primary", "secondary", "backup"]


def test_hub_plan_warns_about_subnets_no_relationship_names():
    tagged = {"user-context": {"ha-server-name": "hub-a"}}
    body = {
        "subnet4": [{"id": 1, "subnet": "192.0.2.0/26", **tagged}, {"id": 2, "subnet": "192.0.2.64/26"}],
        "shared-networks": [
            {"name": "a", **tagged, "subnet4": [{"id": 3, "subnet": "192.0.2.128/26"}]},
            {
                "name": "b",
                "subnet4": [
                    {"id": 4, "subnet": "192.0.2.192/26", **tagged},
                    {"id": 5, "subnet": "198.51.100.0/24"},
                ],
            },
        ],
    }
    assert ha.untagged_subnets(body) == ["192.0.2.64/26", "198.51.100.0/24"]
    warning = ha.hub_subnets_warning(body, ["hub-a", "hub-b"])
    assert warning and "2 subnet(s)" in warning and "hub-a, hub-b" in warning
    body["subnet4"].pop()
    body["shared-networks"][1]["subnet4"].pop()
    assert ha.hub_subnets_warning(body, ["hub-a", "hub-b"]) is None


def test_communication_interrupted_is_read_and_counts_as_lost():
    """Kea 2.6 status-get (ARM 2.6.3, "The status-get Command"): in-touch stays true once the
    partner answered; communication-interrupted carries the outage."""
    remote = {
        "role": "primary",
        "server-name": "s1",
        "in-touch": True,
        "last-state": "hot-standby",
        "age": 75,
        "communication-interrupted": True,
        "connecting-clients": 2,
        "unacked-clients": 1,
        "unacked-clients-left": 9,
        "analyzed-packets": 8,
    }
    status = {
        "high-availability": [
            {
                "ha-mode": "hot-standby",
                "ha-servers": {
                    "local": {"role": "standby", "scopes": [], "server-name": "s2", "state": "hot-standby"},
                    "remote": remote,
                },
            }
        ]
    }
    st = ha.ha_state_from_status("n2", Family.V4, status)
    assert st.partner is not None and st.partner.communication_interrupted is True
    assert st.partner.unacked_clients_left == 9 and st.partner.age == 75
    assert ha.partner_lost(st.partner) and not ha.ha_serving(st)
    remote["communication-interrupted"] = False
    st = ha.ha_state_from_status("n2", Family.V4, status)
    assert not ha.partner_lost(st.partner) and ha.ha_serving(st)
    del remote["communication-interrupted"]
    assert ha.ha_state_from_status("n2", Family.V4, status).partner.communication_interrupted is None
