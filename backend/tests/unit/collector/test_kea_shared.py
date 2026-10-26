# SPDX-License-Identifier: Apache-2.0
"""What Kea HA servers must share: a pair and a backup on different Kea versions hash alike, real
divergence (pools, reservations, options, classes, peers) is caught, hub and spoke compares each
relationship on its own."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from pelagos.collector.kea_shared import divergent, shared_hashes
from pelagos.collector.pollers.peers import CONFIG_DIVERGENCE_GRACE_SECONDS, PeersPoller
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind, NodeModules, Peer

pytestmark = pytest.mark.unit

PEERS = [
    {"name": "ns1", "url": "http://192.0.2.11:8001/", "role": "primary"},
    {"name": "ns2", "url": "http://192.0.2.12:8001/", "role": "standby"},
    {"name": "ns3", "url": "http://192.0.2.13:8001/", "role": "backup"},
]


def option(name: str, code: int, data: str, v3: bool) -> dict[str, Any]:
    opt: dict[str, Any] = {"name": name, "code": code, "data": data, "space": "dhcp4"}
    if v3:
        opt.update({"always-send": False, "csv-format": True, "never-send": False})
    return opt


def server(name: str, v3: bool = False, peers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """A Dhcp4 configuration as config-get answers it: a 2.6 pair member, or a 3.0 backup that adds
    defaults, its own paths, no interface and other per-server keys."""
    hooks = "/usr/lib64/kea/hooks" if v3 else "/usr/lib/x86_64-linux-gnu/kea/hooks"
    subnet: dict[str, Any] = {
        "id": 1,
        "subnet": "192.0.2.0/24",
        "pools": [{"pool": "192.0.2.100-192.0.2.199" if v3 else "192.0.2.100 - 192.0.2.199"}],
        "option-data": [option("domain-name-servers", 6, "192.0.2.11, 192.0.2.12", v3)],
        "reservations": [
            {
                "hw-address": "AA:BB:CC:DD:EE:01" if v3 else "aa:bb:cc:dd:ee:01",
                "ip-address": "192.0.2.50",
                "hostname": "printer",
                **(
                    {"boot-file-name": "", "next-server": "0.0.0.0", "client-classes": [], "option-data": []}  # noqa: S104
                    if v3
                    else {}
                ),
            }
        ],
        "valid-lifetime": 3600,
    }
    if v3:
        subnet.update({"cache-threshold": 0.25, "allocator": "iterative", "4o6-interface": ""})
    else:
        subnet["interface"] = "eth0"
    body: dict[str, Any] = {
        "interfaces-config": {"interfaces": [] if v3 else ["eth0"]},
        "subnet4": [subnet],
        "client-classes": [{"name": "voip", "test": "substring(option[60].hex,0,4) == 'voip'"}],
        "ddns-qualifying-suffix": "" if v3 else "example.lan.",
        "lease-database": {"type": "memfile", "name": f"/var/lib/kea/{name}.csv"},
        "hooks-libraries": [
            {"library": f"{hooks}/libdhcp_lease_cmds.so"},
            {
                "library": f"{hooks}/libdhcp_ha.so",
                "parameters": {
                    "high-availability": [
                        {
                            "this-server-name": name,
                            "mode": "hot-standby",
                            "restrict-commands": v3,
                            "heartbeat-delay": 5000,
                            "peers": [
                                {**p, **({"auto-failover": True} if v3 else {})}
                                for p in copy.deepcopy(peers or PEERS)
                            ],
                        }
                    ]
                },
            },
        ],
    }
    if v3:
        body["control-sockets"] = [{"socket-type": "unix", "socket-name": "kea4-ctrl-socket"}]
    else:
        body["control-socket"] = {"socket-type": "unix", "socket-name": "kea4-ctrl-socket"}
    return {"Dhcp4": body}


def payloads(**configs: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {node: shared_hashes(cfg) for node, cfg in configs.items()}


def test_pair_and_backup_on_two_versions_hash_alike():
    out = payloads(ns1=server("ns1"), ns2=server("ns2"), ns3=server("ns3", v3=True))
    assert divergent(out) == ({}, [])
    rel = out["ns3"]["relationships"][0]
    assert rel["this"] == "ns3" and rel["servers"] == ["ns1", "ns2", "ns3"]
    assert rel["hash"] == out["ns1"]["relationships"][0]["hash"]


@pytest.mark.parametrize(
    "edit",
    [
        lambda b: b["subnet4"][0]["pools"].__setitem__(0, {"pool": "192.0.2.100-192.0.2.150"}),
        lambda b: b["subnet4"][0]["reservations"][0].__setitem__("ip-address", "192.0.2.51"),
        lambda b: b["subnet4"][0]["option-data"][0].__setitem__("data", "192.0.2.11"),
        lambda b: b["client-classes"].append({"name": "printers", "test": "true"}),
        lambda b: b["subnet4"].append({"id": 2, "subnet": "198.51.100.0/24"}),
        lambda b: b["subnet4"][0].__setitem__("valid-lifetime", 7200),
    ],
    ids=["pool", "reservation", "option", "class", "subnet", "lifetime"],
)
def test_real_divergence_on_the_backup_is_caught(edit):
    backup = server("ns3", v3=True)
    edit(backup["Dhcp4"])
    hashes, groups = divergent(payloads(ns1=server("ns1"), ns2=server("ns2"), ns3=backup))
    assert set(hashes) == {"ns1", "ns2", "ns3"}
    assert hashes["ns1"] == hashes["ns2"] != hashes["ns3"]
    assert groups[0]["servers"] == ["ns1", "ns2", "ns3"]


BEHAVIOUR_EDITS = {
    "valid-lifetime": 7200,
    "renew-timer": 1000,
    "rebind-timer": 2000,
    "min-valid-lifetime": 600,
    "max-valid-lifetime": 86400,
    "match-client-id": False,
    "authoritative": True,
    "calculate-tee-times": True,
    "t1-percent": 0.4,
    "t2-percent": 0.7,
    "reservations-global": True,
    "reservations-in-subnet": False,
    "reservations-out-of-pool": True,
    "offer-lifetime": 60,
    "allocator": "random",
}


def in_network(config: dict[str, Any]) -> dict[str, Any]:
    body = config["Dhcp4"]
    body["shared-networks"] = [{"name": "office", "subnet4": body.pop("subnet4")}]
    return config


@pytest.mark.parametrize("level", ["global", "subnet", "network"])
@pytest.mark.parametrize("key", sorted(BEHAVIOUR_EDITS))
def test_lease_and_reservation_behaviour_is_compared(level, key):
    pair = [server("ns1"), server("ns2"), server("ns3", v3=True)]
    if level == "network":
        pair = [in_network(c) for c in pair]
    body = pair[2]["Dhcp4"]
    targets = {"global": body, "subnet": body.get("subnet4", [{}])[0]}
    target = body["shared-networks"][0] if level == "network" else targets[level]
    target[key] = BEHAVIOUR_EDITS[key]
    hashes, _ = divergent(payloads(ns1=pair[0], ns2=pair[1], ns3=pair[2]))
    assert hashes and hashes["ns1"] == hashes["ns2"] != hashes["ns3"]


def test_what_kea_3_derives_is_not_divergence():
    v2, v3 = server("ns1"), server("ns3", v3=True)
    for cfg in (v2, v3):
        cfg["Dhcp4"]["allocator"] = "random"
    # Kea 3 writes the inherited allocator and the min and max lifetimes into the subnet.
    v3["Dhcp4"]["subnet4"][0].update(
        {"allocator": "random", "min-valid-lifetime": 3600, "max-valid-lifetime": 3600}
    )
    assert divergent(payloads(ns1=v2, ns3=v3)) == ({}, [])
    v3["Dhcp4"]["subnet4"][0]["allocator"] = "iterative"
    assert divergent(payloads(ns1=v2, ns3=v3))[0]


def test_a_peers_list_that_differs_is_caught():
    without_backup = [p for p in PEERS if p["name"] != "ns3"]
    hashes, _ = divergent(
        payloads(ns1=server("ns1", peers=without_backup), ns2=server("ns2"), ns3=server("ns3", v3=True))
    )
    assert hashes["ns2"] == hashes["ns3"] != hashes["ns1"]
    moved = copy.deepcopy(PEERS)
    moved[2]["url"] = "http://192.0.2.14:8001/"
    hashes, _ = divergent(
        payloads(ns1=server("ns1"), ns2=server("ns2"), ns3=server("ns3", v3=True, peers=moved))
    )
    assert set(hashes) == {"ns1", "ns2", "ns3"}


def hub_and_spokes() -> dict[str, dict[str, Any]]:
    """hub runs relationship A with spoke1 and B with spoke2; each spoke has its own subnet."""
    rel_a = [
        {"name": "hub-a", "url": "http://192.0.2.10:8001/", "role": "standby"},
        {"name": "spoke1", "url": "http://192.0.2.21:8001/", "role": "primary"},
    ]
    rel_b = [
        {"name": "hub-b", "url": "http://192.0.2.10:8002/", "role": "standby"},
        {"name": "spoke2", "url": "http://192.0.2.22:8001/", "role": "primary"},
    ]
    s1 = {"id": 1, "subnet": "192.0.2.0/25", "pools": [{"pool": "192.0.2.10 - 192.0.2.99"}]}
    s2 = {"id": 2, "subnet": "192.0.2.128/25", "pools": [{"pool": "192.0.2.130 - 192.0.2.199"}]}

    def cfg(entries: list[tuple[str, list[dict[str, Any]]]], subnets: list[dict[str, Any]]) -> dict[str, Any]:
        ha = [{"this-server-name": me, "mode": "hot-standby", "peers": peers} for me, peers in entries]
        return {
            "Dhcp4": {
                "subnet4": copy.deepcopy(subnets),
                "hooks-libraries": [{"library": "libdhcp_ha.so", "parameters": {"high-availability": ha}}],
            }
        }

    return {
        "hub": cfg(
            [("hub-a", rel_a), ("hub-b", rel_b)],
            [
                {**s1, "user-context": {"ha-server-name": "hub-a"}},
                {**s2, "user-context": {"ha-server-name": "hub-b"}},
            ],
        ),
        "spoke1": cfg([("spoke1", rel_a)], [s1]),
        "spoke2": cfg([("spoke2", rel_b)], [s2]),
    }


def test_hub_and_spoke_compares_each_relationship():
    configs = hub_and_spokes()
    out = payloads(**configs)
    assert [r["this"] for r in out["hub"]["relationships"]] == ["hub-a", "hub-b"]
    assert divergent(out) == ({}, [])
    configs["spoke2"]["Dhcp4"]["subnet4"][0]["pools"][0]["pool"] = "192.0.2.130 - 192.0.2.140"
    hashes, groups = divergent(payloads(**configs))
    assert set(hashes) == {"hub", "spoke2"}
    assert [{k: g[k] for k in ("servers", "hashes")} for g in groups] == [
        {"servers": ["hub-b", "spoke2"], "hashes": hashes}
    ]


def test_servers_without_ha_are_compared_with_each_other():
    a = {
        "Dhcp4": {
            "subnet4": [{"id": 1, "subnet": "192.0.2.0/24"}],
            "interfaces-config": {"interfaces": ["eth0"]},
        }
    }
    b = copy.deepcopy(a)
    b["Dhcp4"]["interfaces-config"] = {"interfaces": ["ens18"]}
    assert divergent(payloads(a=a, b=b)) == ({}, [])
    b["Dhcp4"]["subnet4"][0]["subnet"] = "198.51.100.0/24"
    hashes, groups = divergent(payloads(a=a, b=b))
    assert set(hashes) == {"a", "b"} and groups[0]["servers"] == []


def test_peers_poller_alerts_only_on_real_divergence(tmp_root):
    conn = connect(tmp_root / "series.sqlite")
    store = SeriesStore(conn)
    try:
        nodes = {"n1": server("ns1"), "n2": server("ns2"), "n3": server("ns3", v3=True)}
        for node, cfg in nodes.items():
            store.write_snapshot(node, "kea4", "config_hash", 1, {"hash": node, **shared_hashes(cfg)})
        peers = [
            Peer(
                id=n,
                name=n,
                url=f"https://{n}.example.lan:8444",
                cert_fingerprint="sha256:00",
                modules=NodeModules(kea4=True),
            )
            for n in ("n2", "n3")
        ]
        clock = [2_000_000.0]
        poller = PeersPoller(None, "n1", lambda: peers, store, {}, lambda: clock[0])
        assert poller.poll().alerts == []
        nodes["n3"]["Dhcp4"]["subnet4"][0]["pools"] = [{"pool": "192.0.2.100 - 192.0.2.120"}]
        store.write_snapshot("n3", "kea4", "config_hash", 2, {"hash": "n3", **shared_hashes(nodes["n3"])})
        assert poller.poll().alerts == []  # within the grace period
        clock[0] += CONFIG_DIVERGENCE_GRACE_SECONDS
        [alert] = poller.poll().alerts
        assert alert.kind is AlertKind.CONFIG_DIVERGENCE and alert.subject == "kea4:config-hash"
        assert alert.details["relationships"][0]["servers"] == ["ns1", "ns2", "ns3"]
        # A node without relationship hashes (older version): the normalized hashes decide.
        store.write_snapshot("n3", "kea4", "config_hash", 3, {"hash": "n3", "normalized": "x"})
        store.write_snapshot("n1", "kea4", "config_hash", 3, {"hash": "n1", "normalized": "x"})
        store.write_snapshot("n2", "kea4", "config_hash", 3, {"hash": "n2", "normalized": "x"})
        assert poller.poll().alerts == []
    finally:
        conn.close()
