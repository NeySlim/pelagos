# SPDX-License-Identifier: Apache-2.0
"""File versus config-get compared by identity: Kea 2.6 returns reservations (and other lists) in an
order of its own and fills in defaults the file omits; neither is a difference."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from pelagos.core.keafile import (
    conform_root,
    kea_config_differences,
    loads,
    rebase_root,
    redact_kea_difference,
)

pytestmark = pytest.mark.unit

FILE = """
// Kea 2.6 DHCPv4 as an administrator writes it
{
"Dhcp4": {
  "interfaces-config": { "interfaces": [ "eth0" ] },
  "control-socket": { "socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket" },
  "lease-database": { "type": "memfile", "lfc-interval": 3600 },
  "valid-lifetime": 3600,
  "hooks-libraries": [
    { "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so" },
    { "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so",
      "parameters": { "high-availability": [ {
        "this-server-name": "ns1", "mode": "hot-standby",
        "peers": [ { "name": "ns1", "url": "http://192.0.2.11:8000/", "role": "primary" },
                   { "name": "ns2", "url": "http://192.0.2.12:8000/", "role": "standby" } ] } ] } }
  ],
  "option-data": [ { "name": "domain-name-servers", "data": "192.0.2.11, 192.0.2.12" } ],
  "subnet4": [
    { "id": 2, "subnet": "198.51.100.0/24", "pools": [ { "pool": "198.51.100.100 - 198.51.100.150" } ] },
    { "id": 1, "subnet": "192.0.2.0/24",
      "pools": [ { "pool": "192.0.2.100 - 192.0.2.199" }, { "pool": "192.0.2.220-192.0.2.230" } ],
      "option-data": [ { "name": "routers", "data": "192.0.2.1" } ],
      "reservations": [
        { "hw-address": "AA:BB:CC:DD:EE:01", "ip-address": "192.0.2.50", "hostname": "printer" },
        { "client-id": "01:aa:bb:cc:dd:ee:02", "ip-address": "192.0.2.51", "hostname": "scanner" },
        { "hw-address": "aa:bb:cc:dd:ee:03", "ip-address": "192.0.2.52", "hostname": "camera" } ] }
  ]
}
}
"""


def _reservation(**kw: Any) -> dict[str, Any]:
    return {
        "boot-file-name": "",
        "client-classes": [],
        "next-server": "0.0.0.0",  # noqa: S104
        "option-data": [],
        "server-hostname": "",
        **kw,
    }


def _option(name: str, code: int, data: str) -> dict[str, Any]:
    return {
        "always-send": False,
        "code": code,
        "csv-format": True,
        "data": data,
        "name": name,
        "never-send": False,
        "space": "dhcp4",
    }


def running_config() -> dict[str, Any]:
    """config-get: reservations reordered, hooks from another architecture, every default filled in."""
    ha = {
        "this-server-name": "ns1",
        "mode": "hot-standby",
        "heartbeat-delay": 10,
        "peers": [
            {"name": "ns2", "url": "http://192.0.2.12:8000/", "role": "standby", "auto-failover": True},
            {"name": "ns1", "url": "http://192.0.2.11:8000/", "role": "primary", "auto-failover": True},
        ],
    }
    return {
        "Dhcp4": {
            "allocator": "iterative",
            "interfaces-config": {"interfaces": ["eth0"], "re-detect": True},
            "control-socket": {"socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket"},
            "lease-database": {"type": "memfile", "lfc-interval": 3600, "persist": True},
            "valid-lifetime": 3600,
            "renew-timer": 900,
            "hooks-libraries": [
                {
                    "library": "/usr/lib/aarch64-linux-gnu/kea/hooks/libdhcp_ha.so",
                    "parameters": {"high-availability": [ha]},
                },
                {"library": "/usr/lib/aarch64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so"},
            ],
            "option-data": [_option("domain-name-servers", 6, "192.0.2.11, 192.0.2.12")],
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "192.0.2.0/24",
                    "4o6-interface": "",
                    "pools": [
                        {"pool": "192.0.2.220-192.0.2.230", "option-data": []},
                        {"pool": "192.0.2.100-192.0.2.199", "option-data": []},
                    ],
                    "option-data": [_option("routers", 3, "192.0.2.1")],
                    "reservations": [
                        _reservation(
                            **{
                                "hw-address": "aa:bb:cc:dd:ee:03",
                                "ip-address": "192.0.2.52",
                                "hostname": "camera",
                            }
                        ),
                        _reservation(
                            **{
                                "hw-address": "aa:bb:cc:dd:ee:01",
                                "ip-address": "192.0.2.50",
                                "hostname": "printer",
                            }
                        ),
                        _reservation(
                            **{
                                "client-id": "01:aa:bb:cc:dd:ee:02",
                                "ip-address": "192.0.2.51",
                                "hostname": "scanner",
                            }
                        ),
                    ],
                    "valid-lifetime": 3600,
                },
                {
                    "id": 2,
                    "subnet": "198.51.100.0/24",
                    "pools": [{"pool": "198.51.100.100-198.51.100.150", "option-data": []}],
                    "reservations": [],
                    "option-data": [],
                },
            ],
        }
    }


def test_reordered_lists_and_defaults_are_no_difference():
    assert kea_config_differences(loads(FILE), running_config()) == []


def test_a_reservation_removed_at_runtime_is_named():
    running = running_config()
    running["Dhcp4"]["subnet4"][0]["reservations"].pop(1)
    assert kea_config_differences(loads(FILE), running) == [
        "/subnet4[id=1]/reservations[hw-address=aa:bb:cc:dd:ee:01]: "
        "in the file (hostname=printer, ip-address=192.0.2.50), absent from the running configuration"
    ]


def test_a_changed_value_and_a_runtime_only_item_are_reported():
    running = running_config()
    running["Dhcp4"]["subnet4"][0]["reservations"][0]["ip-address"] = "192.0.2.99"
    running["Dhcp4"]["subnet4"][1]["pools"].append({"pool": "198.51.100.200-198.51.100.210"})
    assert sorted(kea_config_differences(loads(FILE), running)) == [
        "/subnet4[id=1]/reservations[hw-address=aa:bb:cc:dd:ee:03]/ip-address: "
        "'192.0.2.52' in the file, '192.0.2.99' running",
        "/subnet4[id=2]/pools[pool=198.51.100.200-198.51.100.210]: running, absent from the file",
    ]


def test_a_hook_missing_at_runtime_is_reported_by_library_name():
    running = running_config()
    running["Dhcp4"]["hooks-libraries"].pop()
    assert kea_config_differences(loads(FILE), running) == [
        "/hooks-libraries[library=libdhcp_lease_cmds.so]: in the file, absent from the running configuration"
    ]


def test_conform_keeps_the_file_order_and_closes_the_difference():
    running = running_config()
    running["Dhcp4"]["subnet4"][0]["reservations"][1]["hostname"] = "label-printer"
    running["Dhcp4"]["subnet4"][0]["reservations"].pop(0)
    out = conform_root(loads(FILE), running["Dhcp4"], "Dhcp4")
    assert kea_config_differences(out, running) == []
    subnet = next(s for s in out["Dhcp4"]["subnet4"] if s["id"] == 1)
    assert [r["hostname"] for r in subnet["reservations"]] == ["label-printer", "scanner"]


def test_rebase_follows_reservations_by_identity():
    before = running_config()
    after = copy.deepcopy(before)
    after["Dhcp4"]["subnet4"][0]["reservations"].append(
        {"hw-address": "aa:bb:cc:dd:ee:04", "ip-address": "192.0.2.53", "hostname": "tv"}
    )
    after["Dhcp4"]["subnet4"][0]["reservations"].pop(0)
    out = rebase_root(loads(FILE), before["Dhcp4"], after["Dhcp4"], "Dhcp4")
    assert kea_config_differences(out, after) == []
    subnet = next(s for s in out["Dhcp4"]["subnet4"] if s["id"] == 1)
    assert [r["hostname"] for r in subnet["reservations"]] == ["printer", "scanner", "tv"]


def test_labels_with_a_mac_do_not_break_redaction():
    line = "/subnet4[id=1]/reservations[hw-address=aa:bb]/ip-address: 'x' in the file, 'y' running"
    assert redact_kea_difference(line) == line
