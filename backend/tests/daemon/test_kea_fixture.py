# SPDX-License-Identifier: Apache-2.0
"""Smoke tests proving the Kea fixtures: config-get, status-get, leases, hooks, DHCPv6, D2 statistics."""

from __future__ import annotations

import pytest

from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.connectors.kea.control_socket import KeaCommandError, KeaControlSocket
from pelagos.connectors.kea.d2 import reduce_d2_stats
from pelagos.domain import Family

pytestmark = pytest.mark.daemon


def _ctx(daemon, tmp_root) -> ConnectorContext:
    return ConnectorContext(
        node_id="n1",
        engine_config={
            "socket_dir": str(daemon.root),
            "dhcp4_socket": daemon.socket_path.name,
            "d2_socket": "d2.sock",
        },
        backup_root=tmp_root / "backups",
        get_secret=lambda name: None,
        settings={},
    )


def test_config_get_and_status(kea_dhcp4):
    cfg = kea_dhcp4.ok("config-get")["Dhcp4"]
    assert cfg["subnet4"][0]["subnet"] == "192.0.2.0/24"
    assert cfg["subnet4"][0]["user-context"]["pelagos"]["notes"] == "fixture subnet"
    status = kea_dhcp4.ok("status-get")
    assert status["pid"] > 0 and "dhcp-state" in status
    commands = kea_dhcp4.ok("list-commands")
    for cmd in (
        "lease4-add",
        "lease4-get-all",
        "reservation-add",
        "subnet4-add",
        "stat-lease4-get",
        "config-hash-get",
    ):
        assert cmd in commands, cmd


def test_lease_add_and_get_all(kea_dhcp4):
    kea_dhcp4.ok(
        "lease4-add",
        {"ip-address": "192.0.2.150", "hw-address": "aa:bb:cc:dd:ee:02", "subnet-id": 1, "hostname": "pc2"},
    )
    leases = kea_dhcp4.ok("lease4-get-all", {"subnets": [1]})["leases"]
    assert [lease["ip-address"] for lease in leases] == ["192.0.2.150"]
    assert leases[0]["hw-address"] == "aa:bb:cc:dd:ee:02" and leases[0]["hostname"] == "pc2"
    stats = kea_dhcp4.ok("stat-lease4-get")["result-set"]
    assert "assigned-addresses" in stats["columns"]
    assert kea_dhcp4.ok("statistic-get-all")["subnet[1].assigned-addresses"][0][0] == 1
    assert kea_dhcp4.ok("reservation-get-all", {"subnet-id": 1})["hosts"][0]["hostname"] == "printer"


def test_backend_capabilities_and_passthrough(kea_dhcp4, tmp_root):
    backend = KeaBackend(_ctx(kea_dhcp4, tmp_root), Family.V4)
    caps = backend.capabilities()
    assert caps.running and caps.version and caps.version.startswith("3.")
    assert caps.lease_cmds and caps.host_cmds and caps.subnet_cmds and caps.stat_cmds
    assert not caps.degraded and caps.lease_backend == "memfile"
    assert len(backend.config_hash()) == 64
    assert backend.option_defs() == []
    with pytest.raises(PermissionError):
        backend.command("config-write")
    with pytest.raises(KeaCommandError):
        KeaControlSocket(kea_dhcp4.socket_path).call("no-such-command")


def test_dhcp6(kea_dhcp6):
    cfg = kea_dhcp6.ok("config-get")["Dhcp6"]
    assert cfg["subnet6"][0]["pd-pools"][0]["delegated-len"] == 64
    kea_dhcp6.ok(
        "lease6-add", {"ip-address": "2001:db8::1000", "duid": "00:01:00:01:aa:bb", "iaid": 1, "subnet-id": 1}
    )
    leases = kea_dhcp6.ok("lease6-get-all", {"subnets": [1]})["leases"]
    assert leases[0]["ip-address"] == "2001:db8::1000"


def test_d2_statistics(kea_d2):
    stats = reduce_d2_stats("n1", kea_d2.ok("statistic-get-all"))
    assert stats.per_key["kea-ddns."]["update-sent"] == 0
    assert "ncr-received" in stats.totals
    cfg = kea_d2.ok("config-get")["DhcpDdns"]
    assert cfg["forward-ddns"]["ddns-domains"][0]["name"] == "example.lan."
    assert "secret" not in cfg["tsig-keys"][0] or cfg["tsig-keys"][0].get("secret") in (None, "")
