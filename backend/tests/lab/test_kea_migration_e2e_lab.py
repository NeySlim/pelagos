# SPDX-License-Identifier: Apache-2.0
"""The whole Kea 2.6.3 to ISC 3.2 migration of a production-like pair, end to end (batch K7).

lab-k1a (primary) and lab-k1b (standby) rolled back to snapshot `k1-ha26` (Debian 13, Kea 2.6.3
from Debian in hot-standby over TLS with `require-client-certs`, D2 with a clear `secret`,
kea-ctrl-agent installed), the deb of this checkout installed on both, k1b enrolled, both imported.
lab-client renews from the pair all along while a probe asks for its address every second and
tcpdump records every DHCP packet (the K5 scenarios of test_kea_migration_window_lab, run in order
from a clean pair). On top of them: the analysis keeps the HA TLS and converts D2's secret; no
address is ever acknowledged to two clients and both nodes' leases agree; after the migration the
HA listener of each node still refuses a peer without a cluster certificate; the return gives back
the 2.6 pair exactly. `PELAGOS_LAB_ROLLED_BACK=1` skips the rollback (VMs restored by the caller).
"""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict

import pytest

from tests.lab import test_kea_migration_window_lab as k5
from tests.lab.labkit import rollback, ssh
from tests.lab.test_kea_migration_api_lab import K1A, K1B, api

pytestmark = pytest.mark.lab

PRIMARY, STANDBY = K1A, K1B
NODES = (PRIMARY, STANDBY)
TLS_KEYS = ("trust-anchor", "cert-file", "key-file", "require-client-certs")


def ha_relation(host: str) -> dict:
    conf = json.loads(ssh(host, "sudo cat /etc/kea/kea-dhcp4.conf")[1])
    [ha] = [h for h in conf["Dhcp4"]["hooks-libraries"] if h["library"].endswith("libdhcp_ha.so")]
    return ha["parameters"]["high-availability"][0]


def acks(capture: str) -> dict[str, set[str]]:
    """Every DHCPACK of a capture: acknowledged address to the hardware addresses it went to."""
    out: dict[str, set[str]] = defaultdict(set)
    dump = ssh(k5.CLIENT, f"sudo tcpdump -r /tmp/k5-{capture}.pcap -v -n 2>/dev/null", timeout=120)[1]
    for packet in re.split(r"\n(?=\S)", dump):
        if not re.search(r"DHCP-Message \(53\).*: ACK", packet):
            continue
        ip = re.search(r"Your-IP (\S+)", packet)
        mac = re.search(r"Client-Ethernet-Address (\S+)", packet)
        if ip and mac and not ip.group(1).startswith("0."):
            out[ip.group(1)].add(mac.group(1).lower())
    return out


def no_duplicate(capture: str) -> int:
    """No address acknowledged to two clients, and both nodes hold the same owner per address."""
    seen = acks(capture)
    assert seen, f"no DHCPACK in the {capture} capture"
    assert not {ip: m for ip, m in seen.items() if len(m) > 1}, seen
    tables = {}
    for host, _ in NODES:
        leases = k5.kea(host, "lease4-get-all").get("arguments", {}).get("leases", [])
        owner: dict[str, str] = {}
        for lease in leases:
            if lease.get("state", 0) != 0:
                continue
            assert lease["ip-address"] not in owner, (host, lease)
            owner[lease["ip-address"]] = lease["hw-address"].lower()
        by_mac = defaultdict(list)
        for ip, mac in owner.items():
            by_mac[mac].append(ip)
        assert not {m: ips for m, ips in by_mac.items() if len(ips) > 1}, (host, by_mac)
        tables[host] = owner
    a, b = (tables[h] for h, _ in NODES)
    assert not {ip: (a[ip], b[ip]) for ip in a.keys() & b.keys() if a[ip] != b[ip]}, (a, b)
    for ip, macs in seen.items():
        for owner in tables.values():
            assert owner.get(ip, next(iter(macs))) in macs, (ip, macs, owner.get(ip))
    return sum(len(m) for m in seen.values())


def tls_listener(host: str, peer: str) -> None:
    """The peer's HA listener answers a cluster certificate and refuses a client without one."""
    base = f"openssl s_client -connect {peer}:8001 -CAfile /etc/kea/tls/ca.crt -verify_return_error"
    ok = ssh(
        host,
        f"echo | sudo timeout 10 {base} -cert /etc/kea/tls/node.crt -key /etc/kea/tls/node.key"
        " -ign_eof 2>&1 | grep -E 'Verify return code|^Cipher'",
        check=False,
    )[1]
    assert "Verify return code: 0" in ok, ok
    # TLS 1.3 refuses the missing client certificate after the handshake: send a request to see it.
    refused = ssh(
        host,
        f"printf 'GET / HTTP/1.0\\r\\n\\r\\n' | sudo timeout 10 {base} -quiet 2>&1; echo exit=$?",
        check=False,
    )[1]
    assert re.search(r"certificate required|alert|handshake failure|exit=1", refused), refused
    assert "HTTP/1." not in refused, refused


class TestKeaMigrationEndToEnd:
    def test_00_clean_pair_installed_and_client(self):
        if os.environ.get("PELAGOS_LAB_ROLLED_BACK") != "1":
            rollback("lab-k1a", "lab-k1b")
        for host, _ in NODES:
            assert "kea-dhcp4-server\t2.6.3" in ssh(host, "dpkg-query -W kea-dhcp4-server")[1]
            assert all(k in ha_relation(host) for k in TLS_KEYS), host
        k5.TestKeaMigrationWindow().test_00_pair_and_client()
        k5.STATE["reference"] = {h: ssh(h, k5.KEA_STATE)[1] for h, _ in NODES}

    def test_01_analysis_keeps_tls_and_converts_d2(self):
        report = api(PRIMARY[1]).post(
            "/install/kea-migration/analyze", {"series": "3.2", "source": "isc"}, timeout=1200
        )
        assert not report["blocking"], [f for f in report["findings"] if f["severity"] == "blocking"]
        assert sorted(report["roles"].values()) == ["primary", "standby"], report["roles"]
        for node_id in report["node_ids"]:
            removed = [
                line
                for line in report["diffs"][node_id]["kea4"].splitlines()
                if line.startswith("-") and any(k in line for k in TLS_KEYS)
            ]
            assert not removed, removed
            assert report["validation"][node_id]["kea4"]["ok"], report["validation"][node_id]
            assert report["validation"][node_id]["d2"]["ok"], report["validation"][node_id]
        codes = {f["code"] for f in report["findings"]}
        assert {"d2_secret_file", "restrict_commands"} <= codes, codes
        print(f"estimated outage: {report['outage_estimate_seconds']} s")

    def test_02_forced_return_in_time_2(self):
        k5.TestKeaMigrationWindow().test_01_outage_over_the_limit_returns_by_itself()
        print(f"acks seen during the forced return: {no_duplicate('auto')}")
        assert {h: ssh(h, k5.KEA_STATE)[1] for h, _ in NODES} == k5.STATE["reference"]

    def test_03_migration_to_isc_3_2(self):
        k5.TestKeaMigrationWindow().test_02_migration_with_a_short_outage()
        print(f"acks seen during the migration: {no_duplicate('migrate')}")
        for (host, _), (_, peer) in ((PRIMARY, STANDBY), (STANDBY, PRIMARY)):
            rel = ha_relation(host)
            assert rel["require-client-certs"] is True and all(k in rel for k in TLS_KEYS), rel
            assert all(p["url"].startswith("https://") for p in rel["peers"]), rel["peers"]
            tls_listener(host, peer)
            d2 = json.loads(ssh(host, "sudo cat /etc/kea/kea-dhcp-ddns.conf")[1])["DhcpDdns"]
            assert all("secret-file" in k and "secret" not in k for k in d2["tsig-keys"]), d2["tsig-keys"]
            assert "control-sockets" in d2 and "control-socket" not in d2, sorted(d2)
            units = ssh(host, "systemctl is-active isc-kea-dhcp4-server isc-kea-dhcp-ddns-server")[1]
            assert units.split() == ["active", "active"], (host, units)
            assert not ssh(host, "systemctl is-active kea-ctrl-agent", check=False)[1].strip() == "active"

    def test_04_return_of_the_pair_to_2_6(self):
        k5.TestKeaMigrationWindow().test_03_return_of_the_migrated_pair()
        print(f"acks seen during the return: {no_duplicate('return')}")
        assert {h: ssh(h, k5.KEA_STATE)[1] for h, _ in NODES} == k5.STATE["reference"]
        for host, _ in NODES:
            rel = ha_relation(host)
            assert all(k in rel for k in TLS_KEYS) and "restrict-commands" not in rel, rel

    def test_99_client_back_to_the_reference_pair(self):
        k5.TestKeaMigrationWindow().test_99_client_back_to_the_reference_pair()
