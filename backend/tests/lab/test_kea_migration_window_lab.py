# SPDX-License-Identifier: Apache-2.0
"""The window, time 3 and the return of a migrated pair on a real Kea 2.6.3 HA pair (section 28,
batch K5), with lab-client renewing all along.

lab-k1a (primary) and lab-k1b (standby) from snapshot `k1-ha26`, Pelagos from this checkout (test_00
of the time 1 test installs and enrolls it). lab-client takes its offers from the pair for the run
(its allow list is put back at the end) and keeps renewing (`networkctl renew` every 3 s), while
`dhcp_probe.py` asks for one address every second (INIT-REBOOT) and tcpdump records every DHCP
packet. Checked: an outage over `kea.migration_outage_max_seconds` (30 s against a 60 s detection
delay) returns the pair to 2.6 by itself with every Kea file, package and service as before; a
migration to ISC 3.2 whose outage is measured and short, no DHCPNAK, the client keeps its address,
a lease given by the primary alone during time 1 present on both nodes after, DDNS working, the
detection delays back; then the return of the migrated pair, again with no DHCPNAK.
Restore the snapshot to run it again from scratch.
"""

from __future__ import annotations

import itertools
import json
import threading
import time
from pathlib import Path

import pytest

from tests.lab.labkit import put, scp, ssh, wait_for
from tests.lab.test_kea_migration_api_lab import K1A, K1B, api
from tests.lab.test_kea_migration_time1_lab import KEA_STATE, ha_state, pair_back, prepared, run_job

pytestmark = pytest.mark.lab

PRIMARY, STANDBY = K1A, K1B
CLIENT, IFACE = "lab-client", "ens19"
ALLOW = "/etc/systemd/network/10-netplan-lab-dhcp.network.d/allow.conf"
ALLOW_DEFAULT = "[DHCPv4]\nAllowList=10.99.0.11 10.99.0.12\n"
PROBE = Path(__file__).with_name("dhcp_probe.py")
MAC_LOOP, MAC_TIME1, MAC_AFTER = "02:00:00:00:05:01", "02:00:00:00:05:02", "02:00:00:00:05:03"
STATE: dict[str, object] = {}
KEA = (
    "sudo python3 -c 'import json,socket,sys;s=socket.socket(socket.AF_UNIX);"
    's.connect("/run/kea/kea4-ctrl-socket");s.sendall(sys.stdin.buffer.read());'
    'b=b""\nwhile True:\n c=s.recv(65536)\n if not c: break\n b+=c\nprint(b.decode())\''
)


def kea(host: str, command: str, arguments: dict | None = None) -> dict:
    body = {"command": command, **({"arguments": arguments} if arguments else {})}
    return json.loads(ssh(host, KEA, data=json.dumps(body).encode())[1])


def has_lease(host: str, ip: str) -> bool:
    return kea(host, "lease4-get", {"ip-address": ip}).get("result") == 0


def client_address() -> str:
    out = ssh(CLIENT, f"ip -4 -br addr show {IFACE}")[1].split()
    return out[2] if len(out) > 2 else ""


def probe_get(mac: str) -> str:
    return ssh(CLIENT, f"sudo python3 /tmp/dhcp_probe.py get {IFACE} {mac}", timeout=120)[1].strip()


class Watch:
    """The renewing client, the per-second probe and the capture, for one scenario."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.address = client_address()
        units = f"k5-{name}-renew k5-{name}-probe k5-{name}-dump"
        ssh(CLIENT, f"sudo systemctl stop {units} 2>/dev/null; sudo rm -f /tmp/k5-{name}.*", check=False)
        ssh(
            CLIENT,
            f"sudo systemd-run --unit k5-{name}-dump tcpdump -i {IFACE} -n -w /tmp/k5-{name}.pcap"
            " udp port 67 or udp port 68",
        )
        ssh(
            CLIENT,
            f"sudo systemd-run --unit k5-{name}-renew"
            f" sh -c 'while :; do networkctl renew {IFACE}; sleep 3; done'",
        )
        ssh(
            CLIENT,
            f"sudo systemd-run --unit k5-{name}-probe -p StandardOutput=file:/tmp/k5-{name}.log"
            f" python3 /tmp/dhcp_probe.py loop {IFACE} {MAC_LOOP} {STATE['loop_ip']} 7200",
        )
        time.sleep(5)

    def stop(self) -> dict:
        time.sleep(5)
        units = f"k5-{self.name}-renew k5-{self.name}-probe k5-{self.name}-dump"
        ssh(CLIENT, f"sudo systemctl stop {units}", check=False)
        lines = [json.loads(x) for x in ssh(CLIENT, f"cat /tmp/k5-{self.name}.log")[1].splitlines() if x]
        acks = [x["t"] for x in lines if x["result"] == "ack"]
        gaps = [b - a for a, b in itertools.pairwise(acks)]
        dump = ssh(CLIENT, f"sudo tcpdump -r /tmp/k5-{self.name}.pcap -v -n 2>/dev/null", timeout=120)[1]
        out = {
            "tries": len(lines),
            "acks": len(acks),
            "naks": sum(1 for x in lines if x["result"] == "nak"),
            "longest_gap": round(max(gaps, default=0.0), 1),
            "last": lines[-1]["result"] if lines else None,
            "pcap_naks": dump.count(": NACK"),
            "pcap_acks": dump.count(": ACK"),
            "address": client_address(),
        }
        print(f"client during {self.name}: {json.dumps(out)}")
        return out


def migration(mid: str) -> dict:
    return api(PRIMARY[1]).get(f"/install/kea-migration/{mid}")


def settings(**kea_values: int) -> None:
    api(PRIMARY[1]).call("PUT", "/admin/settings", {"kea": kea_values})


class TestKeaMigrationWindow:
    def test_00_pair_and_client(self):
        from tests.lab.test_kea_migration_time1_lab import TestKeaMigrationTime1

        TestKeaMigrationTime1().test_00_install_enroll_and_archive_key()
        scp(CLIENT, PROBE, "/tmp/dhcp_probe.py")
        put(CLIENT, ALLOW, "[DHCPv4]\nAllowList=10.99.0.85 10.99.0.86\n")
        ssh(CLIENT, f"sudo networkctl reload && sudo networkctl renew {IFACE}")
        wait_for(
            "lab-client served by the k1 pair",
            lambda: "10.99.0.8" in ssh(CLIENT, "sudo journalctl -u systemd-networkd -n 30 --no-pager")[1],
            timeout=120,
        )
        STATE["loop_ip"] = probe_get(MAC_LOOP)
        assert STATE["loop_ip"].startswith("10.99.1."), STATE

    def test_01_outage_over_the_limit_returns_by_itself(self):
        before = {h: ssh(h, KEA_STATE)[1] for h, _ in (PRIMARY, STANDBY)}
        mid = prepared()
        settings(migration_outage_max_seconds=30)
        watch = Watch("auto")
        try:
            plan = api(PRIMARY[1]).post(
                f"/install/kea-migration/{mid}/plan",
                {"phase": "migrate", "options": {"response_delay_milliseconds": 60000}},
            )
            job = run_job(plan)
        finally:
            settings(migration_outage_max_seconds=180)
        assert job["state"] == "failed" and "automatic return" in job["error"], job["error"]
        assert "within 30 s" in job["error"], job["error"]
        mig = migration(mid)
        assert mig["state"] == "rolled_back" and mig["error_step"] == "kea-mig-wait-partner-down", mig
        pair_back()
        client = watch.stop()
        assert client["naks"] == 0 and client["pcap_naks"] == 0, client
        assert client["address"] == watch.address and client["last"] == "ack", client
        for host, _ in (PRIMARY, STANDBY):
            assert ssh(host, KEA_STATE)[1] == before[host], host

    def test_02_migration_with_a_short_outage(self):
        before = {h: ssh(h, KEA_STATE)[1] for h, _ in (PRIMARY, STANDBY)}
        STATE["before"] = before
        mid = prepared()
        STATE["mid"] = mid
        watch = Watch("migrate")
        got: dict[str, str] = {}

        def during_time_1() -> None:
            # A lease only the primary gives: the standby is stopped in time 1.
            deadline = time.monotonic() + 900
            while time.monotonic() < deadline:
                mig = migration(mid)
                standby = next(n for n in mig["nodes"] if n["role"] == "standby")
                if mig["stage"] == "standby" and standby["step"] == "kea-mig-install":
                    got["ip"] = probe_get(MAC_TIME1)
                    got["stage"] = migration(mid)["stage"]
                    return
                time.sleep(1)

        thread = threading.Thread(target=during_time_1, daemon=True)
        plan = api(PRIMARY[1]).post(f"/install/kea-migration/{mid}/plan", {"phase": "migrate"})
        steps = [c["after"]["step"] for c in plan["changes"]]
        assert steps[4:9] == [
            "kea-mig-stop",
            "kea-mig-fetch-leases",
            "kea-mig-leases-in",
            "kea-mig-start",
            "kea-mig-wait-partner-down",
        ], steps
        started = time.monotonic()
        thread.start()
        job = run_job(plan)
        thread.join(timeout=60)
        assert job["state"] == "done", json.dumps(job, indent=2)
        print(f"migration: {time.monotonic() - started:.0f} s")
        mig = migration(mid)
        assert (mig["state"], mig["stage"], mig["rollback_possible"]) == ("migrated", "done", True), mig
        print(f"measured outage: {mig['outage_seconds']} s")
        assert 0 < mig["outage_seconds"] < 60, mig
        assert got.get("stage") == "standby" and got["ip"].startswith("10.99.1."), got
        # Both nodes on ISC 3.2 in hot-standby; the time 1 lease reached both through the copy.
        for host, _ in (PRIMARY, STANDBY):
            pkgs = ssh(
                host, "dpkg-query -W -f '${Package} ${Version} ${Status}\\n' 'isc-kea-dhcp4' 'kea-dhcp4*'"
            )[1]
            assert "isc-kea-dhcp4 3.2.1" in pkgs and "kea-dhcp4-server 2.6.3-1+deb13u1 install" not in pkgs, (
                pkgs
            )
            assert ha_state(host) == "hot-standby"
            assert has_lease(host, got["ip"]), (host, got)
        # The standby's detection delays are the pair's again (the primary's were never changed).
        delays = []
        for host, _ in (PRIMARY, STANDBY):
            conf = json.loads(ssh(host, "sudo cat /etc/kea/kea-dhcp4.conf")[1])
            [ha] = [h for h in conf["Dhcp4"]["hooks-libraries"] if h["library"].endswith("libdhcp_ha.so")]
            rel = ha["parameters"]["high-availability"][0]
            delays.append((rel.get("max-response-delay"), rel.get("max-unacked-clients")))
        assert delays[0] == delays[1] == (15000, 0), delays
        client = watch.stop()
        assert client["naks"] == 0 and client["pcap_naks"] == 0, client
        assert client["address"] == watch.address and client["last"] == "ack", client
        assert client["longest_gap"] < 60, client
        # DDNS after the migration: a new lease gets its name on the primary's BIND.
        ip = probe_get(MAC_AFTER)
        name = "probe-0503.example.lan"
        wait_for(
            f"{name} in DNS",
            lambda: ip in ssh(PRIMARY[0], f"dig +short @127.0.0.1 {name} A")[1],
            timeout=60,
        )

    def test_03_return_of_the_migrated_pair(self):
        mid = str(STATE["mid"])
        watch = Watch("return")
        plan = api(PRIMARY[1]).post(f"/install/kea-migration/{mid}/plan", {"phase": "rollback"})
        steps = [c["after"]["step"] for c in plan["changes"]]
        assert steps[0] == "kea-mig-ha-maintenance" and "kea-mig-wait-partner-down" in steps, steps
        started = time.monotonic()
        job = run_job(plan)
        assert job["state"] == "done", json.dumps(job, indent=2)
        print(f"return of the pair: {time.monotonic() - started:.0f} s")
        mig = migration(mid)
        assert mig["state"] == "rolled_back" and not mig["rollback_possible"], mig
        print(f"measured outage of the return: {mig['outage_seconds']} s")
        assert all(n["status"] == "rolled_back" for n in mig["nodes"]), mig
        pair_back()
        client = watch.stop()
        assert client["naks"] == 0 and client["pcap_naks"] == 0, client
        assert client["address"] == watch.address and client["last"] == "ack", client
        before = STATE["before"]
        for host, _ in (PRIMARY, STANDBY):
            assert ssh(host, KEA_STATE)[1] == before[host], host  # type: ignore[index]

    def test_99_client_back_to_the_reference_pair(self):
        put(CLIENT, ALLOW, ALLOW_DEFAULT)
        ssh(CLIENT, "sudo networkctl reload")
        assert ha_state(PRIMARY[0]) == "hot-standby"
