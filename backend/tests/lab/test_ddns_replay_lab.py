# SPDX-License-Identifier: Apache-2.0
"""DDNS replay (batch D1) on the real pair lab-ad1/lab-ad2 (Kea 2.6 HA, D2 and BIND from Debian 13).

D2 is stopped on both nodes, leases are written meanwhile (lease4-add sends nothing to D2: the state a
lost update leaves behind), D2 comes back, and the replay plan from the API resends exactly those
leases: their A and PTR records appear on the primary. Runs after test_notify_lab.py, which installs
this checkout on the pair (or installs it itself when the version differs).
"""

from __future__ import annotations

import json
import time

import pytest

from pelagos import __version__
from tests.lab.labkit import Api, deb_package, scp, ssh, wait_for

pytestmark = pytest.mark.lab

A1, A2 = "10.99.0.31", "10.99.0.32"
SOCKET = "/run/kea/kea4-ctrl-socket"
STATE: dict[str, object] = {}
# Two leases of the DHCP subnet of the pair, named after the run so a rerun starts clean.
TAG = time.strftime("%H%M%S")
LEASES = {f"10.99.1.{190 + i}": f"replay{TAG}{i}.example.lan" for i in range(2)}


def api() -> Api:
    if "api" not in STATE:
        client = Api(A1)
        wait_for("login", lambda: client.login(), timeout=300, interval=5)
        STATE["api"] = client
    return STATE["api"]  # type: ignore[return-value]


def kea(host: str, command: str, arguments: dict | None = None) -> dict:
    body = {"command": command, **({"arguments": arguments} if arguments else {})}
    out = ssh(host, f"echo '{json.dumps(body)}' | sudo socat - UNIX-CONNECT:{SOCKET}")[1]
    return json.loads(out)


def dig(name: str, rtype: str) -> str:
    return ssh(A1, f"dig +short @127.0.0.1 {name} {rtype}")[1].strip()


def ptr(ip: str) -> str:
    return ssh(A1, f"dig +short @127.0.0.1 -x {ip}")[1].strip()


def replay_alert(state: str) -> list[dict]:
    items = api().get("/alerts?include_resolved=true&per_page=500")["items"]
    return [a for a in items if a["kind"] == "ddns_replay" and a["state"] == state]


class TestDdnsReplayLab:
    def test_00_pair_on_this_version(self):
        # Always reinstalled: a checkout with uncommitted changes keeps the same package version.
        deb = deb_package()
        for host in (A1, A2):
            scp(host, deb, "/tmp/pelagos.deb")
            ssh(
                host,
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y -q /tmp/pelagos.deb",
                timeout=900,
            )
        STATE.pop("api", None)
        wait_for(
            "both nodes online on this version",
            lambda: all(
                n["status"] == "online" and n.get("version") == __version__
                for n in api().get("/nodes")["items"]
            ),
            timeout=300,
            interval=5,
        )

    def test_00b_zones_readable(self):
        """The replay judges only the zones Pelagos can read: grant its read key by the security plan."""
        for address in (A1, A2):
            client = Api(address)
            client.login()
            ids = [
                f["id"]
                for f in client.get("/install/security")["findings"]
                if f["kind"] == "transfer_without_read_key"
            ]
            if ids:
                client.apply(client.post("/install/security/plan", {"finding_ids": ids}))
        for zone in ("example.lan", "0.99.10.in-addr.arpa", "1.99.10.in-addr.arpa"):
            wait_for(
                f"{zone} readable", lambda zone=zone: api().get(f"/dns/zones/{zone}/records"), timeout=120
            )

    def test_01_updates_lost_while_d2_is_down(self):
        for host in (A1, A2):
            ssh(host, "sudo systemctl stop kea-dhcp-ddns-server")
        # The D2 poller notices the outage (its window opens at the last good poll).
        time.sleep(30)
        for ip, name in LEASES.items():
            out = kea(
                A1,
                "lease4-add",
                {
                    "ip-address": ip,
                    "hw-address": "02:00:5e:10:00:" + ip.rsplit(".", 1)[1][-2:],
                    "subnet-id": 1,
                    "hostname": name,
                    "fqdn-fwd": True,
                    "fqdn-rev": True,
                },
            )
            assert out["result"] == 0, out
        for host in (A1, A2):
            ssh(host, "sudo systemctl start kea-dhcp-ddns-server")
        for ip, name in LEASES.items():
            # The address may keep a PTR from an earlier run: a different name still counts as lost.
            assert dig(name, "A") == "" and ptr(ip) != name + "."

    def test_02_replay_plan_resends_them(self):
        def candidates() -> int:
            replay = api().get("/dhcp/ddns/resilience").get("replay") or {}
            # The alert judges closed windows only: wait for D2's first clean poll.
            return int(replay.get("candidates") or 0) if replay.get("source") == "outage" else 0

        wait_for("replay candidates", lambda: candidates() >= len(LEASES), timeout=300, interval=10)
        # The consistency pass raises ddns_replay over the closed window, and resolves it after the replay.
        api().post("/alerts/consistency/run")
        wait_for("ddns_replay open", lambda: replay_alert("open"), timeout=180, interval=5)
        plan = api().post("/dhcp/ddns/replay/plan", {})
        targets = {c["target"] for p in [plan, *plan.get("parts", [])] for c in p.get("changes", [])}
        assert {f"resend/{ip}" for ip in LEASES} <= targets, json.dumps(plan)[:2000]
        assert plan.get("requires_confirmation") is True
        result = api().apply(plan)
        assert result.get("state") in ("applied", "done"), result
        for ip, name in LEASES.items():
            wait_for(f"A of {name}", lambda name=name, ip=ip: dig(name, "A") == ip, timeout=60)
            wait_for(f"PTR of {ip}", lambda name=name, ip=ip: ptr(ip) == name + ".", timeout=60)
        api().post("/alerts/consistency/run")
        wait_for("ddns_replay resolved", lambda: not replay_alert("open"), timeout=180, interval=5)

    def test_99_cleanup(self):
        for ip in LEASES:
            kea(A1, "lease4-del", {"ip-address": ip})
