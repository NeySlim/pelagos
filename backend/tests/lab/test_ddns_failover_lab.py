# SPDX-License-Identifier: Apache-2.0
"""DDNS failover end to end (batches D1 to D4) on a real pair: lab-d3a ns1 and lab-d3b ns2 (BIND 9.20,
Kea 2.6 HA and D2 from Debian 13), lab-d3c a DHCP client on the pair's segment.

From the legacy pair (snapshot `legacy`, `provision.sh pair`): the deb of this checkout on both, ns2
enrolled, both imported, the security plan (read key on the transfers, md5 key replaced), the zones
handed over from Debian's root-owned named.conf.local through the helper, then the prepare plan. A
webhook receiver on lab-docker gets the alerts. named stopped on ns1: `ddns_outage` reaches the
webhook, the client's update is lost, the failover plan promotes ns2, the client's next lease gets
its records on ns2 and the replay plan resends the lost one. named started again on ns1: its
collector demotes it on its own. The switchover plan gives the role back to ns1. Last, the automatic
promotion (off by default) promotes ns2 once by itself, and the Failover tab of ns1 promotes it back
while ns2's named is stopped (Playwright, frontend/e2e-lab).

The VMs are rolled back to `legacy` first and left as the test ends.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any

import pytest

from pelagos import __version__
from tests.lab.labkit import (
    ADMIN_PASSWORD,
    DOCKER,
    REPO,
    Api,
    ApiError,
    deb_package,
    fixable,
    keep,
    put,
    rollback,
    scp,
    ssh,
    wait_for,
)
from tests.lab.test_notify_lab import RECEIVER

pytestmark = pytest.mark.lab

A1, A2, AC, DK = "10.99.0.71", "10.99.0.72", "10.99.0.73", DOCKER[1]
VMS = ("lab-d3a", "lab-d3b", "lab-d3c")
ZONES = ("example.lan", "0.99.10.in-addr.arpa", "1.99.10.in-addr.arpa")
DDNS_ZONES = ZONES  # D2 names all three
NIC = "ens19"
DROPIN = "/etc/systemd/network/10-netplan-lab-dhcp.network.d/hostname.conf"
SOCKET = "/run/kea/kea4-ctrl-socket"
HOOK_PORT = 8091
HMAC_SECRET = "lab-d6-hmac-1"
TAG = time.strftime("%H%M%S")
STATE: dict[str, Any] = {}


def api(address: str = A1) -> Api:
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=300, interval=5)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


def ids() -> tuple[str, str]:
    if "ids" not in STATE:
        nodes = {n["peer"]["name"]: n["peer"]["id"] for n in api().get("/nodes")["items"]}
        STATE["ids"] = (nodes["ns1"], nodes["ns2"])
    return STATE["ids"]


def dig(host: str, name: str, rtype: str = "A") -> str:
    return ssh(host, f"dig +short +norec @127.0.0.1 {name} {rtype}")[1].strip()


def ptr(host: str, ip: str) -> str:
    return ssh(host, f"dig +short +norec @127.0.0.1 -x {ip}")[1].strip()


def serial(host: str, zone: str = "example.lan") -> int:
    out = dig(host, zone, "SOA").split()
    return int(out[2]) if len(out) > 2 else -1


def kea(host: str, command: str) -> dict:
    body = json.dumps({"command": command})
    return json.loads(ssh(host, f"echo '{body}' | sudo socat - UNIX-CONNECT:{SOCKET}")[1])


def client_address() -> str | None:
    for word in ssh(AC, f"ip -4 -o addr show dev {NIC}")[1].split():
        if word.startswith("10.99.1."):
            return word.split("/")[0]
    return None


def lease_as(hostname: str) -> str:
    """lab-d3c asks again for its lease under `hostname`: a real DHCPREQUEST that Kea sends to D2."""
    wait_for(
        "Kea HA serving",
        lambda: kea(A1, "ha-heartbeat")["arguments"]["state"] in ("hot-standby", "partner-down"),
        timeout=180,
        interval=3,
    )
    put(AC, DROPIN, f"[DHCPv4]\nHostname={hostname}\n")
    ssh(AC, f"sudo networkctl reload; sudo networkctl down {NIC}; sleep 1; sudo networkctl up {NIC}")
    return wait_for("client lease", client_address, timeout=90)


def current_hostname() -> str:
    """The hostname lab-d3c sends (its networkd drop-in)."""
    out = ssh(AC, f"sudo cat {DROPIN}")[1]
    return next(ln.split("=", 1)[1].strip() for ln in out.splitlines() if ln.startswith("Hostname="))


def resilience(address: str = A1) -> dict:
    return api(address).get("/dhcp/ddns/resilience")


def zone_states(address: str = A1) -> dict[str, dict]:
    return {z["zone"].rstrip("."): z for z in resilience(address)["zones"]}


def alerts(address: str, kind: str, state: str = "open") -> list[dict]:
    items = api(address).get("/alerts?include_resolved=true&per_page=500")["items"]
    return [a for a in items if a["kind"] == kind and a["state"] == state]


def webhook() -> list[dict]:
    out = ssh(DK, f"curl -fsS http://127.0.0.1:{HOOK_PORT}/")[1]
    return json.loads(out)


def hook_events(kind: str) -> list[tuple[str, str]]:
    return [
        (e["event"], e["alert"]["subject"])
        for w in webhook()
        if w["body"]["reason"] != "test"
        for e in w["body"]["events"]
        if e["alert"]["kind"] == kind
    ]


def zone_kind(host: str, zone: str = "example.lan") -> str:
    """The type named runs the zone with on `host` (rndc zonestatus)."""
    out = ssh(host, f"sudo rndc zonestatus {zone}", check=False)[1]
    return next((ln.split(":", 1)[1].strip() for ln in out.splitlines() if ln.startswith("type:")), "")


def node_of(address: str) -> str:
    return ids()[0] if address == A1 else ids()[1]


def roles() -> dict[str, dict]:
    return api().get("/admin/settings")["ddns"]["roles"]


def epoch_of(zone: str = "example.lan") -> int:
    return int(roles()[f"_default/{zone}."]["epoch"])


def d2_first(host: str) -> set[str]:
    """First DNS server of each D2 domain in the running D2 file of `host`."""
    conf = json.loads(ssh(host, "sudo cat /etc/kea/kea-dhcp-ddns.conf")[1])["DhcpDdns"]
    return {
        d["dns-servers"][0]["ip-address"]
        for side in ("forward-ddns", "reverse-ddns")
        for d in conf.get(side, {}).get("ddns-domains", [])
    }


class TestDdnsFailoverLab:
    def test_00_legacy_pair(self):
        rollback(*VMS)
        for host in (A1, A2):
            ssh(host, "sudo systemctl restart named kea-dhcp-ddns-server kea-dhcp4-server")
        addr = lease_as("lab-client")
        wait_for("legacy DDNS", lambda: dig(A1, "lab-client.example.lan") == addr, timeout=60)

    def test_01_deploy_init_enroll_import(self):
        deb = deb_package()
        for host in (A1, A2):
            scp(host, deb, "/tmp/pelagos.deb")
            ssh(
                host,
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb",
                timeout=900,
            )
        ssh(
            A1,
            f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
            f"--web-url https://{A1}:8443 --replication-url https://{A1}:8444 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )
        token = api(A1).post("/nodes/enroll-token", {})
        ssh(
            A2,
            f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
            f"--ca-fingerprint {token['ca_fingerprint']} --name ns2 "
            f"--replication-url https://{A2}:8444 --web-url https://{A2}:8443 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )

        def both_current() -> bool:
            nodes = api(A1).get("/nodes")["items"]
            return len(nodes) == 2 and all(
                n["status"] == "online" and n.get("version") == __version__ for n in nodes
            )

        wait_for("both nodes online on this version", both_current, timeout=300, interval=5)
        for address in (A1, A2):
            api(address).apply(api(address).post("/install/import/plan", {"engines": ["bind", "kea4", "d2"]}))
        # ns2, imported right after ns1, signs with ns1's read and admin keys (a copy transfers with them).
        for key in ("ddi-read", "ddi-admin"):
            secrets = {
                ssh(h, f"sudo grep -A3 '\"{key}\"' /etc/bind/pelagos/keys.conf | grep secret")[1]
                for h in (A1, A2)
            }
            assert len(secrets) == 1, key
        # A fast collector; production defaults for the failover itself.
        api().call("PUT", "/admin/settings", {"collector": {"poll_seconds": 10, "peer_poll_seconds": 15}})
        state = zone_states()
        assert set(DDNS_ZONES) <= set(state), state
        for zone in DDNS_ZONES:
            keys = {b["key"] for b in state[zone]["blockers"]}
            assert "ddns.blocker.not_managed" in keys, state[zone]

    def test_02_security_plan(self):
        """transfer_without_read_key on both nodes: Pelagos reads the zones by AXFR with its read key."""
        findings = api(A1).get("/install/security")["findings"]
        assert "transfer_without_read_key" in {f["kind"] for f in findings}
        api(A1).apply(api(A1).post("/install/security/plan", {"finding_ids": fixable(findings)}), timeout=900)
        rest = api(A2).get("/install/security")["findings"]
        assert "transfer_without_read_key" in {f["kind"] for f in rest}
        api(A2).apply(api(A2).post("/install/security/plan", {"finding_ids": fixable(rest)}))
        for address in (A1, A2):
            kinds = {f["kind"] for f in api(address).get("/install/security")["findings"]}
            assert "transfer_without_read_key" not in kinds, (address, kinds)
        for zone in ZONES:
            wait_for(f"{zone} readable", lambda z=zone: api().get(f"/dns/zones/{z}/records"), timeout=120)

    def test_03_zones_handed_over(self):
        """Debian keeps the zones in /etc/bind/named.conf.local (root:bind 0644): the helper writes it."""
        for address in (A1, A2):
            me = node_of(address)
            items = [
                i
                for i in api(address).get("/dns/handover")["items"]
                if i["kind"] == "zones" and me in i["nodes"]
            ]
            assert {i["name"].rstrip(".") for i in items} >= set(ZONES), items
            changes = [{"op": "replace", "target": i["target"], "after": {"comment": True}} for i in items]
            plan = api(address).post("/dns/config/plan", {"changes": changes, "node_ids": [me]})
            api(address).apply(plan)
            local = ssh(address, "sudo cat /etc/bind/named.conf.local")[1]
            assert "moved to zones.conf by Pelagos" in local, local
            assert ssh(address, "stat -c '%U:%G %a' /etc/bind/named.conf.local")[1].strip() == "root:bind 644"
        for zone in ZONES:
            assert serial(A1, zone) == serial(A2, zone) > 0

        def managed() -> bool:
            state = zone_states()
            return all(
                {b["key"] for b in state[z]["blockers"]} == {"ddns.blocker.not_prepared"} for z in DDNS_ZONES
            )

        wait_for("zones only lacking preparation", managed, timeout=120, interval=5)

    def test_04_prepare(self):
        plan = api().post("/dhcp/ddns/resilience/plan", {})
        api().apply(plan)
        state = zone_states()
        ns1, ns2 = ids()
        for zone in DDNS_ZONES:
            z = state[zone]
            assert z["ready"] and z["primary_node_id"] == ns1 and z["copies"] == [ns2], z
            assert z["epoch"] == 1 and z["prepared_at"], z
        for host in (A1, A2):
            assert d2_first(host) == {A1}, host
        with pytest.raises(ApiError) as exc:
            api().post("/dhcp/ddns/failover/plan", {})
        assert exc.value.status == 409  # ns1 still serves the zones

    def test_05_webhook_receiver(self):
        ssh(DK, "sudo docker rm -f d6-hook >/dev/null 2>&1; sudo mkdir -p /srv/d6", check=False)
        put(DK, "/srv/d6/receiver.py", RECEIVER.replace("8090", str(HOOK_PORT)))
        ssh(
            DK,
            f"sudo docker run -d --name d6-hook -p {HOOK_PORT}:{HOOK_PORT} -e HMAC_SECRET={HMAC_SECRET} "
            "-v /srv/d6/receiver.py:/r.py:ro python:3.13-slim python -u /r.py",
        )
        wait_for("webhook receiver", lambda: webhook() == [], timeout=120)
        for channel in api().get("/admin/notifications")["channels"]:
            api().call("DELETE", f"/admin/notifications/channels/{channel['id']}")
        channel = api().post(
            "/admin/notifications/channels",
            {
                "type": "webhook",
                "name": "lab ddns",
                "language": "en",
                "filters": {"kinds_include": ["ddns_outage", "dns_stale_primary", "ddns_replay"]},
                "params": {"url": f"http://{DK}:{HOOK_PORT}/hook"},
                "secrets": {"hmac_secret": HMAC_SECRET},
            },
        )
        STATE["channel"] = channel["id"]
        assert api().post("/admin/notifications/test", {"channel_id": channel["id"]})["ok"] is True
        wait_for("test message", lambda: len(webhook()) == 1, timeout=60)

    def test_06_outage(self):
        ns1, _ns2 = ids()
        ssh(A1, "sudo systemctl stop named")

        def outage() -> list[dict]:
            found = alerts(A2, "ddns_outage")
            return [
                a for a in found if a["node_id"] == ns1 and a["details"]["zone"].rstrip(".") == "example.lan"
            ]

        [alert] = wait_for("ddns_outage", outage, timeout=180, interval=5)
        assert alert["severity"] == "critical" and alert["details"]["remediation"] == "ddns_failover"
        assert alert["details"]["cause"] == "named_down", alert
        wait_for(
            "ddns_outage on the webhook",
            lambda: ("opened", "ddns:_default/example.lan.") in hook_events("ddns_outage"),
            timeout=240,
            interval=5,
        )
        assert all(w["signed"] for w in webhook())
        # This update is lost: D2 tries ns1 (down), then ns2, which is a copy and refuses.
        name = f"lost{TAG}"
        lease_as(name)
        outage = wait_for("D2 outage window", lambda: resilience(A2)["outage"], timeout=120, interval=5)
        # The copy's REFUSED counts as a success in D2's statistics: the window stays open anyway.
        time.sleep(40)
        assert dig(A2, f"{name}.example.lan") == ""
        assert resilience(A2)["outage"]["since"] == outage["since"]
        # The stopped primary keeps its place: the zones stay prepared and D2 lists name it.
        state = resilience(A2)
        assert all(z["ready"] for z in state["zones"]), state["zones"]
        servers = [s for d2 in state["d2"] for d in d2["domains"] for s in d["servers"]]
        assert {(s["node_id"], s["role"]) for s in servers} == {(ns1, "primary"), (ids()[1], "secondary")}
        with pytest.raises(ApiError) as exc:
            api(A2).post("/dhcp/ddns/switchover/plan", {"to_node_id": ids()[1]})
        assert exc.value.status == 409  # the active primary does not answer

    def test_07_promote(self):
        _ns1, ns2 = ids()
        plan = api(A2).post("/dhcp/ddns/failover/plan", {})
        assert plan["requires_confirmation"] is True and plan["scope"] == "dns.failover", plan
        assert any("replay" in (v.get("output") or "") for v in plan["validations"]), plan["validations"]
        api(A2).apply(plan)
        for zone in DDNS_ZONES:
            z = zone_states(A2)[zone]
            assert z["primary_node_id"] == ns2 and z["epoch"] == 2, z
        assert zone_kind(A2) == "primary"
        for host in (A1, A2):
            assert d2_first(host) == {A2}, host

    def test_08_replay_offer(self):
        """The update lost before the promotion is offered for replay, and replayed by plan."""
        name = current_hostname()
        ip = client_address()

        def offered() -> dict | None:
            replay = resilience(A2).get("replay") or {}
            return replay if (replay.get("candidates") or 0) >= 1 else None

        replay = wait_for("replay candidates", offered, timeout=300, interval=10)
        assert replay["source"] in ("open", "outage") and not replay["notes"], replay
        plan = api(A2).post("/dhcp/ddns/replay/plan", {})
        targets = {c["target"] for p in [plan, *plan.get("parts", [])] for c in p.get("changes", [])}
        assert plan["requires_confirmation"] is True and f"resend/{ip}" in targets, plan
        api(A2).apply(plan)
        wait_for(f"A of {name} on ns2", lambda: dig(A2, f"{name}.example.lan") == ip, timeout=90)
        wait_for(f"PTR of {ip} on ns2", lambda: ptr(A2, ip) == f"{name}.example.lan.", timeout=90)

    def test_08b_new_lease_on_the_promoted_node(self):
        name = f"promoted{TAG}"
        ip = lease_as(name)
        wait_for(f"A of {name} on ns2", lambda: dig(A2, f"{name}.example.lan") == ip, timeout=90)
        wait_for(f"PTR of {ip} on ns2", lambda: ptr(A2, ip) == f"{name}.example.lan.", timeout=90)
        STATE["promoted"] = name

    def test_09_old_primary_back_demoted_by_itself(self):
        ns1, ns2 = ids()
        ssh(A1, "sudo systemctl start named")
        wait_for("ns1 a copy again", lambda: zone_kind(A1) == "secondary", timeout=240, interval=5)
        name = STATE["promoted"]
        wait_for("ns1 transfers from ns2", lambda: dig(A1, f"{name}.example.lan") != "", timeout=120)
        assert serial(A1) == serial(A2)
        z = zone_states(A1)["example.lan"]
        assert z["primary_node_id"] == ns2 and z["stale"] == [] and z["copies"] == [ns1], z
        audit = api(A1).get(f"/audit?action=dns.failover.op&user=system&node_id={ns1}")["items"]
        assert audit, "no demotion audit line"
        wait_for("no dns_stale_primary open", lambda: not alerts(A1, "dns_stale_primary"), timeout=180)
        wait_for("ddns_outage resolved", lambda: not alerts(A1, "ddns_outage"), timeout=180, interval=5)
        wait_for(
            "ddns_outage resolution on the webhook",
            lambda: ("resolved", "ddns:_default/example.lan.") in hook_events("ddns_outage"),
            timeout=240,
            interval=5,
        )

    def test_10_switch_back_by_plan(self):
        ns1, _ns2 = ids()
        plan = api(A1).post("/dhcp/ddns/switchover/plan", {"to_node_id": ns1})
        assert plan["requires_confirmation"] is True, plan
        api(A1).apply(plan)
        for zone in DDNS_ZONES:
            z = zone_states(A1)[zone]
            assert z["primary_node_id"] == ns1 and z["epoch"] == 3, z
        assert zone_kind(A1) == "primary" and zone_kind(A2) == "secondary"
        for host in (A1, A2):
            assert d2_first(host) == {A1}, host
        name = f"back{TAG}"
        ip = lease_as(name)
        wait_for(f"A of {name} on ns1", lambda: dig(A1, f"{name}.example.lan") == ip, timeout=90)
        wait_for(f"A of {name} on ns2", lambda: dig(A2, f"{name}.example.lan") == ip, timeout=90)

    def test_11_replay_offer_closed(self):
        api(A1).post("/alerts/consistency/run")
        wait_for("no ddns_replay open", lambda: not alerts(A1, "ddns_replay"), timeout=180, interval=5)

    def test_12_automatic_promotion(self):
        _ns1, ns2 = ids()
        assert api().get("/admin/settings")["ddns"]["failover_auto_enabled"] is False
        api().call(
            "PUT", "/admin/settings", {"ddns": {"failover_auto_enabled": True, "failover_after_seconds": 60}}
        )
        try:
            ssh(A1, "sudo systemctl stop named")
            wait_for("automatic promotion of ns2", lambda: epoch_of() == 4, timeout=420, interval=10)
            z = zone_states(A2)["example.lan"]
            assert z["primary_node_id"] == ns2, z
            role = roles()["_default/example.lan."]
            assert role["by"] == "system", role
            name = f"auto{TAG}"
            ip = lease_as(name)
            wait_for(f"A of {name} on ns2", lambda: dig(A2, f"{name}.example.lan") == ip, timeout=90)
        finally:
            api(A2).call("PUT", "/admin/settings", {"ddns": {"failover_auto_enabled": False}})
            ssh(A1, "sudo systemctl start named")
        wait_for("ns1 demoted again", lambda: zone_kind(A1) == "secondary", timeout=240, interval=5)

    def test_13_failover_tab_on_the_real_pair(self):
        """The Failover tab of ns1 while ns2 (primary since the automatic promotion) has named stopped."""
        frontend = REPO / "frontend"
        if not (frontend / "node_modules" / ".bin" / "playwright").exists():
            pytest.skip("no frontend/node_modules")
        ns1, _ns2 = ids()
        ssh(A2, "sudo systemctl stop named")
        try:
            env = {**os.environ, "TEST_URL": f"https://{A1}:8443", "LAB_PASSWORD": ADMIN_PASSWORD}
            res = subprocess.run(
                ["npx", "playwright", "test", "--config", "e2e-lab/lab.config.js"],
                cwd=frontend,
                env={**env, "FROM": "ns2", "TO": "ns1"},
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
            assert res.returncode == 0, res.stdout[-4000:] + res.stderr[-2000:]
            assert epoch_of() == 5 and roles()["_default/example.lan."]["primary"] == ns1
        finally:
            ssh(A2, "sudo systemctl start named")
        wait_for("ns2 demoted", lambda: zone_kind(A2) == "secondary", timeout=240, interval=5)

    def test_99_cleanup(self):
        if keep():
            pytest.skip("PELAGOS_LAB_KEEP=1")
        if "channel" in STATE:
            api().call("DELETE", f"/admin/notifications/channels/{STATE['channel']}")
        ssh(DK, "sudo docker rm -f d6-hook; sudo rm -rf /srv/d6", check=False)
