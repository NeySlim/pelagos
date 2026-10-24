# SPDX-License-Identifier: Apache-2.0
"""The reference pair end to end: lab-ns1 and lab-ns2 from a legacy BIND + Kea HA setup to a
Pelagos cluster, driven from lab-dev over ssh and HTTPS.

scripts/lab/provision.sh builds the pair without Pelagos (BIND primary/secondary, Kea 2.6 HA
hot-standby, D2 signing with hmac-md5, lab-client as DHCP client). Then: the deb on both nodes,
ns2 enrolled from ns1, both configurations imported, the security plan applied (md5 to sha256
through the dual-key switch on both D2), a record written through ns2 and read on ns1, a host
whose reservation and records join a real lease, Kea killed on ns1 (HA alert), ns2 stopped and
caught up. The VMs are rolled back first; the pair is left running with Pelagos for the demo.
"""

from __future__ import annotations

import json
import time

import pytest

from tests.lab.labkit import (
    CLIENT,
    NS1,
    NS2,
    Api,
    deb_package,
    rollback,
    run_script,
    scp,
    ssh,
    sudo_cat,
    wait_for,
)

pytestmark = pytest.mark.lab

A1, A2, AC = NS1[1], NS2[1], CLIENT[1]
DHCP_NET = "10.99.1."
STATE: dict[str, object] = {}


def api(address: str) -> Api:
    """One logged-in session per node for the whole module (logins are rate limited)."""
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=120)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


def node_id(address: str) -> str:
    return api(address).get("/nodes/self")["peer"]["id"]


def client_nic() -> tuple[str, str]:
    out = ssh(AC, "ip -o link show | awk -F': ' '$2 != \"lo\" && $2 != \"eth0\" {print $2; exit}'")[1]
    nic = out.strip()
    return nic, ssh(AC, f"cat /sys/class/net/{nic}/address")[1].strip()


def client_address() -> str | None:
    nic, _ = client_nic()
    out = ssh(AC, f"ip -4 -o addr show dev {nic}")[1]
    for word in out.split():
        if word.startswith(DHCP_NET):
            return word.split("/")[0]
    return None


def renew_client() -> None:
    """Releases the lease and asks again: a real DISCOVER/REQUEST from lab-client."""
    nic, _ = client_nic()
    ssh(AC, f"sudo networkctl down {nic}; sleep 1; sudo networkctl up {nic}")


def kea_command(host: str, command: str) -> dict:
    out = ssh(
        host,
        f"echo '{json.dumps({'command': command})}' | sudo socat - UNIX-CONNECT:/run/kea/kea4-ctrl-socket",
    )[1]
    return json.loads(out)


def open_alerts(address: str, kind: str) -> list[dict]:
    return api(address).get(f"/alerts?state=open&kind={kind}")["items"]


def restart_collectors() -> None:
    """The collectors read their periods at start; the web processes wait for them to be ready."""
    for address in (A1, A2):
        ssh(address, "sudo systemctl restart pelagos-collector")
    for address in (A1, A2):
        wait_for(f"{address} ready", lambda a=address: Api(a).get("/health")["replication"] == "ready")


def dig(host: str, name: str, rtype: str = "A") -> str:
    return ssh(host, f"dig +short @127.0.0.1 {name} {rtype}")[1].strip()


class TestReferencePair:
    def test_00_rollback_and_provision(self):
        rollback("lab-ns1", "lab-ns2", "lab-client")
        out = run_script("provision.sh", "all", timeout=1800)
        assert "HA: hot-standby" in out

    def test_01_pair_works_without_pelagos(self):
        assert ssh(A1, "/usr/sbin/kea-dhcp4 -v")[1].startswith("2.6")
        wait_for("lab-client lease", client_address, timeout=60)
        addr = client_address()
        for host in (A1, A2):
            wait_for(f"DDNS record on {host}", lambda h=host: dig(h, "lab-client.example.lan") == addr)
        d2 = json.loads(sudo_cat(A2, "/etc/kea/kea-dhcp-ddns.conf"))["DhcpDdns"]
        assert d2["tsig-keys"][0]["algorithm"] == "HMAC-MD5"
        assert kea_command(A1, "ha-heartbeat")["arguments"]["state"] == "hot-standby"

    def test_02_install_the_deb_on_both(self):
        deb = deb_package()
        for host in (A1, A2):
            scp(host, deb, "/tmp/pelagos.deb")
            ssh(
                host,
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb",
                timeout=900,
            )
            assert ssh(host, "systemctl is-active pelagos-helper.socket")[1].strip() == "active"
            assert ssh(host, "stat -c '%U:%G %a' /run/pelagos-helper.sock")[1].strip() == "root:pelagos 660"

    def test_03_init_ns1_enroll_ns2(self):
        from tests.lab.labkit import ADMIN_PASSWORD

        ssh(
            A1,
            f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
            f"--web-url https://{A1}:8443 --replication-url https://{A1}:8444 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )
        token = api(A1).post("/nodes/enroll-token", {})
        assert token["url"] == f"https://{A1}:8444" and token["ca_fingerprint"].startswith("sha256:")
        ssh(
            A2,
            f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
            f"--ca-fingerprint {token['ca_fingerprint']} --name ns2 "
            f"--replication-url https://{A2}:8444 --web-url https://{A2}:8443 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )

        def both_online() -> bool:
            nodes = api(A1).get("/nodes")["items"]
            return len(nodes) == 2 and all(n["status"] == "online" for n in nodes)

        wait_for("both nodes online", both_online, timeout=120)
        # The same admin logs in on ns2: users come from the replicated cluster.toml.
        assert api(A2).get("/nodes/self")["peer"]["name"] == "ns2"

    def test_04_import_both_configurations(self):
        for address in (A1, A2):
            plan = api(address).post("/install/import/plan", {"engines": ["bind", "kea4", "d2"]})
            assert plan["scope"] == "import" and not plan.get("error"), plan
            job = api(address).apply(plan)
            verify = next(s for s in job["steps"] if s["name"] == "import/verify")["output"]
            assert "bind.unchanged=ok" in verify and "kea4.unchanged=ok" in verify, verify
            assert "d2.unchanged=ok" in verify
        mods = {n["peer"]["name"]: n["peer"]["modules"] for n in api(A1).get("/nodes")["items"]}
        for name in ("ns1", "ns2"):
            assert mods[name] == {"bind": True, "kea4": True, "kea6": False, "d2": True}, mods
        # Kea 2.6 from Debian answers the reads the API needs (no host_cmds, no subnet_cmds).
        servers = api(A1).get("/dhcp/v4/servers")["items"]
        assert {s["capabilities"]["version"][:3] for s in servers} == {"2.6"}
        subnets = api(A1).get("/dhcp/v4/subnets")["items"]
        assert [s["subnet"] for s in subnets] == ["10.99.1.0/24"]
        leases = api(A1).get("/dhcp/v4/leases")["items"]
        assert any(lease["ip_address"].startswith(DHCP_NET) for lease in leases)
        ha = {h["server_name"]: h for h in api(A1).get("/dhcp/v4/ha")["items"]}
        assert ha["ns1"]["state"] == "hot-standby" and ha["ns1"]["mode"] == "hot-standby"
        d2 = api(A2).get("/dhcp/d2/servers")["items"]
        assert d2 and d2[0]["capabilities"]["version"].startswith("2.6")

    def test_05_security_audit_and_dual_key_switch(self):
        ids1, ids2 = node_id(A1), node_id(A2)
        findings = api(A1).get("/install/security")["findings"]
        kinds = {f["kind"] for f in findings}
        assert {"weak_shared_kea_key", "update_without_admin_key", "transfer_without_read_key"} <= kinds
        plan = api(A1).post("/install/security/plan", {"finding_ids": [f["id"] for f in findings]})
        switch = next(c for c in plan["changes"] if c["target"].endswith("/2-d2-switch"))
        assert sorted(switch["node_ids"]) == sorted([ids1, ids2])
        since = int(time.time())
        job = api(A1).apply(plan, timeout=900)
        names = [s["name"] for s in job["steps"]]
        assert "2-d2-switch/ns2" in names and names[-1].endswith("3-bind-remove")
        assert api(A1).get("/install/security")["findings"] == []
        # ns2 holds secondary copies only: its finding opens transfers to ddi-read.
        rest = api(A2).get("/install/security")["findings"]
        assert [f["kind"] for f in rest] == ["transfer_without_read_key"]
        api(A2).apply(api(A2).post("/install/security/plan", {"finding_ids": [f["id"] for f in rest]}))
        assert api(A2).get("/install/security")["findings"] == []
        # md5 is gone everywhere; both D2 sign with the sha256 key BIND accepts.
        for host in (A1, A2):
            d2 = json.loads(sudo_cat(host, "/etc/kea/kea-dhcp-ddns.conf"))["DhcpDdns"]
            assert [(k["name"], k["algorithm"].upper()) for k in d2["tsig-keys"]] == [
                ("kea-ddns-sha256", "HMAC-SHA256")
            ]
        assert "hmac-md5" not in ssh(A1, "sudo named-checkconf -p")[1]
        # A real lease renewal updates the DNS with the new key.
        renew_client()

        def ddns_ok() -> bool:
            log = ssh(A1, f"sudo journalctl -u kea-dhcp-ddns-server --since @{since} --no-pager")[1]
            return "DHCP_DDNS_ADD_SUCCEEDED" in log or "DHCP_DDNS_REMOVE_SUCCEEDED" in log

        wait_for("DDNS update signed with the new key", ddns_ok, timeout=90)
        assert "BADKEY" not in ssh(A1, f"sudo journalctl -u named --since @{since} --no-pager")[1]

    def test_06_record_through_ns2_read_on_ns1(self):
        change = {"op": "add", "target": "www/A", "after": {"ttl": 300, "rdata": ["10.99.0.80"]}}
        plan = api(A2).post("/dns/zones/example.lan/records/plan", {"changes": [change]})
        assert plan["target_node_ids"] == [node_id(A1)]  # the primary's named takes the UPDATE
        result = api(A2).apply(plan)
        assert result["state"] == "applied", result
        records = api(A1).get("/dns/zones/example.lan/records?name=www")["items"]
        assert records == [{"name": "www.example.lan.", "rtype": "A", "ttl": 300, "rdata": ["10.99.0.80"]}]
        wait_for("the secondary has www", lambda: dig(A2, "www.example.lan") == "10.99.0.80")
        audit = api(A1).get("/audit?action=dns.rrset")["items"]
        assert any(e.get("plan_id") == plan["id"] for e in audit)

    def test_07_host_joins_a_real_lease(self):
        _, mac = client_nic()
        body = {
            "hostname": "labhost",
            "ip": "10.99.1.50",
            "mac": mac,
            "zone": "example.lan",
            "reverse_zone": "1.99.10.in-addr.arpa",
            "reservation": True,
            "subnet_id": 1,
        }
        plan = api(A1).post("/hosts/plan", body)
        assert sorted(plan["target_node_ids"]) == sorted([node_id(A1), node_id(A2)])
        result = api(A1).apply(plan)
        assert result["state"] == "applied", result
        # Both Kea of the HA pair carry the reservation (config-set and config-write on Kea 2.6).
        for address in (A1, A2):
            res = api(address).get("/dhcp/v4/reservations?subnet_id=1")["items"]
            assert any(r["identifier"] == mac and r["ip_address"] == "10.99.1.50" for r in res), address
            conf = sudo_cat(address, "/etc/kea/kea-dhcp4.conf")
            assert "10.99.1.50" in conf
        renew_client()
        wait_for("lab-client gets its reserved address", lambda: client_address() == "10.99.1.50", timeout=90)

        def joined() -> dict | None:
            hosts = api(A1).get("/hosts?q=labhost")["items"]
            host = hosts[0] if hosts else None
            if host and host["lease"] and host["lease"]["ip_address"] == "10.99.1.50":
                return host
            return None

        host = wait_for("the hosts view joins the lease", joined, timeout=60)
        assert host["reservation"]["identifier"] == mac
        assert {(r["name"], r["rtype"]) for r in host["records"]} >= {
            ("labhost.example.lan.", "A"),
            ("50.1.99.10.in-addr.arpa.", "PTR"),
        }

    def test_08_kea_killed_on_ns1_raises_ha_alert(self):
        settings = {"collector": {"poll_seconds": 10, "peer_poll_seconds": 10}}
        api(A1).call("PUT", "/admin/settings", settings)
        wait_for(
            "settings replicated",
            lambda: api(A2).get("/admin/settings")["collector"]["poll_seconds"] == 10,
        )
        restart_collectors()
        ssh(A1, "sudo systemctl kill -s KILL kea-dhcp4-server")
        alert = wait_for(
            "HA partner-down alert on ns2",
            lambda: open_alerts(A2, "ha_partner_down"),
            timeout=180,
            interval=5,
        )
        assert alert[0]["engine"] == "kea4" and "partner-down" in alert[0]["title"]
        wait_for("kea4 down on ns1", lambda: open_alerts(A1, "daemon_down"), timeout=120, interval=5)
        ha2 = next(h for h in api(A2).get("/dhcp/v4/ha")["items"] if h["server_name"] == "ns2")
        assert ha2["state"] == "partner-down"
        # Back to normal: the primary syncs its leases from ns2 and both return to hot-standby.
        ssh(A1, "sudo systemctl start kea-dhcp4-server")
        wait_for(
            "hot-standby again",
            lambda: kea_command(A1, "ha-heartbeat")["arguments"]["state"] == "hot-standby",
            timeout=240,
            interval=5,
        )
        wait_for("HA alert resolved", lambda: not open_alerts(A2, "ha_partner_down"), timeout=180, interval=5)

    def test_09_ns2_stopped_then_catches_up(self):
        ssh(A2, "sudo systemctl stop pelagos pelagos-collector")
        wait_for("ns2 offline on ns1", lambda: open_alerts(A1, "peer_offline"), timeout=180, interval=5)
        # Writes while ns2 is away: a setting (cluster.toml) and a record (audit log).
        api(A1).call("PUT", "/admin/settings", {"alerts_pool_warning_percent": 81})
        change = {"op": "add", "target": "away/A", "after": {"ttl": 300, "rdata": ["10.99.0.81"]}}
        plan = api(A1).post("/dns/zones/example.lan/records/plan", {"changes": [change]})
        assert api(A1).apply(plan)["state"] == "applied"
        own = next(n for n in api(A1).get("/nodes")["items"] if n["is_self"])
        ssh(A2, "sudo systemctl start pelagos pelagos-collector")

        def caught_up() -> bool:
            me = next(n for n in api(A2).get("/nodes")["items"] if n["is_self"])
            return me["config_version"] >= own["config_version"] and me["audit_count"] >= own["audit_count"]

        wait_for("ns2 catches up", caught_up, timeout=180, interval=5)
        assert api(A2).get("/admin/settings")["alerts_pool_warning_percent"] == 81
        audit = api(A2).get("/audit?action=dns.rrset")["items"]
        assert any(e.get("plan_id") == plan["id"] for e in audit)
        wait_for("peer back online", lambda: not open_alerts(A1, "peer_offline"), timeout=180, interval=5)

    def test_10_demo_state(self):
        api(A1).call(
            "PUT",
            "/admin/settings",
            {"alerts_pool_warning_percent": 80, "collector": {"poll_seconds": 60, "peer_poll_seconds": 30}},
        )
        wait_for(
            "settings replicated",
            lambda: api(A2).get("/admin/settings")["collector"]["poll_seconds"] == 60,
        )
        restart_collectors()
        for address in (A1, A2):
            assert api(address).get("/nodes/replication")["state"] == "ready"
            health = Api(address).get("/health")
            assert health["status"] == "ok" and health["replication"] == "ready"
