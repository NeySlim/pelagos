# SPDX-License-Identifier: Apache-2.0
"""Three nodes end to end: lab-ns1 and lab-ns2 as the Kea HA pair and the BIND primary and
secondary, lab-rpm (Rocky 10, Kea 3.0 and BIND 9.18 from Rocky) as a Kea HA backup server and a
second BIND secondary, all three Pelagos nodes replicating with each other.

scripts/lab/provision.sh three builds the legacy setup (the pair's peer list and zone ACLs name
ns3). Then: the deb on the pair and the rpm on lab-rpm, ns2 enrolled from ns1 with the CA key,
ns3 enrolled from ns2, three imports, replication across the three, a record plan reaching both
secondaries, a reservation on the three Kea servers, a lease of lab-client copied to the backup,
HA maintenance of the pair with the backup unaffected, a zone created with two secondaries and
its secondaries edited, then ns3 taken out of HA and of the zones and removed from the cluster.
"""

from __future__ import annotations

import json
import time

import pytest

from tests.lab.labkit import (
    CLIENT,
    NS1,
    NS2,
    RPM,
    Api,
    ApiError,
    deb_package,
    rollback,
    rpm_package,
    run_script,
    scp,
    ssh,
    sudo_cat,
    wait_for,
)

pytestmark = pytest.mark.lab

A1, A2, A3, AC = NS1[1], NS2[1], RPM[1], CLIENT[1]
DHCP_NET = "10.99.1."
STATE: dict[str, object] = {}
ZONE = "three.example.lan"


def api(address: str) -> Api:
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=120)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


def node_id(address: str) -> str:
    key = f"id:{address}"
    if key not in STATE:
        STATE[key] = api(address).get("/nodes/self")["peer"]["id"]
    return STATE[key]  # type: ignore[return-value]


def kea_command(host: str, command: str, arguments: dict | None = None) -> dict:
    body = {"command": command, **({"arguments": arguments} if arguments else {})}
    out = ssh(host, f"echo '{json.dumps(body)}' | sudo socat - UNIX-CONNECT:/run/kea/kea4-ctrl-socket")[1]
    return json.loads(out)


def ha_state(host: str) -> str | None:
    ha = kea_command(host, "status-get").get("arguments", {}).get("high-availability") or []
    return ha[0]["ha-servers"]["local"]["state"] if ha else None


def dig(host: str, name: str, rtype: str = "A") -> str:
    return ssh(host, f"dig +short @127.0.0.1 {name} {rtype}")[1].strip()


def client_nic() -> tuple[str, str]:
    nic = ssh(AC, "ip -o link show | awk -F': ' '$2 != \"lo\" && $2 != \"eth0\" {print $2; exit}'")[1].strip()
    return nic, ssh(AC, f"cat /sys/class/net/{nic}/address")[1].strip()


def client_address() -> str | None:
    nic, _ = client_nic()
    for word in ssh(AC, f"ip -4 -o addr show dev {nic}")[1].split():
        if word.startswith(DHCP_NET):
            return word.split("/")[0]
    return None


def renew_client() -> None:
    nic, _ = client_nic()
    ssh(AC, f"sudo networkctl down {nic}; sleep 1; sudo networkctl up {nic}")


def open_alerts(address: str, kind: str) -> list[dict]:
    return api(address).get(f"/alerts?state=open&kind={kind}")["items"]


class TestThreeNodes:
    def test_00_rollback_and_provision(self):
        rollback("lab-ns1", "lab-ns2", "lab-rpm", "lab-client")
        out = run_script("provision.sh", "three", timeout=2400)
        assert "HA: hot-standby" in out and "backup: backup" in out

    def test_01_three_servers_without_pelagos(self):
        assert ssh(A3, "/usr/sbin/kea-dhcp4 -v")[1].startswith("3.")
        assert ha_state(A1) == ha_state(A2) == "hot-standby"
        assert ha_state(A3) == "backup"
        addr = wait_for("lab-client lease", client_address, timeout=90)
        # The active server sends every lease update to the backup too.
        wait_for(
            "the backup holds the client's lease",
            lambda: kea_command(A3, "lease4-get", {"ip-address": addr})["result"] == 0,
            timeout=90,
        )
        for host in (A2, A3):
            wait_for(f"the zones on {host}", lambda h=host: dig(h, "ns1.example.lan") == A1, timeout=90)

    def test_02_install_the_packages(self):
        deb = deb_package()
        for host in (A1, A2):
            scp(host, deb, "/tmp/pelagos.deb")
            ssh(
                host,
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb",
                timeout=900,
            )
        rpm = rpm_package()
        scp(A3, rpm, "/tmp/pelagos.rpm")
        ssh(A3, "sudo dnf install -y -q /tmp/pelagos.rpm", timeout=1800)
        for host in (A1, A2, A3):
            assert ssh(host, "systemctl is-active pelagos-helper.socket")[1].strip() == "active"

    def test_03_init_and_enroll_the_third_node_through_the_second(self):
        from tests.lab.labkit import ADMIN_PASSWORD

        ssh(
            A1,
            f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
            f"--web-url https://{A1}:8443 --replication-url https://{A1}:8444 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )
        # ns2 receives a copy of the CA key, so it can enroll ns3.
        token = api(A1).post("/nodes/enroll-token", {"ca": True})
        ssh(
            A2,
            f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
            f"--ca-fingerprint {token['ca_fingerprint']} --name ns2 "
            f"--replication-url https://{A2}:8444 --web-url https://{A2}:8443 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )
        wait_for("ns2 serves its API", lambda: api(A2).get("/nodes/self"), timeout=120)
        token = api(A2).post("/nodes/enroll-token", {})
        assert token["url"] == f"https://{A2}:8444"
        ssh(
            A3,
            "if systemctl is-active -q firewalld; then sudo firewall-cmd -q --add-port=8443/tcp "
            "--add-port=8444/tcp; fi; "
            f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
            f"--ca-fingerprint {token['ca_fingerprint']} --name ns3 "
            f"--replication-url https://{A3}:8444 --web-url https://{A3}:8443 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )

        def all_online(address: str) -> bool:
            nodes = api(address).get("/nodes")["items"]
            return sorted(n["peer"]["name"] for n in nodes) == ["ns1", "ns2", "ns3"] and all(
                n["status"] == "online" for n in nodes
            )

        for address in (A1, A2, A3):
            wait_for(f"three nodes online seen from {address}", lambda a=address: all_online(a), timeout=180)
        for address in (A1, A2, A3):
            peers = api(address).get("/nodes/replication")["peers"]
            assert len(peers) == 2 and all(p["reachable"] for p in peers), (address, peers)

    def test_04_import_the_three(self):
        engines = {A1: ["bind", "kea4", "d2"], A2: ["bind", "kea4", "d2"], A3: ["bind", "kea4"]}
        for address, wanted in engines.items():
            plan = api(address).post("/install/import/plan", {"engines": wanted})
            job = api(address).apply(plan, timeout=900)
            verify = next(s for s in job["steps"] if s["name"] == "import/verify")["output"]
            assert "kea4.unchanged=ok" in verify, verify

        def relationship() -> dict | None:
            rels = api(A1).get("/dhcp/v4/ha").get("relationships") or []
            if not rels:
                return None
            rel = rels[0]
            by = {s["name"]: s for s in rel["servers"]}
            ready = (
                by.get("ns3", {}).get("state") == "backup" and by.get("ns1", {}).get("state") == "hot-standby"
            )
            return rel if ready and all(s["node_id"] for s in rel["servers"]) else None

        rel = wait_for("the relationship with its backup", relationship, timeout=300, interval=5)
        assert rel["mode"] == "hot-standby" and rel["backups"] == ["ns3"]
        assert {s["name"]: s["node_name"] for s in rel["servers"]} == {
            "ns1": "ns1",
            "ns2": "ns2",
            "ns3": "ns3",
        }

    def test_05_security_plans(self):
        """The pair's md5 key and transfers, as on the reference pair; ns3 reads its copies with ddi-read."""
        findings = api(A1).get("/install/security")["findings"]
        plan = api(A1).post("/install/security/plan", {"finding_ids": [f["id"] for f in findings]})
        api(A1).apply(plan, timeout=900)
        for address in (A2, A3):
            rest = api(address).get("/install/security")["findings"]
            if rest:
                api(address).apply(
                    api(address).post("/install/security/plan", {"finding_ids": [f["id"] for f in rest]})
                )
            assert api(address).get("/install/security")["findings"] == [], address

    def test_06_replication_across_three(self):
        api(A3).call("PUT", "/admin/settings", {"alerts_pool_warning_percent": 79})
        for address in (A1, A2):
            wait_for(
                f"the setting written on ns3 reaches {address}",
                lambda a=address: api(a).get("/admin/settings")["alerts_pool_warning_percent"] == 79,
                timeout=60,
            )

        def same_heads() -> bool:
            nodes = api(A1).get("/nodes")["items"]
            return len({(n["config_version"], n["audit_count"]) for n in nodes}) == 1

        wait_for("the three nodes agree", same_heads, timeout=120, interval=5)

    def test_07_record_plan_reaches_both_secondaries(self):
        change = {"op": "add", "target": "three/A", "after": {"ttl": 300, "rdata": ["10.99.0.90"]}}
        plan = api(A3).post("/dns/zones/example.lan/records/plan", {"changes": [change]})
        assert plan["target_node_ids"] == [node_id(A1)]
        assert api(A3).apply(plan)["state"] == "applied"
        for host in (A2, A3):
            wait_for(
                f"{host} transfers the record", lambda h=host: dig(h, "three.example.lan") == "10.99.0.90"
            )

    def test_08_reservation_on_the_three_kea_servers(self):
        after = {
            "subnet_id": 1,
            "id_type": "hw-address",
            "identifier": "02:00:00:00:13:13",
            "ip_address": "10.99.1.70",
        }
        plan = api(A1).post(
            "/dhcp/v4/reservations/plan", {"change": {"op": "add", "target": "", "after": after}}
        )
        assert sorted(plan["target_node_ids"]) == sorted(node_id(a) for a in (A1, A2, A3))
        result = api(A1).apply(plan)
        assert result["state"] == "applied" and len(result["results"]) == 3, result
        for address in (A1, A2, A3):
            assert "10.99.1.70" in sudo_cat(address, "/etc/kea/kea-dhcp4.conf"), address
            res = api(A1).get(f"/dhcp/v4/reservations?subnet_id=1&node_id={node_id(address)}")["items"]
            assert any(r["ip_address"] == "10.99.1.70" for r in res), address

    def test_09_a_lease_of_the_client_reaches_the_backup(self):
        renew_client()
        addr = wait_for("lab-client lease", client_address, timeout=90)

        def on_backup() -> bool:
            copies = api(A1).get(f"/dhcp/v4/leases/{addr}")["items"]
            return node_id(A3) in {c["node_id"] for c in copies}

        wait_for("the lease read on the backup through the API", on_backup, timeout=120, interval=5)

    def test_10_maintenance_of_the_pair_leaves_the_backup(self):
        with pytest.raises(ApiError) as err:
            api(A3).post("/dhcp/v4/ha/maintenance/plan", {"action": "start", "node_id": node_id(A3)})
        assert err.value.status == 400
        plan = api(A3).post("/dhcp/v4/ha/maintenance/plan", {"action": "start", "node_id": node_id(A2)})
        assert plan["target_node_ids"] == [node_id(A1)]
        assert api(A3).apply(plan)["state"] == "applied"
        wait_for("ns2 in maintenance", lambda: ha_state(A2) == "in-maintenance", timeout=60)
        assert ha_state(A1) == "partner-in-maintenance" and ha_state(A3) == "backup"
        cancel = api(A1).post("/dhcp/v4/ha/maintenance/plan", {"action": "cancel", "node_id": node_id(A2)})
        assert api(A1).apply(cancel)["state"] == "applied"
        wait_for(
            "the pair back to hot-standby", lambda: ha_state(A1) == ha_state(A2) == "hot-standby", timeout=180
        )
        assert ha_state(A3) == "backup"
        assert not open_alerts(A1, "ha_backup_out_of_sync")

    def test_11_a_zone_with_two_secondaries(self):
        change = {
            "op": "add",
            "target": f"_default/{ZONE}",
            "after": {"kind": "primary", "ns": ["ns1.example.lan."]},
        }
        plan = api(A1).post("/dns/zones/plan", {"change": change, "node_ids": [node_id(A2), node_id(A3)]})
        assert plan["target_node_ids"] == [node_id(A1), node_id(A2), node_id(A3)]
        assert api(A1).apply(plan)["state"] == "applied"
        rec = {"op": "add", "target": "www/A", "after": {"ttl": 60, "rdata": ["10.99.0.91"]}}
        assert (
            api(A1).apply(api(A1).post(f"/dns/zones/{ZONE}/records/plan", {"changes": [rec]}))["state"]
            == "applied"
        )
        for host in (A2, A3):
            wait_for(
                f"{host} serves {ZONE}", lambda h=host: dig(h, f"www.{ZONE}") == "10.99.0.91", timeout=90
            )
        detail = api(A1).get(f"/dns/zones/{ZONE}")
        assert {k: v["kind"] for k, v in detail["copies"].items()} == {
            node_id(A1): "primary",
            node_id(A2): "secondary",
            node_id(A3): "secondary",
        }
        # ns3 leaves the zone, then comes back.
        drop = api(A1).post(f"/dns/zones/{ZONE}/secondaries/plan", {"node_ids": [node_id(A2)]})
        assert drop["requires_confirmation"]
        assert api(A1).apply(drop)["state"] == "applied"
        wait_for(f"{ZONE} gone from ns3", lambda: dig(A3, f"www.{ZONE}") == "", timeout=60)
        back = api(A1).post(f"/dns/zones/{ZONE}/secondaries/plan", {"node_ids": [node_id(A2), node_id(A3)]})
        assert api(A1).apply(back)["state"] == "applied"
        wait_for(f"{ZONE} back on ns3", lambda: dig(A3, f"www.{ZONE}") == "10.99.0.91", timeout=90)

    def test_12_remove_the_third_node(self):
        # Out of the HA relationship first: the pair keeps its roles, ns3 loses its hook.
        rel = api(A1).get("/dhcp/v4/ha")["relationships"][0]
        servers = [
            {k: s[k] for k in ("name", "url", "role")} | {"node_id": s["node_id"]}
            for s in rel["servers"]
            if s["name"] != "ns3"
        ]
        plan = api(A1).post("/dhcp/v4/ha/setup/plan", {"mode": rel["mode"], "servers": servers})
        assert api(A1).apply(plan)["state"] == "applied"
        remove = api(A1).post("/dhcp/v4/ha/setup/plan", {"remove": True, "node_ids": [node_id(A3)]})
        assert api(A1).apply(remove)["state"] == "applied"
        wait_for(
            "the pair without its backup", lambda: ha_state(A1) == ha_state(A2) == "hot-standby", timeout=240
        )
        assert ha_state(A3) is None
        drop = api(A1).post(f"/dns/zones/{ZONE}/secondaries/plan", {"node_ids": [node_id(A2)]})
        assert api(A1).apply(drop)["state"] == "applied"
        ns3 = node_id(A3)
        api(A1).call("DELETE", f"/nodes/{ns3}")

        def gone(address: str) -> bool:
            names = sorted(n["peer"]["name"] for n in api(address).get("/nodes")["items"])
            peers = [p["node_id"] for p in api(address).get("/nodes/replication")["peers"]]
            return names == ["ns1", "ns2"] and ns3 not in peers

        for address in (A1, A2):
            wait_for(f"ns3 gone on {address}", lambda a=address: gone(a), timeout=180, interval=5)
        wait_for(
            "ns3 isolated",
            lambda: Api(A3).get("/health").get("replication") == "isolated",
            timeout=300,
            interval=10,
        )
        time.sleep(1)
        assert not open_alerts(A1, "peer_offline")
