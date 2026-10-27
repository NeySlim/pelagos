# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501
"""Node by node upgrade of a production-like two-node cluster, and the way back.

lab-up1 (amd64) and lab-up3 (arm64, Debian 13 under qemu-system on lab-up2, scripts/lab/emul-node.sh)
run BIND and Kea 2.6 HA from Debian (scripts/lab/provision.sh pair), Pelagos from the packages of an
older commit (PELAGOS_UPGRADE_OLD, default 2b86817) with the web and replication ports moved to
9443/9444 and query_address set to the node address. Dynamic zones, the security plan (update-policy,
dual TSIG key switch), a reservation, leases, custom settings and audit entries exist before the
upgrade. Then ns2 (arm64), ns1 (amd64) go to the current packages while the other node still runs the
old ones, and both go back. Checked at each step: files migrated, no audit entry lost, replication
between different versions, the engines untouched.

The four debs come from $PELAGOS_UPGRADE_DEBS/{old,new}/pelagos_*_{amd64,arm64}.deb (default
build/upgrade); the test is skipped without them. The hosts are not rolled back: the test cleans them.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
from pathlib import Path

import pytest

from tests.lab.labkit import REPO, SCRIPTS, Api, fixable, left, scp, ssh, sudo_cat, wait_for

A1, A2 = "10.99.0.24", "10.99.0.26"  # lab-up1 (amd64), lab-up3 (arm64)
ARCH = {A1: "amd64", A2: "arm64"}
WEB, REPL = 9443, 9444
DEBS = Path(os.environ.get("PELAGOS_UPGRADE_DEBS", REPO / "build" / "upgrade"))
PASSWORD = "Upgrade-Admin-Password-1"
STATE: dict[str, object] = {}
AUDIT = "/var/lib/pelagos/audit/audit.jsonl"
CUSTOM = {"alerts_pool_warning_percent": 70, "alerts_d2_error_rate": 0.1, "session_ttl_seconds": 7200}


def _ready() -> bool:
    """The four debs are there and both hosts answer ssh (lab-up2 starts the arm64 guest)."""
    if not all(
        list((DEBS / w).glob(f"pelagos_*_{a}.deb")) for w in ("old", "new") for a in ("amd64", "arm64")
    ):
        return False
    for host in (A1, A2):
        try:
            socket.create_connection((host, 22), timeout=3).close()
        except OSError:
            return False
    return True


pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(
        not _ready(), reason="needs the upgrade debs ($PELAGOS_UPGRADE_DEBS) and lab-up1, lab-up3"
    ),
]


def deb(which: str, address: str) -> Path:
    found = sorted((DEBS / which).glob(f"pelagos_*_{ARCH[address]}.deb"))
    if not found:
        pytest.skip(f"no {which} {ARCH[address]} deb in {DEBS / which}")
    return found[-1]


def api(address: str) -> Api:
    client = Api(address, port=WEB)
    wait_for(f"{address} login", lambda: client.login("admin", PASSWORD), timeout=180)
    return client


def audit_lines(address: str) -> dict[str, str]:
    """Audit lines of the node by sha256, so a lost or rewritten entry shows."""
    text = sudo_cat(address, AUDIT)
    return {hashlib.sha256(line.encode()).hexdigest(): line for line in text.splitlines() if line.strip()}


def install(address: str, path: Path, downgrade: bool = False) -> None:
    scp(address, path, "/tmp/pelagos-under-test.deb")
    flag = "--allow-downgrades " if downgrade else ""
    ssh(
        address,
        f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q {flag}/tmp/pelagos-under-test.deb 2>&1 | tail -5",
        timeout=900,
    )


def version(address: str) -> str:
    """The installed package version (the API reports the project version, the same for every build)."""
    return ssh(address, "dpkg-query -W -f '${Version}' pelagos")[1].strip()


def healthy(address: str) -> bool:
    return ssh(address, "systemctl is-active pelagos pelagos-collector", check=False)[1].split() == [
        "active",
        "active",
    ]


def nodes_online(address: str) -> bool:
    nodes = api(address).get("/nodes")["items"]
    return len(nodes) == 2 and all(n["status"] == "online" for n in nodes)


def dig(address: str, name: str) -> str:
    return ssh(address, f"dig +short @127.0.0.1 {name} A")[1].strip()


def add_record(via: str, name: str, ip: str) -> dict:
    client = api(via)
    change = {"op": "add", "target": f"{name}/A", "after": {"ttl": 300, "rdata": [ip]}}
    plan = client.post("/dns/zones/example.lan/records/plan", {"changes": [change]})
    result = client.apply(plan)
    assert result["state"] == "applied", result
    return plan


def converged_audit(a: str, b: str) -> bool:
    return audit_lines(a).keys() == audit_lines(b).keys()


def cluster_toml(address: str) -> str:
    return sudo_cat(address, "/var/lib/pelagos/cluster.toml")


def entries(address: str) -> str:
    """cluster.toml without its header: version and writer differ per node, the entries must not."""
    return re.sub(r"^(version|updated_at|updated_by) = .*\n", "", cluster_toml(address), count=3, flags=re.M)


def lose_nothing(address: str, before: dict[str, str]) -> None:
    now = audit_lines(address)
    missing = [line for h, line in before.items() if h not in now]
    assert not missing, f"{len(missing)} audit entries lost on {address}: {missing[:2]}"


class TestUpgrade:
    def test_00_clean_hosts_and_provision_the_legacy_pair(self):
        for address in (A1, A2):
            deb("old", address)
            deb("new", address)
            ssh(
                address,
                "sudo systemctl stop pelagos pelagos-collector 2>/dev/null; "
                "sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -q pelagos >/dev/null 2>&1; "
                "sudo rm -rf /etc/pelagos /var/lib/pelagos /var/lib/pelagos-helper; true",
            )
        env = {
            "PROV_NS1": A1,
            "PROV_NS2": A2,
            "PROV_NS1_IP": A1,
            "PROV_NS2_IP": A2,
            "PROV_IFACE": "eth0",
        }
        res = subprocess.run(
            [str(SCRIPTS / "provision.sh"), "pair", "--force"],
            capture_output=True,
            text=True,
            timeout=1800,
            env={**os.environ, **env},
            check=False,
        )
        assert res.returncode == 0 and "HA: hot-standby" in res.stdout, res.stdout + res.stderr
        assert ssh(A2, "dpkg --print-architecture")[1].strip() == "arm64"
        assert ssh(A1, "/usr/sbin/kea-dhcp4 -V")[1].startswith("2.6.3")

    def test_01_install_the_old_packages_with_production_ports(self):
        for address in (A1, A2):
            install(address, deb("old", address))
        ssh(
            A1,
            f"sudo PELAGOS_ADMIN_PASSWORD={PASSWORD} pelagos init --name ns1 "
            f"--web-url https://{A1}:{WEB} --replication-url https://{A1}:{REPL}",
        )
        for address in (A1,):
            self._ports(address)
        ssh(A1, "sudo systemctl start pelagos pelagos-collector")
        wait_for("ns1 up", lambda: api(A1).get("/nodes/self"), timeout=120)
        token = api(A1).post("/nodes/enroll-token", {})
        ssh(
            A2,
            f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
            f"--ca-fingerprint {token['ca_fingerprint']} --name ns2 "
            f"--replication-url https://{A2}:{REPL} --web-url https://{A2}:{WEB}",
            timeout=600,
        )
        self._ports(A2)
        ssh(A2, "sudo systemctl start pelagos pelagos-collector")
        wait_for("both online", lambda: nodes_online(A1), timeout=240)
        assert ".2b86817" in version(A1) and ".2b86817" in version(A2)

    @staticmethod
    def _ports(address: str) -> None:
        ssh(
            address,
            f"sudo sed -i -e 's/^web_listen = .*/web_listen = \"0.0.0.0:{WEB}\"/' "
            f"-e 's/^replication_listen = .*/replication_listen = \"0.0.0.0:{REPL}\"/' /etc/pelagos/node.toml",
        )

    def test_02_import_and_security_plan(self):
        for address in (A1, A2):
            client = api(address)
            plan = client.post("/install/import/plan", {"engines": ["bind", "kea4", "d2"]})
            assert not plan.get("error"), plan
            client.apply(plan)
            # query_address is the node's LAN address, as in production.
            ssh(
                address,
                f"sudo sed -i 's/^query_address = .*/query_address = \"{address}\"/' /etc/pelagos/node.toml; "
                "sudo systemctl restart pelagos pelagos-collector",
            )
            assert f'query_address = "{address}"' in sudo_cat(address, "/etc/pelagos/node.toml")

        def servers() -> bool:
            items = api(A1).get("/dhcp/v4/servers")["items"]
            return len(items) == 2 and all(s.get("capabilities") for s in items)

        wait_for("both Kea known", servers, timeout=180)
        client = api(A1)
        findings = client.get("/install/security")["findings"]
        assert {f["kind"] for f in findings} >= {"weak_shared_kea_key", "update_without_admin_key"}
        plan = client.post("/install/security/plan", {"finding_ids": fixable(findings)})
        client.apply(plan, timeout=900)
        rest = fixable(api(A2).get("/install/security")["findings"])
        if rest:
            api(A2).apply(api(A2).post("/install/security/plan", {"finding_ids": rest}))
        for address in (A1, A2):
            assert left(api(address).get("/install/security")["findings"]) == []
        policy = ssh(A1, "sudo grep -rh update-policy /etc/bind /var/lib/bind 2>/dev/null | head -3")[1]
        assert "update-policy" in policy or "ddi-admin" in ssh(A1, "sudo named-checkconf -p")[1]

    def test_03_production_like_data(self):
        client = api(A1)
        client.call("PUT", "/admin/settings", CUSTOM)
        for i in range(5):
            add_record(A2 if i % 2 else A1, f"app{i}", f"10.99.0.{150 + i}")
        # A reservation by plan (config-set on Kea 2.6) and a few leases.
        body = {
            "hostname": "upgrade-host",
            "ip": "10.99.1.50",
            "mac": "02:00:00:aa:bb:01",
            "zone": "example.lan",
            "reverse_zone": "1.99.10.in-addr.arpa",
            "reservation": True,
            "subnet_id": 1,
        }
        client.apply(client.post("/hosts/plan", body))
        for i in range(3):
            cmd = {
                "command": "lease4-add",
                "arguments": {
                    "ip-address": f"10.99.1.{110 + i}",
                    "hw-address": f"02:00:00:cc:dd:0{i}",
                    "valid-lft": 86400,
                },
            }
            ssh(A1, f"echo '{json.dumps(cmd)}' | sudo socat - UNIX-CONNECT:/run/kea/kea4-ctrl-socket")
        wait_for("audit converged", lambda: converged_audit(A1, A2), timeout=120)
        wait_for("records on the secondary", lambda: dig(A2, "app4.example.lan") == "10.99.0.154", timeout=90)
        STATE["audit"] = audit_lines(A1)
        STATE["cluster_old"] = cluster_toml(A1)
        STATE["node_old"] = {a: sudo_cat(a, "/etc/pelagos/node.toml") for a in (A1, A2)}
        STATE["zone"] = ssh(A1, "dig +noall +answer @127.0.0.1 example.lan AXFR | sort")[1]
        assert len(STATE["audit"]) >= 10  # type: ignore[arg-type]
        assert "alerts_pool_warning_percent = 70" in STATE["cluster_old"]  # type: ignore[operator]

    def test_04_upgrade_ns2_arm64_first(self):
        before = STATE["audit"]
        install(A2, deb("new", A2))
        wait_for("ns2 services", lambda: healthy(A2), timeout=300)
        wait_for("ns2 answers", lambda: api(A2).get("/nodes/self"), timeout=600)
        STATE["new_version"] = version(A2)
        assert version(A2) != version(A1)
        # node.toml: same identity and ports, still readable.
        node = sudo_cat(A2, "/etc/pelagos/node.toml")
        old = STATE["node_old"][A2]  # type: ignore[index]
        for key in ("id", "web_listen", "replication_listen", "query_address", "replication_url"):
            line = next(x for x in old.splitlines() if x.startswith(f"{key} ="))
            assert line in node, (key, line)
        lose_nothing(A2, before)  # type: ignore[arg-type]
        wait_for("both online across versions", lambda: nodes_online(A1), timeout=240)

    def test_05_replication_between_two_versions(self):
        plan_old = add_record(A1, "mixed-from-old", "10.99.0.161")
        wait_for(
            "new node sees the old node's record",
            lambda: dig(A2, "mixed-from-old.example.lan") == "10.99.0.161",
            timeout=120,
        )
        plan_new = add_record(A2, "mixed-from-new", "10.99.0.162")
        wait_for(
            "old node sees the new node's record",
            lambda: dig(A1, "mixed-from-new.example.lan") == "10.99.0.162",
            timeout=120,
        )

        def audited(address: str) -> bool:
            text = sudo_cat(address, AUDIT)
            return plan_old["id"] in text and plan_new["id"] in text

        for address in (A1, A2):
            wait_for(f"audit of both plans on {address}", lambda a=address: audited(a), timeout=180)
        assert dig(A1, "app0.example.lan") == dig(A2, "app0.example.lan") == "10.99.0.150"
        # The old node keeps working next to the new one: its settings view and Kea read.
        assert api(A1).get("/dhcp/v4/subnets")["items"]
        assert api(A2).get("/dhcp/v4/subnets")["items"]

    def test_06_upgrade_ns1_amd64(self):
        install(A1, deb("new", A1))
        wait_for("ns1 services", lambda: healthy(A1), timeout=180)
        wait_for("ns1 answers", lambda: api(A1).get("/nodes/self"), timeout=300)
        assert version(A1) == version(A2)
        wait_for("both online on one version", lambda: nodes_online(A1), timeout=240)
        for address in (A1, A2):
            lose_nothing(address, STATE["audit"])  # type: ignore[arg-type]

        def same_cluster() -> bool:
            return entries(A1) == entries(A2)

        wait_for("cluster.toml identical", same_cluster, timeout=240)

    def test_07_settings_migrated(self):
        text = cluster_toml(A1)
        assert "[settings.checks]" in text, text[:2000]
        assert "pool_warning_percent = 70" in text
        assert "d2_error_percent = 10" in text
        assert re.search(r"session\w*\s*=\s*7200", text)
        migrations = [
            line
            for line in sudo_cat(A1, AUDIT).splitlines()
            if '"op": "migrate"' in line or '"op":"migrate"' in line
        ]
        assert len(migrations) >= 1
        # Not once per node and restart: one migration entry for the cluster.
        assert len(migrations) <= 2, migrations
        legacy = ssh(A1, "sudo pelagos settings --legacy")[1]
        assert "alerts_pool_warning_percent" in legacy and "70" in legacy, legacy

    def test_08_engines_and_data_untouched(self):
        zone = ssh(A1, "dig +noall +answer @127.0.0.1 example.lan AXFR | sort")[1]
        for line in STATE["zone"].splitlines():  # type: ignore[union-attr]
            if " SOA " not in line:
                assert line in zone, line
        for address in (A1, A2):
            assert ssh(address, "sudo named-checkconf && echo ok")[1].strip() == "ok"
            assert (
                ssh(address, "systemctl is-active named kea-dhcp4-server kea-dhcp-ddns-server")[1].split()
                == ["active"] * 3
            )
        ha = {h["server_name"]: h["state"] for h in api(A1).get("/dhcp/v4/ha")["items"]}
        assert set(ha.values()) <= {"hot-standby", "partner-down"}, ha
        res = api(A1).get("/dhcp/v4/reservations?subnet_id=1")["items"]
        assert any(r["ip_address"] == "10.99.1.50" for r in res)

    def test_09_roll_back_ns2_then_ns1(self):
        before = {a: audit_lines(a) for a in (A1, A2)}
        for address in (A2, A1):
            # The series cache of the new release holds alert kinds the old one rejects: drop it
            # (it is rebuilt from the engines) before the old code starts.
            ssh(
                address,
                "sudo systemctl stop pelagos pelagos-collector; sudo sh -c 'rm -f /var/lib/pelagos/series.sqlite*'",
            )
            install(address, deb("old", address), downgrade=True)
            wait_for(f"{address} services", lambda a=address: healthy(a), timeout=300)
            wait_for(f"{address} answers", lambda a=address: api(a).get("/nodes/self"), timeout=600)
            assert version(address) != STATE["new_version"]
            for node in (A1, A2):
                lose_nothing(node, STATE["audit"])  # type: ignore[arg-type]
            if address == A2:
                # The node still on the new release keeps its customised settings while its peer
                # runs the old one, whatever the old one replicates back.
                wait_for("old ns2 online for new ns1", lambda: nodes_online(A1), timeout=240)
                add_record(A2, "half-back", "10.99.0.170")
                wait_for(
                    "record reaches ns1",
                    lambda: dig(A1, "half-back.example.lan") == "10.99.0.170",
                    timeout=120,
                )
                wait_for("config exchanged", lambda: "pool_warning_percent = 70" in entries(A1), timeout=120)
                assert "d2_error_percent = 10" in entries(A1)
        wait_for("both online on the old version", lambda: nodes_online(A1), timeout=240)
        # The old release works again end to end: a record through each node.
        add_record(A1, "back-from-ns1", "10.99.0.171")
        add_record(A2, "back-from-ns2", "10.99.0.172")
        for address in (A1, A2):
            wait_for(
                f"records on {address}",
                lambda a=address: dig(a, "back-from-ns2.example.lan") == "10.99.0.172",
                timeout=120,
            )
            assert before[address].keys() <= audit_lines(address).keys()
            errors = ssh(
                address,
                "sudo journalctl -u pelagos -u pelagos-collector --since '-4min' --no-pager | grep -c ' ERROR '",
                check=False,
            )[1].strip()
            assert errors == "0", ssh(
                address,
                "sudo journalctl -u pelagos-collector --since '-4min' --no-pager | grep -A3 ' ERROR ' | tail -20",
            )[1]
        # Customised values do not come back by themselves: `pelagos settings --legacy` listed them.
        assert api(A1).get("/admin/settings")["alerts_pool_warning_percent"] == 80
