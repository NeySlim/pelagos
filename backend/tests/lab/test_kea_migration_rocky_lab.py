# SPDX-License-Identifier: Apache-2.0
"""The Kea migration on Rocky 10: ISC Kea 2.6 from the `el` repository to ISC 3.2 (batch K7).

lab-k7r (VMID 9180, Rocky 10 from tpl-rocky10, SELinux enforcing), snapshot `isc26`: ISC Kea 2.6.5
(Cloudsmith kea-2-6, el/10) dhcp4 and D2 configured by hand as an administrator would (D2 with a
clear `secret`, sockets by bare name), BIND 9.18 from Rocky with example.lan and its reverse zone
dynamic, no Pelagos. test_00 provisions a fresh clone when the snapshot is missing. The rpm of
this checkout is installed (built on lab-pkg-rpm), the node initialized and imported. A single
node without HA: the outage is the restart. lab-client asks for its address every second
(dhcp_probe.py, INIT-REBOOT) during the migration and the return. Checked: inventory and
analysis on dnf, the dry run, the prepare (target rpms downloaded, the exact 2.6 rpms kept), the
migration to 3.2 (lease kept, no DHCPNAK, DDNS through the converted secret file, no SELinux
denial), then the return to 2.6 with every Kea file and package as before.
`PELAGOS_LAB_ROLLED_BACK=1` skips the rollback (VM restored by the caller).
"""

from __future__ import annotations

import itertools
import json
import os
import time
from pathlib import Path

import pytest

from tests.lab.labkit import (
    ADMIN_PASSWORD,
    Api,
    put,
    rollback,
    rpm_package,
    run_script,
    scp,
    ssh,
    wait_for,
)

pytestmark = pytest.mark.lab

NODE, ADDRESS = "lab-k7r", "10.99.0.80"
CLIENT, IFACE = "lab-client", "ens19"
PROBE = Path(__file__).with_name("dhcp_probe.py")
MAC_LOOP, MAC_AFTER = "02:00:00:00:07:01", "02:00:00:00:07:02"
STATE: dict[str, object] = {}
# Cloudsmith repository definition for ISC Kea 2.6 on EL 10 (read on 2026-10-30).
ISC26_REPO = "https://dl.cloudsmith.io/public/isc/kea-2-6/config.rpm.txt?distro=el&codename=10"
ISC26_VERSION = "2.6.5"
# What the return must give back: Kea files (content, owner, mode, SELinux label), packages, units.
KEA_STATE = (
    'sudo sh -c \'cd / && find etc/kea -printf "%p %y %m %u %g %l\\n" | sort;'
    " find etc/kea -type f -exec sha256sum {} + | sort; ls -Z etc/kea | sort;"
    ' rpm -qa "isc-kea*" "kea*" | sort; systemctl is-active kea-dhcp4 kea-dhcp-ddns || true\''
)
KEA = (
    "sudo python3 -c 'import json,socket,sys;s=socket.socket(socket.AF_UNIX);"
    's.connect("/run/kea/kea4-ctrl-socket");s.sendall(sys.stdin.buffer.read());'
    'b=b""\nwhile True:\n c=s.recv(65536)\n if not c: break\n b+=c\nprint(b.decode())\''
)

DHCP4 = {
    "Dhcp4": {
        "interfaces-config": {"interfaces": ["eth0"]},
        "control-socket": {"socket-type": "unix", "socket-name": "kea4-ctrl-socket"},
        "lease-database": {"type": "memfile", "lfc-interval": 3600},
        "valid-lifetime": 3600,
        "renew-timer": 900,
        "rebind-timer": 1800,
        "hooks-libraries": [
            {"library": "/usr/lib64/kea/hooks/libdhcp_lease_cmds.so"},
            {"library": "/usr/lib64/kea/hooks/libdhcp_stat_cmds.so"},
        ],
        "dhcp-ddns": {"enable-updates": True, "server-ip": "127.0.0.1", "server-port": 53001},
        "ddns-send-updates": True,
        "ddns-override-client-update": True,
        "ddns-replace-client-name": "when-not-present",
        "ddns-qualifying-suffix": "example.lan.",
        "subnet4": [
            {
                "id": 1,
                "subnet": "10.99.2.0/24",
                "interface": "eth0",
                "pools": [{"pool": "10.99.2.100 - 10.99.2.199"}],
                "option-data": [{"name": "domain-name", "data": "example.lan"}],
            }
        ],
        "loggers": [{"name": "kea-dhcp4", "output-options": [{"output": "stdout"}], "severity": "INFO"}],
    }
}


def d2_conf(secret: str) -> dict:
    server = [{"ip-address": "127.0.0.1", "port": 53}]
    return {
        "DhcpDdns": {
            "ip-address": "127.0.0.1",
            "port": 53001,
            "control-socket": {"socket-type": "unix", "socket-name": "kea-ddns-ctrl-socket"},
            "tsig-keys": [{"name": "kea-ddns", "algorithm": "HMAC-SHA256", "secret": secret}],
            "forward-ddns": {
                "ddns-domains": [{"name": "example.lan.", "key-name": "kea-ddns", "dns-servers": server}]
            },
            "reverse-ddns": {
                "ddns-domains": [
                    {"name": "2.99.10.in-addr.arpa.", "key-name": "kea-ddns", "dns-servers": server}
                ]
            },
            "loggers": [
                {"name": "kea-dhcp-ddns", "output-options": [{"output": "stdout"}], "severity": "INFO"}
            ],
        }
    }


ZONES = """
include "/etc/named/kea-ddns.key";
zone "example.lan" IN { type primary; file "dynamic/example.lan.db"; allow-update { key kea-ddns; }; };
zone "2.99.10.in-addr.arpa" IN { type primary; file "dynamic/2.99.10.db"; allow-update { key kea-ddns; }; };
"""
ZONE = """$TTL 300
@ IN SOA ns1.example.lan. hostmaster.example.lan. 1 3600 600 86400 300
@ IN NS ns1.example.lan.
"""


def provision() -> None:
    """ISC Kea 2.6 and BIND from Rocky, configured by hand: the production-like starting point."""
    ssh(
        NODE,
        f'sudo sh -c \'curl -1sLf "{ISC26_REPO}" > /etc/yum.repos.d/isc-kea-2-6.repo && dnf -y -q install'
        f" isc-kea-dhcp4-{ISC26_VERSION} isc-kea-dhcp-ddns-{ISC26_VERSION} isc-kea-hooks-{ISC26_VERSION}"
        " bind bind-utils'",
        timeout=1800,
    )
    secret = ssh(NODE, "tsig-keygen -a hmac-sha256 kea-ddns | awk -F'\"' '/secret/{print $2}'")[1].strip()
    put(NODE, "/etc/named/kea-ddns.key", f'key "kea-ddns" {{ algorithm hmac-sha256; secret "{secret}"; }};\n')
    zone = ZONE + "ns1 IN A 10.99.0.80\n"
    put(NODE, "/var/named/dynamic/example.lan.db", zone)
    put(NODE, "/var/named/dynamic/2.99.10.db", ZONE)
    ssh(
        NODE,
        "sudo sh -c 'chown root:named /etc/named/kea-ddns.key && chmod 640 /etc/named/kea-ddns.key"
        " && chown named:named /var/named/dynamic/*.db && restorecon -R /etc/named /var/named/dynamic'",
    )
    ssh(NODE, "sudo tee -a /etc/named.conf >/dev/null", data=ZONES.encode())
    for name, conf in (("kea-dhcp4.conf", DHCP4), ("kea-dhcp-ddns.conf", d2_conf(secret))):
        put(NODE, f"/etc/kea/{name}", json.dumps(conf, indent=2) + "\n", mode="0640")
        ssh(NODE, f"sudo chown kea:kea /etc/kea/{name} && sudo restorecon /etc/kea/{name}")
    ssh(NODE, "sudo systemctl enable --now named kea-dhcp4 kea-dhcp-ddns")
    ssh(NODE, "sudo firewall-cmd -q --add-service=dhcp --permanent 2>/dev/null; true", check=False)


def api() -> Api:
    if "api" not in STATE:
        client = Api(ADDRESS)
        wait_for(f"{ADDRESS} login", lambda: client.login(), timeout=180)
        STATE["api"] = client
    return STATE["api"]  # type: ignore[return-value]


def kea(command: str, arguments: dict | None = None) -> dict:
    body = {"command": command, **({"arguments": arguments} if arguments else {})}
    return json.loads(ssh(NODE, KEA, data=json.dumps(body).encode())[1])


def kea_version() -> str:
    return ssh(NODE, "sudo /usr/sbin/kea-dhcp4 -v")[1].strip()


def run_job(plan: dict, timeout: float = 1800) -> dict:
    out = api().post(f"/plans/{plan['id']}/apply", {"confirm": True}, timeout=timeout)

    def done() -> dict | None:
        job = api().get(f"/jobs/{out['id']}")
        return job if job["state"] in ("done", "failed") else None

    return wait_for(f"job {out['id']}", done, timeout=timeout, interval=3)


class Probe:
    """INIT-REBOOT for the looped address every second from lab-client, for one scenario."""

    def __init__(self, name: str) -> None:
        self.unit = f"k7-{name}"
        ssh(
            CLIENT,
            f"sudo systemctl stop {self.unit} 2>/dev/null; sudo rm -f /tmp/{self.unit}.log",
            check=False,
        )
        ssh(
            CLIENT,
            f"sudo systemd-run --unit {self.unit} -p StandardOutput=file:/tmp/{self.unit}.log"
            f" python3 /tmp/dhcp_probe.py loop {IFACE} {MAC_LOOP} {STATE['loop_ip']} 3600",
        )
        time.sleep(5)

    def stop(self) -> dict:
        time.sleep(5)
        ssh(CLIENT, f"sudo systemctl stop {self.unit}", check=False)
        lines = [json.loads(x) for x in ssh(CLIENT, f"cat /tmp/{self.unit}.log")[1].splitlines() if x]
        acks = [x["t"] for x in lines if x["result"] == "ack" and x.get("server") == ADDRESS]
        gaps = [b - a for a, b in itertools.pairwise(acks)]
        out = {
            "tries": len(lines),
            "acks": len(acks),
            "naks": sum(1 for x in lines if x["result"] == "nak"),
            "longest_gap": round(max(gaps, default=0.0), 1),
            "last": lines[-1]["result"] if lines else None,
            "addresses": sorted({x["yiaddr"] for x in lines if x.get("yiaddr")}),
        }
        print(f"client during {self.unit}: {json.dumps(out)}")
        return out


def probe_get(mac: str) -> str:
    return ssh(CLIENT, f"sudo python3 /tmp/dhcp_probe.py get {IFACE} {mac}", timeout=120)[1].strip()


class TestKeaMigrationRocky:
    def test_00_node_on_isc_2_6(self):
        if os.environ.get("PELAGOS_LAB_ROLLED_BACK") != "1":
            snapshots = run_script("rollback.sh", NODE, "--list")
            if "isc26" in snapshots:
                rollback(NODE)
        if ssh(NODE, "sudo grep -q 10.99.2.0 /etc/kea/kea-dhcp4.conf", check=False)[0]:
            provision()
        assert ssh(NODE, "getenforce")[1].strip() == "Enforcing"
        assert kea_version().startswith(ISC26_VERSION), kea_version()
        assert ssh(NODE, "systemctl is-active named kea-dhcp4 kea-dhcp-ddns")[1].split() == ["active"] * 3
        assert kea("status-get")["result"] == 0

    def test_01_pelagos_installed_and_imported(self):
        rpm = rpm_package()
        scp(NODE, rpm, "/tmp/pelagos.rpm")
        ssh(NODE, "sudo dnf install -y -q /tmp/pelagos.rpm", timeout=1800)
        ssh(
            NODE,
            f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name k7r "
            f"--web-url https://{ADDRESS}:8443 --replication-url https://{ADDRESS}:8444 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )
        ssh(NODE, "if systemctl is-active -q firewalld; then sudo firewall-cmd -q --add-port=8443/tcp; fi")
        job = api().apply(api().post("/install/import/plan", {"engines": ["kea4", "d2"]}))
        assert job.get("state", "done") == "done", job
        out = api().get("/admin/archives")
        if not any(r.get("kind") == "cluster" for r in out.get("recipients") or []):
            api().post("/admin/archives/identity", {"op": "generate", "password": ADMIN_PASSWORD})
        scp(CLIENT, PROBE, "/tmp/dhcp_probe.py")
        STATE["loop_ip"] = probe_get(MAC_LOOP)
        assert STATE["loop_ip"].startswith("10.99.2."), STATE
        STATE["before"] = ssh(NODE, KEA_STATE)[1]

    def test_02_inventory_and_analysis(self):
        def inventory() -> dict | None:
            out = api().get("/install/kea-migration", timeout=180)
            return out if out["nodes"] and out["nodes"][0].get("engines") else None

        out = wait_for("the inventory", inventory, timeout=120, interval=10)
        [node] = out["nodes"]
        kea4 = node["engines"]["kea4"]
        assert (kea4["version"], kea4["series"], kea4["source"], kea4["package"]) == (
            f"{ISC26_VERSION}",
            "2.6",
            "isc",
            "isc-kea-dhcp4",
        ), kea4
        assert node["distro"]["id"] == "rocky", node["distro"]
        targets = {(t["series"], t["source"]) for t in out["targets"] if t["available"]}
        assert ("3.2", "isc") in targets and not any(s == "backports" for _, s in targets), targets
        report = api().post(
            "/install/kea-migration/analyze", {"series": "3.2", "source": "isc"}, timeout=1200
        )
        assert not report["blocking"], [f for f in report["findings"] if f["severity"] == "blocking"]
        [node_id] = report["node_ids"]
        assert report["roles"][node_id] == "single", report["roles"]
        for engine in ("kea4", "d2"):
            result = report["validation"][node_id][engine]
            assert result["mode"] == "dry_run" and result["ok"], (engine, result)
            assert result["version"].startswith("3.2."), result
        installed = {p["name"]: p["version"] for p in report["packages"][node_id]["install"]}
        assert installed.get("isc-kea-dhcp4", "").startswith("3.2."), installed
        assert {"d2_secret_file"} <= {f["code"] for f in report["findings"]}, report["findings"]
        assert ssh(NODE, KEA_STATE)[1] == STATE["before"]
        STATE["report"] = report["id"]

    def test_03_prepare(self):
        mid = str(STATE["report"])
        plan = api().post(f"/install/kea-migration/{mid}/plan", {"phase": "prepare"})
        job = api().apply(plan, timeout=1800)
        assert job["state"] == "done", job
        mig = api().get(f"/install/kea-migration/{mid}")
        assert mig["state"] == "prepared", mig
        d = f"/var/lib/pelagos/kea-migration/{mid}"
        manifest = json.loads(ssh(NODE, f"sudo cat {d}/manifest.json")[1])
        before = {p["name"]: p["version"] for p in manifest["packages_before"]}
        assert before.get("isc-kea-dhcp4", "").startswith(ISC26_VERSION), before
        for p in manifest["packages_before"]:
            ssh(NODE, f"sudo test -s {d}/packages/previous/{p['file']}")
        for p in manifest["packages_target"]:
            ssh(NODE, f"sudo test -s {p['file']}")
        assert ssh(NODE, KEA_STATE)[1] == STATE["before"]

    def test_04_migration_to_isc_3_2(self):
        mid = str(STATE["report"])
        probe = Probe("migrate")
        plan = api().post(f"/install/kea-migration/{mid}/plan", {"phase": "migrate"})
        started = time.monotonic()
        job = run_job(plan)
        assert job["state"] == "done", json.dumps(job, indent=2)
        print(f"migration: {time.monotonic() - started:.0f} s")
        mig = api().get(f"/install/kea-migration/{mid}")
        assert mig["state"] == "migrated" and mig["rollback_possible"], mig
        print(f"measured outage: {mig['outage_seconds']} s")
        client = probe.stop()
        assert client["naks"] == 0 and client["last"] == "ack", client
        assert client["addresses"] == [STATE["loop_ip"]], client
        assert kea_version().startswith("3.2."), kea_version()
        assert kea("lease4-get", {"ip-address": STATE["loop_ip"]})["result"] == 0
        d2 = json.loads(ssh(NODE, "sudo cat /etc/kea/kea-dhcp-ddns.conf")[1])["DhcpDdns"]
        assert all("secret-file" in k and "secret" not in k for k in d2["tsig-keys"]), d2["tsig-keys"]
        ip = probe_get(MAC_AFTER)
        wait_for(
            "the DDNS name of a new lease",
            lambda: ip in ssh(NODE, "dig +short @127.0.0.1 probe-0702.example.lan A")[1],
            timeout=60,
        )
        denials = ssh(NODE, "sudo ausearch -m AVC -ts today 2>/dev/null | grep -i kea", check=False)[1]
        assert not denials.strip(), denials

    def test_05_return_to_2_6(self):
        mid = str(STATE["report"])
        probe = Probe("return")
        plan = api().post(f"/install/kea-migration/{mid}/plan", {"phase": "rollback"})
        job = run_job(plan)
        assert job["state"] == "done", json.dumps(job, indent=2)
        mig = api().get(f"/install/kea-migration/{mid}")
        assert mig["state"] == "rolled_back" and not mig["rollback_possible"], mig
        client = probe.stop()
        assert client["naks"] == 0 and client["last"] == "ack", client
        assert kea_version().startswith(ISC26_VERSION), kea_version()
        assert kea("lease4-get", {"ip-address": STATE["loop_ip"]})["result"] == 0
        assert ssh(NODE, KEA_STATE)[1] == STATE["before"]
