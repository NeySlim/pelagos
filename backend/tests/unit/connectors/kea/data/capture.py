# SPDX-License-Identifier: Apache-2.0
"""Capture real Kea 3.x control-socket payloads into this directory (run on lab-dev).

    cd backend && PATH=/usr/sbin:$PATH .venv/bin/python tests/unit/connectors/kea/data/capture.py

Starts kea-dhcp4 (with HA, class_cmds and a shared network), kea-dhcp6 and
kea-dhcp-ddns behind a fixture named, records the answers to the commands the
connector relies on, and rewrites the temporary paths to the Debian layout.
The Kea 2.6 payloads next to these files are hand-written from the 2.6 ARM.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[4]))

from tests.fixtures import kea as fx  # noqa: E402
from tests.fixtures import named as named_fx  # noqa: E402
from tests.fixtures.ports import free_port, wait_for  # noqa: E402


def start(name: str, root: Path, config: dict[str, Any], socket_path: Path) -> fx.KeaDaemon:
    """Like fixtures.kea.start_kea but the socket may come from control-sockets (3.x list form)."""
    binary = f"/usr/sbin/{name}"
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o750)
    config_path = root / f"{name}.conf"
    config_path.write_text(json.dumps(config, indent=2))
    env = fx.kea_env(root)
    check = subprocess.run(
        [binary, "-t", str(config_path)], capture_output=True, text=True, env=env, check=False
    )
    if check.returncode != 0:
        raise RuntimeError(f"{name} -t failed:\n{check.stdout}\n{check.stderr}")
    stdout = (root / f"{name}.stdout").open("w")
    proc = subprocess.Popen(
        [binary, "-c", str(config_path)], stdout=stdout, stderr=subprocess.STDOUT, env=env
    )
    daemon = fx.KeaDaemon(
        name=name, root=root, config_path=config_path, socket_path=socket_path, process=proc
    )
    wait_for(lambda: fx.send_command(socket_path, "status-get").get("result") == 0, timeout=20, what=name)
    return daemon


def dhcp4_config(root: Path, hooks: Path, http_port: int, ha_port: int, peer_port: int) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    (root / "ha.user").write_text("ha")
    (root / "ha.pw").write_text("ha-secret")
    (root / "ha.peer").write_text("ha:ha-secret")
    for name in ("ha.user", "ha.pw", "ha.peer"):
        (root / name).chmod(0o600)
    libs = ["lease_cmds", "host_cmds", "subnet_cmds", "stat_cmds", "class_cmds"]
    ha = {
        "this-server-name": "server1",
        "mode": "hot-standby",
        "heartbeat-delay": 10000,
        "max-response-delay": 60000,
        "max-ack-delay": 5000,
        "max-unacked-clients": 5,
        "peers": [
            {
                "name": "server1",
                "url": f"http://127.0.0.1:{ha_port}/",
                "role": "primary",
                "auto-failover": True,
                "basic-auth-password-file": str(root / "ha.peer"),
            },
            {
                "name": "server2",
                "url": f"http://127.0.0.1:{peer_port}/",
                "role": "standby",
                "auto-failover": True,
                "basic-auth-password-file": str(root / "ha.peer"),
            },
        ],
    }
    cfg = fx.dhcp4_config(root, hooks)["Dhcp4"]
    del cfg["control-socket"]
    cfg["control-sockets"] = [
        {"socket-type": "unix", "socket-name": str(root / "kea4.sock")},
        {
            "socket-type": "http",
            "socket-address": "127.0.0.1",
            "socket-port": http_port,
            "authentication": {
                "type": "basic",
                "realm": "kea",
                "clients": [{"user-file": str(root / "ha.user"), "password-file": str(root / "ha.pw")}],
            },
        },
    ]
    cfg["hooks-libraries"] = [{"library": str(hooks / f"libdhcp_{h}.so")} for h in libs] + [
        {"library": str(hooks / "libdhcp_ha.so"), "parameters": {"high-availability": [ha]}}
    ]
    cfg["subnet4"][0]["pools"].append({"pool": "192.0.2.200 - 192.0.2.220", "client-classes": ["voip"]})
    cfg["subnet4"][0]["evaluate-additional-classes"] = ["late"]
    cfg["subnet4"].append(
        {
            "id": 2,
            "subnet": "198.51.100.0/24",
            "pools": [{"pool": "198.51.100.0/25"}],
            "relay": {"ip-addresses": ["198.51.100.254"]},
            "ddns-send-updates": True,
            "ddns-qualifying-suffix": "example.lan.",
            "reservations": [{"client-id": "01:0a:0b:0c:0d:0e:0f", "ip-address": "198.51.100.200"}],
        }
    )
    cfg["shared-networks"] = [
        {
            "name": "office",
            "interface": "",
            "option-data": [{"name": "domain-name-servers", "data": "192.0.2.1"}],
            "subnet4": [
                {"id": 10, "subnet": "203.0.113.0/25", "pools": [{"pool": "203.0.113.10-203.0.113.100"}]},
                {"id": 11, "subnet": "203.0.113.128/25", "pools": [{"pool": "203.0.113.130-203.0.113.200"}]},
            ],
            "user-context": {"pelagos": {"notes": "two floors"}},
        }
    ]
    cfg["client-classes"] = [
        {
            "name": "voip",
            "test": "option[60].text == 'phone'",
            "option-data": [{"name": "tftp-server-name", "data": "tftp.example.lan"}],
        },
        {"name": "late", "test": "member('ALL')", "only-in-additional-list": True},
    ]
    cfg["option-def"] = [{"name": "vendor-tag", "code": 224, "type": "string", "space": "dhcp4"}]
    cfg["option-data"] = [
        {"name": "domain-name", "data": "example.lan"},
        {"name": "domain-name-servers", "data": "192.0.2.1, 192.0.2.2"},
        {"name": "vendor-tag", "data": "pelagos"},
    ]
    cfg["reservations"] = [{"hw-address": "aa:bb:cc:dd:ee:ff", "hostname": "global-host"}]
    cfg["reservations-global"] = True
    cfg["dhcp-ddns"] = {"enable-updates": True, "server-ip": "127.0.0.1", "server-port": 53001}
    cfg["ddns-send-updates"] = True
    cfg["ddns-qualifying-suffix"] = "example.lan."
    return {"Dhcp4": cfg}


def dhcp6_config(root: Path, hooks: Path) -> dict[str, Any]:
    cfg = fx.dhcp6_config(root, hooks)["Dhcp6"]
    cfg["subnet6"][0]["pd-pools"][0]["excluded-prefix"] = "2001:db8:1:0:ff00::"
    cfg["subnet6"][0]["pd-pools"][0]["excluded-prefix-len"] = 72
    cfg["subnet6"][0]["reservations"] = [
        {"duid": "01:02:03:04:05:06", "ip-addresses": ["2001:db8::100"], "prefixes": ["2001:db8:1:100::/64"]}
    ]
    cfg["shared-networks"] = [
        {
            "name": "campus",
            "subnet6": [{"id": 20, "subnet": "2001:db8:2::/64", "pools": [{"pool": "2001:db8:2::/80"}]}],
        }
    ]
    cfg["client-classes"] = [{"name": "cpe", "test": "option[16].hex == 0x0001"}]
    return {"Dhcp6": cfg}


def sanitize(obj: Any, root: Path, hooks: Path) -> Any:
    text = json.dumps(obj)
    for sub in sorted({str(root / d) for d in ("k4", "k6", "d2", "ns1")}, key=len, reverse=True):
        text = text.replace(sub, "/var/lib/kea")
    text = text.replace(str(root), "/var/lib/kea")
    text = text.replace(str(hooks), "/usr/lib/x86_64-linux-gnu/kea/hooks")
    return json.loads(text)


def main() -> None:
    hooks = fx.kea_hooks_dir()
    assert hooks, "Kea hooks directory not found"
    root = Path(tempfile.mkdtemp(prefix="plg-cap-"))
    out: dict[str, Any] = {}
    http_port, ha_port, peer_port = free_port(), free_port(), free_port()
    d4 = start(
        "kea-dhcp4",
        root / "k4",
        dhcp4_config(root / "k4", hooks, http_port, ha_port, peer_port),
        root / "k4" / "kea4.sock",
    )
    try:
        d4.ok(
            "lease4-add",
            {
                "ip-address": "192.0.2.150",
                "hw-address": "aa:bb:cc:dd:ee:02",
                "subnet-id": 1,
                "hostname": "pc2",
                "client-id": "01:aa:bb:cc:dd:ee:02",
            },
        )
        d4.ok(
            "lease4-add",
            {
                "ip-address": "192.0.2.151",
                "hw-address": "aa:bb:cc:dd:ee:04",
                "subnet-id": 1,
                "fqdn-fwd": True,
                "fqdn-rev": True,
                "hostname": "pc4.example.lan.",
                "user-context": {"ISC": {"relay-agent-info": "0x0204"}},
            },
        )
        d4.ok(
            "lease4-add",
            {"ip-address": "203.0.113.20", "hw-address": "aa:bb:cc:dd:ee:05", "subnet-id": 10, "state": 1},
        )
        time.sleep(1.5)
        out["kea32-dhcp4-config-get"] = d4.command("config-get")
        out["kea32-dhcp4-status-get"] = d4.command("status-get")
        out["kea32-dhcp4-version-get"] = d4.command("version-get")
        out["kea32-dhcp4-list-commands"] = d4.command("list-commands")
        out["kea32-dhcp4-statistic-get-all"] = d4.command("statistic-get-all")
        out["kea32-dhcp4-stat-lease4-get"] = d4.command("stat-lease4-get")
        out["kea32-dhcp4-lease4-get-page"] = d4.command("lease4-get-page", {"from": "start", "limit": 100})
        out["kea32-dhcp4-lease4-get-page-empty"] = d4.command(
            "lease4-get-page", {"from": "203.0.113.20", "limit": 100}
        )
        out["kea32-dhcp4-lease4-get"] = d4.command("lease4-get", {"ip-address": "192.0.2.150"})
        out["kea32-dhcp4-lease4-get-missing"] = d4.command("lease4-get", {"ip-address": "192.0.2.199"})
        out["kea32-dhcp4-lease4-get-by-hw-address"] = d4.command(
            "lease4-get-by-hw-address", {"hw-address": "aa:bb:cc:dd:ee:02"}
        )
        out["kea32-dhcp4-lease4-get-by-hostname"] = d4.command("lease4-get-by-hostname", {"hostname": "pc2"})
        out["kea32-dhcp4-reservation-get-page"] = d4.command(
            "reservation-get-page", {"subnet-id": 1, "limit": 100}
        )
        out["kea32-dhcp4-reservation-get-page-global"] = d4.command(
            "reservation-get-page", {"subnet-id": 0, "limit": 100}
        )
        out["kea32-dhcp4-subnet4-list"] = d4.command("subnet4-list")
        out["kea32-dhcp4-network4-list"] = d4.command("network4-list")
        out["kea32-dhcp4-class-list"] = d4.command("class-list")
        out["kea32-dhcp4-config-hash-get"] = d4.command("config-hash-get")
        out["kea32-dhcp4-config-test-error"] = d4.command(
            "config-test", {"Dhcp4": {"subnet4": [{"id": 1, "subnet": "bad"}]}}
        )
        out["kea32-dhcp4-reservation-add-no-db"] = d4.command(
            "reservation-add",
            {"reservation": {"subnet-id": 1, "hw-address": "aa:bb:cc:dd:ee:03", "ip-address": "192.0.2.51"}},
        )
        out["kea32-dhcp4-lease4-del"] = d4.command("lease4-del", {"ip-address": "203.0.113.20"})
        out["kea32-dhcp4-lease4-del-missing"] = d4.command("lease4-del", {"ip-address": "203.0.113.20"})
    finally:
        d4.stop()
    d6 = start("kea-dhcp6", root / "k6", dhcp6_config(root / "k6", hooks), root / "k6" / "kea6.sock")
    try:
        d6.ok(
            "lease6-add",
            {
                "ip-address": "2001:db8::1000",
                "duid": "00:01:00:01:aa:bb",
                "iaid": 1,
                "subnet-id": 1,
                "hostname": "pc6",
            },
        )
        d6.ok(
            "lease6-add",
            {
                "ip-address": "2001:db8:1:1::",
                "prefix-len": 64,
                "type": "IA_PD",
                "duid": "00:01:00:01:aa:bb",
                "iaid": 2,
                "subnet-id": 1,
            },
        )
        time.sleep(1)
        out["kea32-dhcp6-config-get"] = d6.command("config-get")
        out["kea32-dhcp6-status-get"] = d6.command("status-get")
        out["kea32-dhcp6-list-commands"] = d6.command("list-commands")
        out["kea32-dhcp6-statistic-get-all"] = d6.command("statistic-get-all")
        out["kea32-dhcp6-stat-lease6-get"] = d6.command("stat-lease6-get")
        out["kea32-dhcp6-lease6-get-page"] = d6.command("lease6-get-page", {"from": "start", "limit": 100})
        out["kea32-dhcp6-lease6-get-by-duid"] = d6.command(
            "lease6-get-by-duid", {"duid": "00:01:00:01:aa:bb"}
        )
        out["kea32-dhcp6-reservation-get-page"] = d6.command(
            "reservation-get-page", {"subnet-id": 1, "limit": 100}
        )
    finally:
        d6.stop()
    ns = named_fx.start_named(root / "ns1")
    try:
        d2root = root / "d2"
        d2root.mkdir()
        cfg = fx.d2_config(d2root, ns.dns_port, "kea-ddns", ns.keys["kea-ddns"], free_port())
        d2 = fx.start_kea("kea-dhcp-ddns", d2root, cfg)
        try:
            out["kea32-d2-config-get"] = d2.command("config-get")
            out["kea32-d2-status-get"] = d2.command("status-get")
            out["kea32-d2-list-commands"] = d2.command("list-commands")
            out["kea32-d2-statistic-get-all"] = d2.command("statistic-get-all")
            out["kea32-d2-config-hash-get"] = d2.command("config-hash-get")
        finally:
            d2.stop()
    finally:
        ns.stop()
    for name, payload in out.items():
        (HERE / f"{name}.json").write_text(
            json.dumps(sanitize(payload, root, hooks), indent=2, sort_keys=True) + "\n"
        )
        print("wrote", name)


if __name__ == "__main__":
    main()
