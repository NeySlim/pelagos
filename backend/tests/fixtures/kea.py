# SPDX-License-Identifier: Apache-2.0
"""Real unprivileged Kea 3.x daemons in a temp dir: kea-dhcp4 (no packet I/O), kea-dhcp6, kea-dhcp-ddns.

Kea 3.x path restrictions: socket, leases, logs, pid and lock files must live
under KEA_CONTROL_SOCKET_DIR, KEA_DHCP_DATA_DIR, KEA_LOG_FILE_DIR,
KEA_PIDFILE_DIR, KEA_LOCKFILE_DIR; the socket directory must be mode 0750 or
stricter; hooks load from the compiled-in hooks directory; D2 TSIG keys use
secret-file. The fixtures honor all of that instead of passing -X.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tests.fixtures.ports import find_binary, wait_for

HOOKS4 = ("lease_cmds", "host_cmds", "subnet_cmds", "stat_cmds")
HOOKS6 = ("lease_cmds", "host_cmds", "subnet_cmds", "stat_cmds")


def kea_hooks_dir() -> Path | None:
    """From `kea-dhcp4 -W` ("Hooks directory:"), then the usual distro locations."""
    binary = find_binary("kea-dhcp4")
    if binary:
        try:
            out = subprocess.run(
                [binary, "-W"], capture_output=True, text=True, timeout=10, check=False
            ).stdout
            for line in out.splitlines():
                if "Hooks directory:" in line:
                    path = Path(line.split(":", 1)[1].strip())
                    if path.is_dir():
                        return path
        except (OSError, subprocess.SubprocessError):
            pass
    for candidate in ("/usr/lib/x86_64-linux-gnu/kea/hooks", "/usr/lib64/kea/hooks", "/usr/lib/kea/hooks"):
        if Path(candidate).is_dir():
            return Path(candidate)
    return None


def kea_available() -> bool:
    binary = find_binary("kea-dhcp4")
    return bool(binary) and os.access(binary, os.X_OK) and kea_hooks_dir() is not None


def kea_env(root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "KEA_CONTROL_SOCKET_DIR": str(root),
            "KEA_DHCP_DATA_DIR": str(root),
            "KEA_LOG_FILE_DIR": str(root),
            "KEA_PIDFILE_DIR": str(root),
            "KEA_LOCKFILE_DIR": str(root),
            "KEA_LEGAL_LOG_DIR": str(root),
        }
    )
    return env


def send_command(
    sock_path: Path, command: str, arguments: dict[str, Any] | None = None, timeout: float = 15.0
) -> dict[str, Any]:
    payload: dict[str, Any] = {"command": command}
    if arguments is not None:
        payload["arguments"] = arguments
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(sock_path))
        s.sendall(json.dumps(payload).encode())
        buf = bytearray()
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf.extend(chunk)
            try:
                return json.loads(buf.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
    return json.loads(buf.decode())


@dataclass(slots=True)
class KeaDaemon:
    name: str  # kea-dhcp4 | kea-dhcp6 | kea-dhcp-ddns
    root: Path
    config_path: Path
    socket_path: Path
    process: subprocess.Popen | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def command(self, command: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        return send_command(self.socket_path, command, arguments)

    def ok(
        self, command: str, arguments: dict[str, Any] | None = None, allow_empty: bool = False
    ) -> dict[str, Any]:
        resp = self.command(command, arguments)
        assert resp.get("result") == 0 or (allow_empty and resp.get("result") == 3), resp
        return resp.get("arguments") or {}

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process = None

    def log_text(self) -> str:
        p = self.root / f"{self.name}.stdout"
        return p.read_text() if p.exists() else ""


def dhcp4_config(
    root: Path, hooks_dir: Path, hooks: tuple[str, ...] = HOOKS4, extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "Dhcp4": {
            "interfaces-config": {"interfaces": []},
            "control-socket": {"socket-type": "unix", "socket-name": str(root / "kea4.sock")},
            "lease-database": {
                "type": "memfile",
                "persist": True,
                "name": str(root / "kea-leases4.csv"),
                "lfc-interval": 0,
            },
            "valid-lifetime": 3600,
            "hooks-libraries": [{"library": str(hooks_dir / f"libdhcp_{h}.so")} for h in hooks],
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "192.0.2.0/24",
                    "pools": [{"pool": "192.0.2.100 - 192.0.2.199"}],
                    "option-data": [{"name": "routers", "data": "192.0.2.1"}],
                    "reservations": [
                        {"hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "192.0.2.50", "hostname": "printer"}
                    ],
                    "user-context": {"pelagos": {"notes": "fixture subnet", "tags": ["lab"]}},
                }
            ],
            "loggers": [
                {
                    "name": "kea-dhcp4",
                    "output-options": [{"output": str(root / "kea-dhcp4.log")}],
                    "severity": "INFO",
                }
            ],
        }
    }
    if extra:
        cfg["Dhcp4"].update(extra)
    return cfg


def dhcp6_config(root: Path, hooks_dir: Path, hooks: tuple[str, ...] = HOOKS6) -> dict[str, Any]:
    return {
        "Dhcp6": {
            "interfaces-config": {"interfaces": []},
            "control-socket": {"socket-type": "unix", "socket-name": str(root / "kea6.sock")},
            "lease-database": {
                "type": "memfile",
                "persist": True,
                "name": str(root / "kea-leases6.csv"),
                "lfc-interval": 0,
            },
            "hooks-libraries": [{"library": str(hooks_dir / f"libdhcp_{h}.so")} for h in hooks],
            "subnet6": [
                {
                    "id": 1,
                    "subnet": "2001:db8::/64",
                    "pools": [{"pool": "2001:db8::1000 - 2001:db8::1fff"}],
                    "pd-pools": [{"prefix": "2001:db8:1::", "prefix-len": 48, "delegated-len": 64}],
                }
            ],
            "loggers": [
                {
                    "name": "kea-dhcp6",
                    "output-options": [{"output": str(root / "kea-dhcp6.log")}],
                    "severity": "INFO",
                }
            ],
        }
    }


def d2_config(root: Path, dns_port: int, key_name: str, key_secret_b64: str, d2_port: int) -> dict[str, Any]:
    secret_file = root / f"{key_name}.secret"
    secret_file.write_text(key_secret_b64)
    secret_file.chmod(0o600)
    return {
        "DhcpDdns": {
            "ip-address": "127.0.0.1",
            "port": d2_port,
            "control-socket": {"socket-type": "unix", "socket-name": str(root / "d2.sock")},
            "tsig-keys": [{"name": key_name, "algorithm": "HMAC-SHA256", "secret-file": str(secret_file)}],
            "forward-ddns": {
                "ddns-domains": [
                    {
                        "name": "example.lan.",
                        "key-name": key_name,
                        "dns-servers": [{"ip-address": "127.0.0.1", "port": dns_port}],
                    }
                ]
            },
            "reverse-ddns": {
                "ddns-domains": [
                    {
                        "name": "2.0.192.in-addr.arpa.",
                        "key-name": key_name,
                        "dns-servers": [{"ip-address": "127.0.0.1", "port": dns_port}],
                    }
                ]
            },
            "loggers": [
                {
                    "name": "kea-dhcp-ddns",
                    "output-options": [{"output": str(root / "kea-dhcp-ddns.log")}],
                    "severity": "INFO",
                }
            ],
        }
    }


def start_kea(name: str, root: Path, config: dict[str, Any]) -> KeaDaemon:
    """Write the config, `-t` it, start it, wait for the control socket."""
    binary = find_binary(name)
    if not binary:
        raise FileNotFoundError(f"{name} not found")
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o750)
    config_path = root / f"{name}.conf"
    config_path.write_text(json.dumps(config, indent=2))
    env = kea_env(root)
    check = subprocess.run(
        [binary, "-t", str(config_path)], capture_output=True, text=True, env=env, check=False
    )
    if check.returncode != 0:
        raise RuntimeError(f"{name} -t failed:\n{check.stdout}\n{check.stderr}")
    key = next(iter(config))
    socket_path = Path(config[key]["control-socket"]["socket-name"])
    stdout = (root / f"{name}.stdout").open("w")
    proc = subprocess.Popen(
        [binary, "-c", str(config_path)], stdout=stdout, stderr=subprocess.STDOUT, env=env
    )
    daemon = KeaDaemon(name=name, root=root, config_path=config_path, socket_path=socket_path, process=proc)

    def up() -> bool:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited:\n{daemon.log_text()}")
        return send_command(socket_path, "status-get").get("result") == 0

    try:
        wait_for(up, timeout=20, what=f"{name} control socket")
    except Exception:
        daemon.stop()
        raise
    return daemon
