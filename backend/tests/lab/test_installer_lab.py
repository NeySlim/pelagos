# SPDX-License-Identifier: Apache-2.0
"""Installer on real lab VMs: Debian 13 (lab-ns1) and Rocky 10 (lab-rpm).

Preconditions (done from the workstation, which holds the Proxmox token):
  scripts/lab/rollback.sh <vmid of lab-ns1> ; scripts/lab/rollback.sh <vmid of lab-rpm>
  ssh lab-dev cat ~/.ssh/pelagos_lab.pub | ssh lab-ns1 'cat >> ~/.ssh/authorized_keys'   (same for lab-rpm)
Then on lab-dev: PELAGOS_LAB=1 .venv/bin/pytest -m lab tests/lab/test_installer_lab.py

Debian: a pre-seeded legacy server (hmac-md5 keys, address-based updates, open listeners) is
imported, audited and migrated; then Kea is installed from Debian (2.6) and switched to ISC 3.2.
Rocky: BIND and Kea installed from the distro with `--init`, then Kea switched to ISC 3.2.
Each class runs in order on a VM in its clean snapshot; the VMs are rolled back afterwards.
"""

from __future__ import annotations

import io
import json
import os
import shlex
import subprocess
import tarfile
from pathlib import Path

import pytest

from pelagos.installer import bindconf, keaconf

pytestmark = pytest.mark.lab

BACKEND = Path(__file__).resolve().parents[2]
DATA = BACKEND / "tests" / "unit" / "installer" / "data"
NS1 = os.environ.get("PELAGOS_LAB_NS1", "lab@10.99.0.11")
RPM = os.environ.get("PELAGOS_LAB_RPM", "lab@10.99.0.13")
SSH_KEY = os.path.expanduser(os.environ.get("PELAGOS_LAB_SSH_KEY", "~/.ssh/pelagos_lab"))
VENV = "/opt/pelagos-lab"
PELAGOS = f"sudo {VENV}/bin/pelagos"
ADMIN_PASSWORD = "Lab-Admin-Password-1"


def ssh(host: str, command: str, check: bool = True, data: bytes | None = None, timeout: int = 1800):
    argv = [
        "ssh",
        "-i",
        SSH_KEY,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        host,
        command,
    ]
    res = subprocess.run(argv, input=data, capture_output=True, timeout=timeout, check=False)
    out = res.stdout.decode(errors="replace")
    err = res.stderr.decode(errors="replace")
    if check and res.returncode != 0:
        raise AssertionError(f"{host}: {command!r} exited {res.returncode}\n{out[-4000:]}\n{err[-4000:]}")
    return res.returncode, out, err


def put(host: str, path: str, content: str, mode: str = "0644") -> None:
    ssh(host, f"sudo install -D -m {mode} /dev/stdin {shlex.quote(path)}", data=content.encode())


def deploy(host: str) -> None:
    """Copies the backend source and installs it in a venv on the VM."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for item in ("pyproject.toml", "pelagos"):
            tar.add(
                BACKEND / item,
                arcname=f"src/{item}",
                filter=lambda t: None if "__pycache__" in t.name else t,
            )
    ssh(
        host,
        "rm -rf /tmp/pelagos-lab && mkdir -p /tmp/pelagos-lab && tar -xz -C /tmp/pelagos-lab",
        data=buf.getvalue(),
    )
    ssh(
        host,
        "if command -v apt-get >/dev/null; then "
        "sudo DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null && "
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3-venv >/dev/null; fi; "
        f"sudo python3 -m venv {VENV} && sudo {VENV}/bin/pip install -q /tmp/pelagos-lab/src",
        timeout=1800,
    )


def pelagos(host: str, args: str, check: bool = True):
    return ssh(host, f"{PELAGOS} {args}", check=check, timeout=2400)


def sudo_cat(host: str, path: str) -> str:
    return ssh(host, f"sudo cat {shlex.quote(path)}")[1]


def socket_ok_as_pelagos(host: str, socket_path: str) -> bool:
    """status-get over the Unix socket as the pelagos user: group access is what the node relies on."""
    code = (
        "import json,socket,sys\n"
        "s=socket.socket(socket.AF_UNIX)\n"
        f"s.connect({socket_path!r})\n"
        's.sendall(b\'{"command": "status-get"}\')\n'
        "buf=b''\n"
        "while True:\n"
        "    c=s.recv(65536)\n"
        "    if not c: break\n"
        "    buf+=c\n"
        "    try:\n"
        "        r=json.loads(buf); break\n"
        "    except ValueError: pass\n"
        "sys.exit(0 if r.get('result')==0 else 1)\n"
    )
    rc, _, _ = ssh(host, "sudo -u pelagos python3 -", check=False, data=code.encode())
    return rc == 0


def keys_of(text: str) -> dict[str, bindconf.KeyDef]:
    return {k.name: k for k in bindconf.keys(bindconf.parse(text))}


def nsupdate(host: str, key: str, algorithm: str, secret: str, script: str) -> tuple[int, str]:
    full = f"server 127.0.0.1\n{script}\nsend\n"
    rc, out, err = ssh(
        host, f"nsupdate -y {shlex.quote(f'{algorithm}:{key}:{secret}')}", check=False, data=full.encode()
    )
    return rc, out + err


ZONE = """$TTL 300
@ IN SOA ns1.example.lan. hostmaster.example.lan. 2026102401 3600 600 86400 300
@ IN NS ns1.example.lan.
ns1 IN A 192.0.2.1
"""

LEGACY_D2 = {
    "DhcpDdns": {
        "ip-address": "127.0.0.1",
        "port": 53001,
        "control-socket": {"socket-type": "unix", "socket-name": "kea-ddns-ctrl-socket"},
        "tsig-keys": [
            {
                "name": "kea-ddns",
                "algorithm": "HMAC-MD5",
                "secret": "bGVnYWN5LWtlYS1kZG5zLXNlY3JldC0wMDAwMDAwMDAwMDA=",
            }
        ],
        "forward-ddns": {
            "ddns-domains": [
                {"name": "example.lan.", "key-name": "kea-ddns", "dns-servers": [{"ip-address": "127.0.0.1"}]}
            ]
        },
        "reverse-ddns": {"ddns-domains": []},
        "loggers": [{"name": "kea-dhcp-ddns", "output-options": [{"output": "stdout"}], "severity": "INFO"}],
    }
}


class TestDebian:
    """lab-ns1: legacy import and migration, then Kea from Debian (2.6) and from ISC (3.2)."""

    host = NS1

    def test_00_reachable_and_clean(self):
        _rc, out, _ = ssh(self.host, "cat /etc/os-release; test ! -e /etc/bind/pelagos && echo CLEAN")
        assert "trixie" in out and "CLEAN" in out

    def test_01_seed_legacy_server(self):
        ssh(
            self.host,
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q bind9 bind9-utils bind9-dnsutils "
            "kea-dhcp-ddns-server >/dev/null",
            timeout=1800,
        )
        for f in ("named.conf", "named.conf.local", "named.conf.options", "rndc.key"):
            mode = "0640" if f == "rndc.key" else "0644"
            put(self.host, f"/etc/bind/{f}", (DATA / "bind" / "legacy" / f).read_text(), mode)
        ssh(self.host, "sudo chgrp bind /etc/bind/rndc.key")
        for z in ("db.example.lan", "db.2.0.192", "db.corp.example.lan"):
            origin = {
                "db.example.lan": "example.lan.",
                "db.2.0.192": "2.0.192.in-addr.arpa.",
                "db.corp.example.lan": "corp.example.lan.",
            }[z]
            put(self.host, f"/var/lib/bind/{z}", f"$ORIGIN {origin}\n" + ZONE)
        ssh(self.host, "sudo chown bind:bind /var/lib/bind/db.*")
        put(self.host, "/etc/kea/kea-dhcp-ddns.conf", json.dumps(LEGACY_D2, indent=2))
        ssh(
            self.host,
            "sudo systemctl restart named kea-dhcp-ddns-server && sleep 2 && sudo rndc status >/dev/null",
        )
        rc, out = nsupdate(
            self.host,
            "kea-ddns",
            "hmac-md5",
            "bGVnYWN5LWtlYS1kZG5zLXNlY3JldC0wMDAwMDAwMDAwMDA=",
            "update add legacy.example.lan. 300 IN A 192.0.2.50",
        )
        assert rc == 0, out

    def test_02_deploy_pelagos(self):
        deploy(self.host)
        _rc, out, _ = pelagos(self.host, "version")
        assert out.startswith("pelagos ")

    def test_03_audit_before_import(self):
        _, out, _ = pelagos(self.host, "audit --json")
        kinds = {f["kind"] for f in json.loads(out)["findings"]}
        assert {
            "weak_rndc_key",
            "weak_shared_kea_key",
            "weak_tsig_key",
            "allow_update_by_address",
            "open_allow_transfer",
            "open_recursion",
            "dnssec_validation_off",
            "rndc_nonlocal",
            "stats_nonlocal",
        } <= kinds

    def test_04_import(self):
        before = {f: sudo_cat(self.host, f"/etc/bind/{f}") for f in ("named.conf.local", "rndc.key")}
        rc, out, err = pelagos(self.host, "import --engines bind,d2 --yes")
        assert rc == 0, out + err
        assert "import/verify: ok" in out and "bind.unchanged=ok" in out and "d2.unchanged=ok" in out
        # Only include lines were added to the user files.
        for f, text in before.items():
            assert sudo_cat(self.host, f"/etc/bind/{f}") == text
        named = sudo_cat(self.host, "/etc/bind/named.conf")
        assert named.rstrip().endswith('include "/etc/bind/pelagos/pelagos.conf";')
        assert 'include "/etc/bind/pelagos/options.conf";' in sudo_cat(
            self.host, "/etc/bind/named.conf.options"
        )
        keys = keys_of(sudo_cat(self.host, "/etc/bind/pelagos/keys.conf"))
        assert set(keys) == {"ddi-read", "ddi-admin"}
        assert (
            ssh(self.host, "sudo stat -c '%a %U %G' /etc/bind/pelagos/keys.conf")[1].strip()
            == "640 pelagos bind"
        )
        # The node's own access path works as the pelagos user.
        rc, out, _ = ssh(
            self.host, "sudo -u pelagos rndc -c /etc/bind/pelagos/rndc-pelagos.conf status", check=False
        )
        assert rc == 0, out
        assert socket_ok_as_pelagos(self.host, "/run/kea/kea-ddns-ctrl-socket")

    def test_05_migrate_everything(self):
        rc, out, err = pelagos(self.host, "audit --fix-all --yes")
        assert rc == 0, out + err
        _, out, _ = pelagos(self.host, "audit --json")
        assert json.loads(out)["findings"] == []
        ssh(self.host, "sudo rndc status >/dev/null && systemctl is-active named kea-dhcp-ddns-server")
        assert "algorithm hmac-sha256" in sudo_cat(self.host, "/etc/bind/rndc.key")
        keys = keys_of(sudo_cat(self.host, "/etc/bind/pelagos/keys.conf"))
        assert "kea-ddns-sha256" in keys
        d2 = keaconf.loads(sudo_cat(self.host, "/etc/kea/kea-dhcp-ddns.conf"))["DhcpDdns"]
        assert [k["name"] for k in d2["tsig-keys"]] == ["kea-ddns-sha256"]
        assert d2["forward-ddns"]["ddns-domains"][0]["key-name"] == "kea-ddns-sha256"
        # Updates: the new D2 key and ddi-admin are accepted, the old md5 key is refused.
        new = keys["kea-ddns-sha256"]
        rc, out = nsupdate(
            self.host, new.name, "hmac-sha256", new.secret, "update add d2.example.lan. 300 IN A 192.0.2.51"
        )
        assert rc == 0, out
        adm = keys["ddi-admin"]
        rc, out = nsupdate(
            self.host, adm.name, "hmac-sha256", adm.secret, 'update add t.example.lan. 300 IN TXT "x"'
        )
        assert rc == 0, out
        rc, out = nsupdate(
            self.host,
            "kea-ddns",
            "hmac-md5",
            "bGVnYWN5LWtlYS1kZG5zLXNlY3JldC0wMDAwMDAwMDAwMDA=",
            "update add old.example.lan. 300 IN A 192.0.2.52",
        )
        assert rc != 0
        # Transfers need ddi-read now.
        rd = keys["ddi-read"]
        _, out, _ = ssh(
            self.host, f"dig +noall +answer -y hmac-sha256:ddi-read:{rd.secret} @127.0.0.1 example.lan AXFR"
        )
        assert "d2.example.lan." in out and "t.example.lan." in out
        _, out, _ = ssh(self.host, "dig +noall +answer @127.0.0.1 example.lan AXFR", check=False)
        assert "d2.example.lan." not in out
        # Listeners are local only.
        _, out, _ = ssh(self.host, "sudo ss -ltnH '( sport = :953 or sport = :8053 )'")
        assert out.strip() and all(" 127.0.0.1:" in line for line in out.strip().splitlines())

    def test_06_install_kea_from_debian(self):
        rc, out, err = pelagos(self.host, "install --engines kea4,d2 --source distro --yes")
        assert rc == 0, out + err
        assert "install/verify: ok" in out
        _, ver, _ = ssh(self.host, "sudo /usr/sbin/kea-dhcp4 -v")
        assert ver.startswith("2.6")
        # Kea 2.6 creates its socket 0750: the drop-in makes it group-writable for the pelagos user.
        assert "pelagos-socket.conf" in ssh(self.host, "systemctl cat kea-dhcp4-server")[1]
        assert socket_ok_as_pelagos(self.host, "/run/kea/kea4-ctrl-socket")
        cfg = keaconf.loads(sudo_cat(self.host, "/etc/kea/kea-dhcp4.conf"))["Dhcp4"]
        assert cfg["interfaces-config"] == {"interfaces": []}
        assert "lease_cmds" in json.dumps(cfg["hooks-libraries"])
        _, out, _ = pelagos(self.host, "install --detect")
        det = json.loads(out)
        assert (
            det["engines"]["kea4"]["version"].startswith("2.6")
            and det["engines"]["kea4"]["source"] == "distro"
        )
        assert (
            det["pelagos"]["include_present"]
            and det["pelagos"]["keys_present"]
            and det["pelagos"]["sockets_ok"]
        )

    def test_07_switch_kea_to_isc(self):
        rc, out, err = pelagos(self.host, "install --engines kea4,d2 --source isc --isc-series 3.2 --yes")
        assert rc == 0, out + err
        assert "install/verify: ok" in out
        _, ver, _ = ssh(self.host, "sudo /usr/sbin/kea-dhcp4 -v")
        assert ver.startswith("3.2")
        assert ssh(self.host, "systemctl is-active isc-kea-dhcp4-server isc-kea-dhcp-ddns-server")[0] == 0
        d2 = keaconf.loads(sudo_cat(self.host, "/etc/kea/kea-dhcp-ddns.conf"))["DhcpDdns"]
        (key,) = d2["tsig-keys"]
        assert "secret" not in key and key["secret-file"] == "/etc/kea/kea-ddns-sha256.tsig"
        assert socket_ok_as_pelagos(self.host, "/run/kea/kea4-ctrl-socket")
        assert socket_ok_as_pelagos(self.host, "/run/kea/kea-ddns-ctrl-socket")


class TestRocky:
    """lab-rpm: fresh install from Rocky packages with --init, SELinux enforcing, then ISC Kea 3.2."""

    host = RPM

    def test_00_reachable_and_clean(self):
        _, out, _ = ssh(
            self.host, "cat /etc/os-release; getenforce; test ! -e /etc/named/pelagos && echo CLEAN"
        )
        assert 'ID="rocky"' in out and "Enforcing" in out and "CLEAN" in out

    def test_01_deploy(self):
        deploy(self.host)

    def test_02_install_distro(self):
        rc, out, err = pelagos(
            self.host,
            "install --engines bind,kea4,d2 --source distro --init --name lab-rpm "
            f"--admin-password {ADMIN_PASSWORD} --yes",
        )
        assert rc == 0, out + err
        assert "install/verify: ok" in out
        ssh(self.host, "systemctl is-active named kea-dhcp4 kea-dhcp-ddns")
        named = sudo_cat(self.host, "/etc/named.conf")
        assert named.rstrip().endswith('include "/etc/named/pelagos/pelagos.conf";')
        assert 'include "/etc/named/pelagos/options.conf";' in named
        # SELinux: our files carry the named configuration type, named reads them, no denial.
        _, ctx, _ = ssh(self.host, "sudo ls -Z /etc/named.conf /etc/named/pelagos/keys.conf")
        assert ctx.count("named_conf_t") == 2, ctx
        _, out, _ = ssh(self.host, "curl -fsS http://127.0.0.1:8953/json/v1/server")
        assert "boot-time" in out
        rc, out, _ = ssh(
            self.host, "sudo -u pelagos rndc -c /etc/named/pelagos/rndc-pelagos.conf status", check=False
        )
        assert rc == 0, out
        assert socket_ok_as_pelagos(self.host, "/run/kea/kea4-ctrl-socket")
        assert socket_ok_as_pelagos(self.host, "/run/kea/kea-ddns-ctrl-socket")
        # D2 and BIND share kea-ddns (hmac-sha256) through a secret file.
        keys = keys_of(sudo_cat(self.host, "/etc/named/pelagos/keys.conf"))
        assert set(keys) == {"ddi-read", "ddi-admin", "kea-ddns"}
        assert sudo_cat(self.host, "/etc/kea/kea-ddns.tsig").strip() == keys["kea-ddns"].secret
        # The node was initialized and knows what it drives; secrets are encrypted in cluster.toml.
        node = sudo_cat(self.host, "/etc/pelagos/node.toml")
        assert 'named_conf = "/etc/named.conf"' in node and "kea4 = true" in node
        cluster = sudo_cat(self.host, "/var/lib/pelagos/cluster.toml")
        assert '"tsig/ddi-admin" = "enc:v1:' in cluster and '"tsig/kea-ddns" = "enc:v1:' in cluster
        _, audit, _ = pelagos(self.host, "audit --json")
        assert json.loads(audit)["findings"] == []

    def test_03_switch_kea_to_isc(self):
        rc, out, err = pelagos(self.host, "install --engines kea4,d2 --source isc --isc-series 3.2 --yes")
        assert rc == 0, out + err
        _, ver, _ = ssh(self.host, "sudo /usr/sbin/kea-dhcp4 -v")
        assert ver.startswith("3.2")
        assert socket_ok_as_pelagos(self.host, "/run/kea/kea4-ctrl-socket")
        assert socket_ok_as_pelagos(self.host, "/run/kea/kea-ddns-ctrl-socket")
        _, out, _ = pelagos(self.host, "install --detect")
        det = json.loads(out)
        assert det["engines"]["kea4"]["source"] == "isc" and det["pelagos"]["sockets_ok"]
