# SPDX-License-Identifier: Apache-2.0
"""A real unprivileged named (BIND 9.20) in a temp dir: dynamic zones, TSIG keys, rndc, statistics-channel."""

from __future__ import annotations

import os
import re
import secrets
import signal
import subprocess
from base64 import b64encode
from dataclasses import dataclass, field
from pathlib import Path

from tests.fixtures.ports import find_binary, free_port, wait_for

ZONE = "example.lan."
REVERSE_ZONE = "2.0.192.in-addr.arpa."
REVERSE6_ZONE = "8.b.d.0.1.0.0.2.ip6.arpa."

FORWARD_ZONE_TEXT = """$TTL 3600
@ IN SOA ns1.example.lan. hostmaster.example.lan. ( 2026102401 3600 900 1209600 300 )
@ IN NS ns1.example.lan.
@ IN NS ns2.example.lan.
ns1 IN A 192.0.2.1
ns1 IN AAAA 2001:db8::1
ns2 IN A 192.0.2.2
www IN A 192.0.2.10
"""

REVERSE_ZONE_TEXT = """$TTL 3600
@ IN SOA ns1.example.lan. hostmaster.example.lan. ( 2026102401 3600 900 1209600 300 )
@ IN NS ns1.example.lan.
@ IN NS ns2.example.lan.
1 IN PTR ns1.example.lan.
2 IN PTR ns2.example.lan.
10 IN PTR www.example.lan.
"""

REVERSE6_ZONE_TEXT = """$TTL 3600
@ IN SOA ns1.example.lan. hostmaster.example.lan. ( 2026102401 3600 900 1209600 300 )
@ IN NS ns1.example.lan.
1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 IN PTR ns1.example.lan.
"""


def new_secret() -> str:
    return b64encode(secrets.token_bytes(32)).decode()


@dataclass(slots=True)
class NamedServer:
    root: Path
    dns_port: int
    rndc_port: int
    stats_port: int
    keys: dict[str, str]  # name -> base64 secret, all hmac-sha256
    rndc_conf: Path
    named_conf: Path
    process: subprocess.Popen | None = None
    log: Path = field(default_factory=Path)
    role: str = "primary"

    @property
    def stats_url(self) -> str:
        return f"http://127.0.0.1:{self.stats_port}/json/v1"

    def rndc(self, *args: str) -> str:
        rndc = find_binary("rndc")
        assert rndc, "rndc not found"
        out = subprocess.run(
            [rndc, "-c", str(self.rndc_conf), "-s", "127.0.0.1", "-p", str(self.rndc_port), *args],
            capture_output=True, text=True, timeout=15, check=False,
        )  # fmt: skip
        if out.returncode != 0:
            raise RuntimeError(out.stderr.strip() or out.stdout.strip())
        return out.stdout

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
        return self.log.read_text() if self.log.exists() else ""


def _key_statement(name: str, secret: str) -> str:
    return f'key "{name}" {{\n\talgorithm hmac-sha256;\n\tsecret "{secret}";\n}};\n'


def write_primary_conf(
    root: Path, ports: dict[str, int], keys: dict[str, str], secondary_port: int | None = None
) -> Path:
    zones = root / "zones"
    run = root / "run"
    zones.mkdir(exist_ok=True)
    run.mkdir(exist_ok=True)
    (zones / "example.lan.db").write_text(FORWARD_ZONE_TEXT)
    (zones / "2.0.192.in-addr.arpa.db").write_text(REVERSE_ZONE_TEXT)
    (zones / "8.b.d.0.1.0.0.2.ip6.arpa.db").write_text(REVERSE6_ZONE_TEXT)
    (root / "keys.conf").write_text("".join(_key_statement(n, s) for n, s in keys.items() if n != "rndc-key"))
    (root / "rndc.key").write_text(_key_statement("rndc-key", keys["rndc-key"]))
    also_notify = (
        f"also-notify {{ 127.0.0.1 port {secondary_port}; }};\n\tnotify explicit;"
        if secondary_port
        else "notify no;"
    )
    policy = (
        "grant ddi-admin zonesub A AAAA PTR CNAME TXT SRV MX DHCID; grant kea-ddns zonesub A AAAA PTR DHCID;"
    )
    ptr_policy = "grant ddi-admin zonesub PTR; grant kea-ddns zonesub PTR DHCID;"

    def zone(name: str, file: str, extra_policy: str = policy) -> str:
        return (
            f'zone "{name}" {{\n\ttype primary;\n\tfile "{file}";\n'
            f"\tupdate-policy {{ {extra_policy} }};\n"
            f"\tallow-transfer {{ key ddi-read; key secondary-xfr; }};\n\t{also_notify}\n}};\n"
        )

    conf = f"""// Pelagos test fixture, generated
include "{root}/keys.conf";
include "{root}/rndc.key";
controls {{ inet 127.0.0.1 port {ports["rndc"]} allow {{ 127.0.0.1; }} keys {{ "rndc-key"; }}; }};
statistics-channels {{ inet 127.0.0.1 port {ports["stats"]} allow {{ 127.0.0.1; }}; }};
options {{
\tdirectory "{zones}";
\tpid-file "{run}/named.pid";
\tsession-keyfile "{run}/session.key";
\tmanaged-keys-directory "{run}";
\tlisten-on port {ports["dns"]} {{ 127.0.0.1; }};
\tlisten-on-v6 {{ none; }};
\trecursion no;
\tdnssec-validation no;
\tallow-query {{ any; }};
\tminimal-responses yes;
}};
logging {{
\tchannel pelagos_log {{ file "{root}/named.log"; severity info; print-time yes; print-category yes; }};
\tcategory default {{ pelagos_log; }};
\tcategory update {{ pelagos_log; }};
\tcategory security {{ pelagos_log; }};
}};
{zone("example.lan", "example.lan.db")}
{zone("2.0.192.in-addr.arpa", "2.0.192.in-addr.arpa.db", ptr_policy)}
{zone("8.b.d.0.1.0.0.2.ip6.arpa", "8.b.d.0.1.0.0.2.ip6.arpa.db", ptr_policy)}
"""
    path = root / "named.conf"
    path.write_text(conf)
    return path


def write_secondary_conf(root: Path, ports: dict[str, int], keys: dict[str, str], primary_port: int) -> Path:
    zones = root / "zones"
    run = root / "run"
    zones.mkdir(exist_ok=True)
    run.mkdir(exist_ok=True)
    (root / "keys.conf").write_text(_key_statement("secondary-xfr", keys["secondary-xfr"]))
    (root / "rndc.key").write_text(_key_statement("rndc-key", keys["rndc-key"]))

    def zone(name: str) -> str:
        return (
            f'zone "{name}" {{\n\ttype secondary;\n\tfile "{name}.db";\n'
            f"\tprimaries {{ 127.0.0.1 port {primary_port} key secondary-xfr; }};\n"
            f"\tallow-transfer {{ key secondary-xfr; }};\n}};\n"
        )

    conf = f"""// Pelagos test fixture, secondary
include "{root}/keys.conf";
include "{root}/rndc.key";
server 127.0.0.1 {{ keys {{ secondary-xfr; }}; }};
controls {{ inet 127.0.0.1 port {ports["rndc"]} allow {{ 127.0.0.1; }} keys {{ "rndc-key"; }}; }};
statistics-channels {{ inet 127.0.0.1 port {ports["stats"]} allow {{ 127.0.0.1; }}; }};
options {{
\tdirectory "{zones}";
\tpid-file "{run}/named.pid";
\tsession-keyfile "{run}/session.key";
\tmanaged-keys-directory "{run}";
\tlisten-on port {ports["dns"]} {{ 127.0.0.1; }};
\tlisten-on-v6 {{ none; }};
\trecursion no;
\tdnssec-validation no;
\tnotify no;
}};
logging {{
\tchannel pelagos_log {{ file "{root}/named.log"; severity info; print-time yes; print-category yes; }};
\tcategory default {{ pelagos_log; }};
\tcategory xfer-in {{ pelagos_log; }};
}};
{zone("example.lan")}
{zone("2.0.192.in-addr.arpa")}
{zone("8.b.d.0.1.0.0.2.ip6.arpa")}
"""
    path = root / "named.conf"
    path.write_text(conf)
    return path


def write_rndc_conf(root: Path, port: int) -> Path:
    path = root / "rndc.conf"
    path.write_text(
        f'include "{root}/rndc.key";\n'
        f'options {{ default-key "rndc-key"; default-server 127.0.0.1; default-port {port}; }};\n'
    )
    return path


def start_named(
    root: Path,
    *,
    role: str = "primary",
    keys: dict[str, str] | None = None,
    primary_port: int | None = None,
    secondary_port: int | None = None,
) -> NamedServer:
    """Start named -g -u <user>; waits for rndc status. Caller stops it."""
    named = find_binary("named")
    checkconf = find_binary("named-checkconf")
    if not named or not checkconf:
        raise FileNotFoundError("named / named-checkconf not found")
    root.mkdir(parents=True, exist_ok=True)
    keys = dict(keys or {})
    for name in ("ddi-read", "ddi-admin", "kea-ddns", "secondary-xfr", "rndc-key"):
        keys.setdefault(name, new_secret())
    ports = {"dns": free_port(), "rndc": free_port(), "stats": free_port()}
    if role == "primary":
        conf = write_primary_conf(root, ports, keys, secondary_port=secondary_port)
    else:
        assert primary_port is not None
        conf = write_secondary_conf(root, ports, keys, primary_port)
    rndc_conf = write_rndc_conf(root, ports["rndc"])
    check = subprocess.run([checkconf, str(conf)], capture_output=True, text=True, check=False)
    if check.returncode != 0:
        raise RuntimeError(f"named-checkconf failed:\n{check.stdout}{check.stderr}")
    user = os.environ.get("USER") or str(os.getuid())
    stdout = (root / "named.stdout").open("w")
    proc = subprocess.Popen(
        [named, "-c", str(conf), "-g", "-u", user], stdout=stdout, stderr=subprocess.STDOUT
    )
    server = NamedServer(
        root=root, dns_port=ports["dns"], rndc_port=ports["rndc"], stats_port=ports["stats"],
        keys=keys, rndc_conf=rndc_conf, named_conf=conf, process=proc, log=root / "named.log", role=role,
    )  # fmt: skip

    def up() -> bool:
        if proc.poll() is not None:
            raise RuntimeError("named exited:\n" + (root / "named.stdout").read_text())
        return "server is up and running" in server.rndc("status")

    try:
        wait_for(up, timeout=15, what="named rndc status")
    except Exception:
        server.stop()
        raise
    return server


def parse_serial(zonestatus: str) -> int | None:
    m = re.search(r"^serial:\s*(\d+)", zonestatus, re.M)
    return int(m.group(1)) if m else None
