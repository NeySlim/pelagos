# SPDX-License-Identifier: Apache-2.0
"""A real named with a configuration body of the test's choice (views, catalogs, policies).

Same rules as tests.fixtures.named: temp directory, free ports, rndc and statistics channel on
127.0.0.1, run as the current user. The caller stops the server.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from tests.fixtures import named as named_fx
from tests.fixtures.ports import find_binary, free_port, wait_for

KEY_NAMES = ("ddi-read", "ddi-admin", "kea-ddns", "secondary-xfr", "rndc-key")


def zone_text(zone: str, serial: int = 2026102401, extra: str = "") -> str:
    zone = zone.rstrip(".") + "."
    return (
        f"$TTL 3600\n@ IN SOA ns1.{zone} hostmaster.{zone} ( {serial} 3600 900 1209600 300 )\n"
        f"@ IN NS ns1.{zone}\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\n{extra}"
    )


def start(
    root: Path,
    body: str,
    keys: dict[str, str] | None = None,
    extra_keys: tuple[str, ...] = (),
    options: str = "",
    files: dict[str, str] | None = None,
) -> named_fx.NamedServer:
    """`body` may use {zones} (the zone directory) and {key:<name>} is not needed: every key of
    `keys` is defined at the top level before it."""
    named = find_binary("named")
    checkconf = find_binary("named-checkconf")
    if not named or not checkconf:
        raise FileNotFoundError("named / named-checkconf not found")
    root.mkdir(parents=True, exist_ok=True)
    zones = root / "zones"
    run = root / "run"
    zones.mkdir(exist_ok=True)
    run.mkdir(exist_ok=True)
    keys = dict(keys or {})
    for name in (*KEY_NAMES, *extra_keys):
        keys.setdefault(name, named_fx.new_secret())
    for name, text in (files or {}).items():
        (zones / name).write_text(text)
    ports = {"dns": free_port(), "rndc": free_port(), "stats": free_port()}
    (root / "keys.conf").write_text(
        "".join(named_fx._key_statement(n, s) for n, s in keys.items() if n != "rndc-key")
    )
    (root / "rndc.key").write_text(named_fx._key_statement("rndc-key", keys["rndc-key"]))
    conf = f"""// Pelagos daemon test, custom body
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
\tnotify no;
{options}}};
logging {{
\tchannel pelagos_log {{ file "{root}/named.log"; severity info; print-time yes; print-category yes; }};
\tcategory default {{ pelagos_log; }};
}};
{body.replace("{zones}", str(zones)).replace("{dns_port}", str(ports["dns"]))}
"""
    path = root / "named.conf"
    path.write_text(conf)
    rndc_conf = named_fx.write_rndc_conf(root, ports["rndc"])
    check = subprocess.run([checkconf, str(path)], capture_output=True, text=True, check=False)
    if check.returncode != 0:
        raise RuntimeError(f"named-checkconf failed:\n{check.stdout}{check.stderr}\n{conf}")
    user = os.environ.get("USER") or str(os.getuid())
    stdout = (root / "named.stdout").open("w")
    proc = subprocess.Popen(
        [named, "-c", str(path), "-g", "-u", user], stdout=stdout, stderr=subprocess.STDOUT
    )
    server = named_fx.NamedServer(
        root=root,
        dns_port=ports["dns"],
        rndc_port=ports["rndc"],
        stats_port=ports["stats"],
        keys=keys,
        rndc_conf=rndc_conf,
        named_conf=path,
        process=proc,
        log=root / "named.log",
    )

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
