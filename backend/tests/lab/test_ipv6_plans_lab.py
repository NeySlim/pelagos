# SPDX-License-Identifier: Apache-2.0
"""IPv6 AAAA and PTR plans against a real SLAAC client (design 13.7, batches V4 and V5).

lab-r5a (snapshot `legacy`) gets the deb built from this checkout, `pelagos init` and the BIND
import, then sends router advertisements (radvd) for a documentation /64; lab-v6c (10.99.0.90)
takes an EUI-64 and a temporary address (`use_tempaddr=2`). The collector records both from the
real neighbor table. A history injected in the node's observation table (rotated temporaries,
the host's old prefix) stands for the days that pass. Through the web API: only the EUI-64
address is proposed, a temporary one is refused, the selection first asks for the missing
reverse zone, and once that zone exists the plan writes the AAAA and the PTR of the stable address
in the real named, nothing for the temporary ones.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time

import pytest

from tests.lab.labkit import (
    ADMIN_PASSWORD,
    Api,
    ApiError,
    deb_package,
    fixable,
    put,
    rollback,
    scp,
    ssh,
    wait_for,
)

pytestmark = pytest.mark.lab

NODE = "10.99.0.55"
V6C = os.environ.get("PELAGOS_LAB_V6C", "10.99.0.90")
PREFIX = ipaddress.IPv6Network("2001:db8:97::/64")
OLD_PREFIX = ipaddress.IPv6Network("2001:db8:96::/64")
NODE6 = "2001:db8:97::55"
ZONE = "v6lab.lan."
HOST = f"v6c.{ZONE}"
SERIES = "/var/lib/pelagos/series.sqlite"
DAY = 86400
RADVD = (
    "interface eth0 {\n\tAdvSendAdvert on;\n\tMinRtrAdvInterval 3;\n\tMaxRtrAdvInterval 10;\n"
    f"\tprefix {PREFIX} {{\n\t\tAdvOnLink on;\n\t\tAdvAutonomous on;\n\t}};\n}};\n"
)
# Rows (mac, address, first, last) added to the node's observation table, as days of history.
INJECT = """\
import json, sqlite3, sys
rows = json.load(sys.stdin)
c = sqlite3.connect(sys.argv[1])
q = "SELECT node_id FROM ipv6_observations WHERE mac = ? LIMIT 1"
node = c.execute(q, (rows["mac"],)).fetchone()[0]
for a, f, l in rows["history"]:
    c.execute(
        "INSERT OR REPLACE INTO ipv6_observations VALUES (?, ?, 'neighbors', '', ?, ?, ?, 'reachable')",
        (rows["mac"], a, node, f, l),
    )
c.execute(
    "UPDATE ipv6_observations SET first_seen = ? WHERE mac = ? AND address = ?",
    (rows["eui_first"], rows["mac"], rows["eui"]),
)
c.commit()
"""


def api() -> Api:
    a = Api(NODE)
    a.login()
    return a


def dig(name: str, rtype: str) -> list[str]:
    out = ssh(NODE, f"dig +short +norecurse @127.0.0.1 {name} {rtype}")[1]
    return sorted(line.strip() for line in out.splitlines() if line.strip())


def ptr_name(address: str) -> str:
    return ipaddress.IPv6Address(address).reverse_pointer + "."


def slaac_addresses() -> dict[str, str] | None:
    addrs = json.loads(ssh(V6C, "ip -j -6 addr show dev eth0")[1])[0]["addr_info"]
    found = {
        ("temporary" if a.get("temporary") else "stable"): a["local"]
        for a in addrs
        if a.get("scope") == "global"
        and ipaddress.IPv6Address(a["local"]) in PREFIX
        and not a.get("tentative")
        and not a.get("deprecated")
    }
    return found if {"temporary", "stable"} <= set(found) else None


@pytest.fixture(scope="module")
def lab():
    if ssh(V6C, "true", check=False, timeout=30)[0] != 0:
        pytest.skip("lab-v6c is not running")
    rollback("lab-r5a")
    deb = deb_package()
    scp(NODE, deb, "/tmp/pelagos.deb")
    ssh(NODE, "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb radvd", timeout=900)
    ssh(
        NODE,
        f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
        f"--web-url https://{NODE}:8443 --replication-url https://{NODE}:8444 "
        "&& sudo systemctl start pelagos pelagos-collector",
    )
    a = wait_for("web API", api, timeout=120)
    a.apply(a.post("/install/import/plan", {"engines": ["bind"]}), timeout=900)
    findings = a.get("/install/security")["findings"]
    a.apply(a.post("/install/security/plan", {"finding_ids": fixable(findings)}), timeout=900)

    # radvd refuses to run without forwarding; the node keeps its own address in the /64.
    put(NODE, "/etc/radvd.conf", RADVD)
    ssh(
        NODE,
        f"sudo sysctl -qw net.ipv6.conf.all.forwarding=1 && sudo ip -6 addr replace {NODE6}/64 dev eth0 nodad"
        " && sudo systemctl restart radvd",
    )
    ssh(
        V6C,
        "sudo sysctl -qw net.ipv6.conf.eth0.accept_ra=1 net.ipv6.conf.eth0.use_tempaddr=2"
        f" && sudo ip -6 addr flush dev eth0 to {PREFIX}",
    )
    try:
        found = wait_for("the SLAAC addresses of lab-v6c", slaac_addresses, timeout=120, interval=3)
        mac = ssh(V6C, "cat /sys/class/net/eth0/address")[1].strip()
        yield {"mac": mac, "eui": found["stable"], "temp": found["temporary"]}
    finally:
        ssh(NODE, "sudo systemctl stop radvd", check=False)
        ssh(V6C, f"sudo ip -6 addr flush dev eth0 to {PREFIX}", check=False)
        ssh(NODE, f"sudo ip -6 addr del {NODE6}/64 dev eth0", check=False)


def test_stable_address_gets_aaaa_and_ptr_temporaries_never(lab):
    a = api()
    mac, eui, temp = lab["mac"], lab["eui"], lab["temp"]
    iid = int(ipaddress.IPv6Address(eui)) & (2**64 - 1)
    old_eui = str(ipaddress.IPv6Address(int(OLD_PREFIX.network_address) | iid))

    # The host's forward zone: its A and the AAAA of the prefix it had before.
    a.call("PUT", "/admin/settings", {"dns": {"default_ns": [f"ns1.{ZONE}"]}})
    a.call("PUT", "/admin/ipv6", {"prefixes": [str(OLD_PREFIX)]})
    records = [
        {"name": f"ns1.{ZONE}", "rtype": "A", "ttl": 300, "rdata": [NODE]},
        {"name": HOST, "rtype": "A", "ttl": 300, "rdata": [V6C]},
        {"name": HOST, "rtype": "AAAA", "ttl": 300, "rdata": [old_eui]},
    ]
    zone = {"name": ZONE, "kind": "primary", "view": "_default", "ns": [f"ns1.{ZONE}"], "records": records}
    a.apply(a.post("/dns/zones/plan", {"change": {"op": "add", "target": f"_default/{ZONE}", "after": zone}}))
    assert dig(HOST, "AAAA") == [old_eui]

    def observed() -> bool:
        for src in (eui, temp):
            ssh(V6C, f"ping -6 -c 2 -W 2 -I {src} {NODE6}", check=False)
        rows = a.get("/hosts/ipv6?per_page=500")["items"]
        seen = {o["address"] for r in rows if r["mac"] == mac for o in r["observed"]}
        return {eui, temp} <= seen

    wait_for("both addresses observed by the collector", observed, timeout=300, interval=10)

    # Ten days of daily temporaries, the old prefix left 20 days ago, the EUI-64 there for 20 days.
    now = int(time.time())
    base = int(PREFIX.network_address)
    temps = [
        (str(ipaddress.IPv6Address(base | 0xDEAD0000 | d)), now - d * DAY, now - d * DAY + 2 * DAY)
        for d in range(10, 1, -1)
    ]
    old = (old_eui, now - 40 * DAY, now - 20 * DAY)
    history = {"mac": mac, "eui": eui, "eui_first": now - 20 * DAY, "history": [*temps, old]}
    put(NODE, "/tmp/inject-ipv6.py", INJECT)
    ssh(NODE, f"sudo python3 /tmp/inject-ipv6.py {SERIES}", data=json.dumps(history).encode())

    r = wait_for("the proposal", lambda: host_row(a, mac, proposed=True), timeout=120, interval=5)
    classes = {o["address"]: o["class"] for o in r["observed"]}
    assert classes[eui] == "eui64"
    assert classes[temp] in ("unknown", "temporary")
    assert all(classes[t] == "temporary" for t, _f, _l in temps[:-2]), classes
    assert r["proposal"]["address"] == eui and r["proposal"]["name"] == HOST
    assert mac in {x["mac"] for x in a.get("/hosts/ipv6?filter=missing_aaaa&per_page=500")["items"]}
    # The AAAA of the old prefix, unseen for 20 days, is stale on the host without lease.
    stale = a.get("/hosts/ipv6?filter=stale&per_page=500")["items"]
    assert [x["stale"] for x in stale if x["mac"] == mac] == [[old_eui]], stale

    # A temporary address is never written.
    with pytest.raises(ApiError) as refused:
        a.post("/hosts/ipv6/plan", {"items": [{"host_key": r["host_key"], "address": temps[0][0]}]})
    assert refused.value.status == 400

    # No reverse zone serves the /64 yet: the selection names the zone to create.
    item = {"items": [{"host_key": r["host_key"], "address": eui}]}
    with pytest.raises(ApiError) as missing:
        a.post("/hosts/ipv6/plan", item)
    assert missing.value.status == 409
    zones = missing.value.body["reverse_zones"]
    rev = "7.9.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
    assert zones == [{"prefix": str(PREFIX), "zone": "0.0.0.0." + rev, "view": "_default"}], zones
    a.apply(a.post("/hosts/ipv6/reverse-zone/plan", {"prefix": str(PREFIX)}))
    assert dig("0.0.0.0." + rev, "SOA")

    plan = a.post("/hosts/ipv6/plan", item)
    assert plan["summary_message"]["key"] == "plan.ipv6.aaaa"
    assert a.apply(plan)["state"] == "applied"
    assert dig(HOST, "AAAA") == sorted([eui, old_eui])
    assert dig(ptr_name(eui), "PTR") == [HOST]
    assert dig(ptr_name(temp), "PTR") == []
    assert all(dig(ptr_name(t), "PTR") == [] for t, _f, _l in temps)

    after = wait_for("the row without proposal", lambda: host_row(a, mac, proposed=False), timeout=60)
    assert eui in after["aaaa"] and temp not in after["aaaa"] and after["proposal"] is None
    assert mac not in {x["mac"] for x in a.get("/hosts/ipv6?filter=missing_aaaa&per_page=500")["items"]}


def host_row(a: Api, mac: str, proposed: bool) -> dict | None:
    rows = a.get("/hosts/ipv6?per_page=500")["items"]
    r = next((x for x in rows if x["mac"] == mac and x["name"] == HOST), None)
    return r if r and bool(r["proposal"]) == proposed else None
