# SPDX-License-Identifier: Apache-2.0
"""An AAAA added at a DDNS name (design 13.7 decision 6, `note.ipv6_ddns_owner`) against the real
kea-dhcp-ddns 2.6.3 and BIND 9.20 of lab-ad1.

Name change requests go straight to D2 (127.0.0.1:53001, length-prefixed JSON, Kea
`ncr_msg.cc`). RFC 4703 section 5.5 as Kea 2.6.3 `nc_remove.cc` builds it: the removal deletes
the lease's A, then the DHCID only when no A nor AAAA is left. So the AAAA, the DHCID and the
IPv4 PTR stay after the lease ends, and another client (another DHCID) is refused the name.
"""

from __future__ import annotations

import time

import pytest

from tests.lab.labkit import put, ssh

pytestmark = pytest.mark.lab

NODE = "10.99.0.31"
NAME = f"v6ddns{time.strftime('%H%M%S')}.example.lan."
IP, OTHER_IP = "10.99.1.201", "10.99.1.202"
AAAA = "2001:db8::77"
NCR = """\
import hashlib, json, socket, struct, sys, time
kind, fqdn, ip, client = sys.argv[1:5]
dhcid = (b"\\x00\\x01\\x01" + hashlib.sha256(client.encode() + fqdn.encode()).digest()).hex()
ncr = {"change-type": 0 if kind == "add" else 1, "forward-change": True, "reverse-change": True,
       "fqdn": fqdn, "ip-address": ip, "dhcid": dhcid,
       "lease-expires-on": time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time() + 3600)),
       "lease-length": 3600, "use-conflict-resolution": True}
data = json.dumps(ncr).encode()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(struct.pack("!H", len(data)) + data, ("127.0.0.1", 53001))
"""
# The TSIG key D2 signs with, read from its configuration.
KEY = """\
import json
d = json.load(open("/etc/kea/kea-dhcp-ddns.conf"))["DhcpDdns"]
k = d["tsig-keys"][0]
print(f"{k['algorithm'].lower()}:{k['name']}:{k['secret']}")
"""


def dig(*args: str) -> list[str]:
    out = ssh(NODE, "dig +short +norecurse @127.0.0.1 " + " ".join(args))[1]
    return sorted(line.strip() for line in out.splitlines() if line.strip())


def ncr(kind: str, ip: str, client: str) -> None:
    ssh(NODE, f"python3 /tmp/pelagos-ncr.py {kind} {NAME} {ip} {client}")
    time.sleep(3)


def nsupdate(key: str, lines: str) -> None:
    ssh(NODE, f"nsupdate -y {key}", data=f"server 127.0.0.1\n{lines}".encode())


@pytest.fixture(scope="module")
def key():
    if ssh(NODE, "systemctl is-active -q kea-dhcp-ddns-server", check=False, timeout=30)[0] != 0:
        pytest.skip("lab-ad1 or its kea-dhcp-ddns is not running")
    put(NODE, "/tmp/pelagos-ncr.py", NCR)
    put(NODE, "/tmp/pelagos-key.py", KEY)
    secret = ssh(NODE, "sudo python3 /tmp/pelagos-key.py")[1].strip()
    yield secret
    nsupdate(
        secret,
        f"zone example.lan.\nupdate delete {NAME}\nsend\n"
        f"zone 1.99.10.in-addr.arpa.\nupdate delete {IP.split('.')[3]}.1.99.10.in-addr.arpa.\nsend\n",
    )


def test_an_aaaa_at_a_ddns_name_keeps_the_dhcid_and_refuses_another_client(key):
    ncr("add", IP, "client-a")
    assert dig(NAME, "A") == [IP] and dig(NAME, "DHCID") and dig("-x", IP) == [NAME]
    dhcid = dig(NAME, "DHCID")

    # What a Pelagos IPv6 plan writes at that owner.
    nsupdate(key, f"zone example.lan.\nupdate add {NAME} 300 AAAA {AAAA}\nsend\n")
    assert dig(NAME, "AAAA") == [AAAA]

    # The lease ends: D2 removes the A only; the DHCID and the IPv4 PTR stay with the AAAA.
    ncr("remove", IP, "client-a")
    assert dig(NAME, "A") == []
    assert dig(NAME, "AAAA") == [AAAA]
    assert dig(NAME, "DHCID") == dhcid
    assert dig("-x", IP) == [NAME]

    # Another client (a random MAC gives another DHCID) is refused the name.
    ncr("add", OTHER_IP, "client-b")
    assert dig(NAME, "A") == []
    assert dig("-x", OTHER_IP) == []
