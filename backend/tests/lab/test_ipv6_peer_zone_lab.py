# SPDX-License-Identifier: Apache-2.0
"""IPv6 view of a zone primary on ns1 only, read from ns2 (production item 72).

The reference pair (lab-ns1, lab-ns2, scripts/lab/provision.sh pair) gets two static zones on ns1
alone: a forward zone with AAAA at the apex and on hosts, and its /64 reverse zone in nibbles with
some PTR missing. Then the deb of this checkout on both, ns2 enrolled, both imported, the security
fixes applied, collectors running under the packaged units. ns1's collector raises ptr_mismatch for
the missing PTR; GET /hosts/ipv6 flags the same addresses on ns1 and on ns2, which does not serve
the zones. With ns1's peer API down, ns2 names the node in meta.errors instead of dropping it.
"""

from __future__ import annotations

import pytest

from tests.lab.labkit import (
    ADMIN_PASSWORD,
    NS1,
    NS2,
    Api,
    deb_package,
    fixable,
    rollback,
    run_script,
    scp,
    ssh,
    wait_for,
)

pytestmark = pytest.mark.lab

A1, A2 = NS1[1], NS2[1]
ZONE = "lab6.example"
PREFIX = "2001:db8:72::"
REV = "0.0.0.0.2.7.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
HEAD = (
    "$TTL 300\n@ IN SOA ns1.example.lan. hostmaster.example.lan. 1 3600 900 1209600 300\n"
    "@ IN NS ns1.example.lan.\n"
)
FORWARD = HEAD + (
    f"@ IN AAAA {PREFIX}1\n@ IN AAAA {PREFIX}2\nhost1 IN AAAA {PREFIX}a1\n"
    f"host2 IN AAAA {PREFIX}a2\nhost3 IN AAAA {PREFIX}a3\n"
)
REVERSE = HEAD + (
    f"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 IN PTR {ZONE}.\n2.a.0.0.0.0.0.0.0.0.0.0.0.0.0.0 IN PTR host2.{ZONE}.\n"
)
MISSING = {f"{PREFIX}2", f"{PREFIX}a1", f"{PREFIX}a3"}
STATE: dict[str, Api] = {}


def api(address: str) -> Api:
    if address not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=180, interval=5)
        STATE[address] = client
    return STATE[address]


def zone_conf(name: str) -> str:
    return (
        f'zone "{name}" {{\n\ttype primary;\n\tfile "/var/lib/bind/db.{name}";\n'
        f"\tallow-transfer {{ {A2}; }};\n\tnotify no;\n}};\n"
    )


def flagged(address: str) -> set[str]:
    page = api(address).get("/hosts/ipv6?filter=missing_ptr&per_page=500")
    return {x for r in page["items"] for x in r["ptr_missing"] if x.startswith(PREFIX)}


def no_ptr_alerts() -> set[str]:
    """ns1's ptr_mismatch: the only node holding the zones."""
    items = api(A1).get("/alerts?kind=ptr_mismatch&per_page=500")["items"]
    return {
        x["details"]["ip"]
        for x in items
        if x["state"] != "resolved"
        and x["details"]["ip"].startswith(PREFIX)
        and any("has no PTR" in p for p in x["details"]["problems"])
    }


@pytest.fixture(scope="module")
def pair():
    rollback("lab-ns1", "lab-ns2")
    run_script("provision.sh", "pair", timeout=1800)
    for name, text in ((ZONE, FORWARD), (REV, REVERSE)):
        ssh(
            A1,
            f"sudo tee /var/lib/bind/db.{name} >/dev/null && sudo chown bind:bind /var/lib/bind/db.{name}",
            data=text.encode(),
        )
        ssh(A1, "sudo tee -a /etc/bind/named.conf.local >/dev/null", data=zone_conf(name).encode())
    ssh(A1, "sudo named-checkconf && sudo rndc reconfig")
    deb = deb_package()
    for host in (A1, A2):
        scp(host, deb, "/tmp/pelagos.deb")
        ssh(host, "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb", timeout=900)
    ssh(
        A1,
        f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
        f"--web-url https://{A1}:8443 --replication-url https://{A1}:8444 "
        "&& sudo systemctl start pelagos pelagos-collector",
    )
    token = api(A1).post("/nodes/enroll-token", {})
    ssh(
        A2,
        f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
        f"--ca-fingerprint {token['ca_fingerprint']} --name ns2 "
        f"--replication-url https://{A2}:8444 --web-url https://{A2}:8443 "
        "&& sudo systemctl start pelagos pelagos-collector",
    )
    for address in (A1, A2):
        a = api(address)
        a.apply(a.post("/install/import/plan", {"engines": ["bind", "kea4", "d2"]}), timeout=900)
    for address in (A1, A2):
        a = api(address)
        a.apply(
            a.post(
                "/install/security/plan", {"finding_ids": fixable(a.get("/install/security")["findings"])}
            ),
            timeout=900,
        )
    # The consistency pass runs at start, then every 15 minutes: one now, with the fixes applied.
    for host in (A1, A2):
        ssh(host, "sudo systemctl restart pelagos-collector")
    yield


def test_the_zones_are_primary_on_ns1_only(pair):
    def names(address: str) -> set[str]:
        return {i["zone"]["name"] for i in api(address).get("/dns/zones")["items"]}

    assert {f"{ZONE}.", f"{REV}."} <= names(A1)
    assert not {f"{ZONE}.", f"{REV}."} & names(A2)


def test_missing_ptr_agrees_with_ptr_mismatch_on_both_nodes(pair):
    wait_for("ptr_mismatch of ns1's collector", lambda: no_ptr_alerts() == MISSING, timeout=300, interval=10)
    assert flagged(A1) == no_ptr_alerts() == MISSING
    page = api(A2).get("/hosts/ipv6?per_page=500")
    assert "dns.zones" not in page["meta"].get("errors", {}) and "dns.peers" not in page["meta"].get(
        "errors", {}
    )
    by_name = {r["name"]: r for r in page["items"]}
    assert by_name[f"{ZONE}."]["aaaa"] == [f"{PREFIX}1", f"{PREFIX}2"]
    assert by_name[f"{ZONE}."]["ptr_missing"] == [f"{PREFIX}2"]
    assert flagged(A2) == MISSING


def test_ns1_unreachable_is_named_on_ns2(pair):
    ssh(A1, "sudo systemctl stop pelagos")
    try:
        errors = wait_for(
            "ns1 named in meta.errors",
            lambda: api(A2).get("/hosts/ipv6")["meta"].get("errors", {}).get("dns.peers"),
            timeout=120,
            interval=5,
        )
        assert "ns1" in errors
    finally:
        ssh(A1, "sudo systemctl start pelagos")
    STATE.pop(A1, None)
    wait_for("ns1 back in ns2's view", lambda: flagged(A2) == MISSING, timeout=180, interval=5)
