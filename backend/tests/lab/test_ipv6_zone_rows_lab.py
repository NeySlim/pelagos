# SPDX-License-Identifier: Apache-2.0
"""IPv6 view from the zones under the packaged units (section 27, production item 72).

lab-r5a (snapshot `legacy`, Debian 13, BIND and Kea from Debian) gets the deb built from this
checkout, `pelagos init`, the import of its engines and the security fixes (ddi-read transfers).
Its named serves zones shaped like production: AAAA at the apex and on hosts, a /64 reverse zone
in nibbles where some PTR are missing. lab-v6c (10.99.0.90) holds the laptop's address.
Before any observation pass every AAAA is already a row and the missing source is named in
meta.unavailable; after it the laptop row carries the neighbor; `missing_ptr` always agrees with
the open `ptr_mismatch` alerts of the collector; a source without netlink shows in meta.unavailable.
"""

from __future__ import annotations

import os

import pytest

from tests.lab.labkit import ADMIN_PASSWORD, Api, deb_package, fixable, put, rollback, scp, ssh, wait_for

pytestmark = pytest.mark.lab

NODE = "10.99.0.55"
V6C = os.environ.get("PELAGOS_LAB_V6C", "10.99.0.90")
PREFIX = "2001:db8:9b::"
REV = "0.0.0.0.b.9.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
DROPIN = "/etc/systemd/system/pelagos-collector.service.d/no-netlink.conf"
NO_NETLINK = "[Service]\nRestrictAddressFamilies=\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n"
HEAD = (
    "$TTL 300\n@ IN SOA ns1.example.lan. hostmaster.example.lan. 1 3600 900 1209600 300\n"
    "@ IN NS ns1.example.lan.\n"
)
FORWARD = HEAD + (
    f"@ IN A {NODE}\n@ IN AAAA {PREFIX}1\n@ IN AAAA {PREFIX}2\ndesktop IN AAAA {PREFIX}a1\n"
    f"laptop IN AAAA {PREFIX}90\nprinter IN AAAA {PREFIX}c3\n"
)
REVERSE = HEAD + (
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 IN PTR home.lan.\n"
    "3.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0 IN PTR printer.home.lan.\n"
)
MISSING = {f"{PREFIX}2", f"{PREFIX}a1", f"{PREFIX}90"}


def zone_conf(name: str) -> str:
    return (
        f'zone "{name}" {{\n\ttype primary;\n\tfile "/var/lib/bind/db.{name}";\n'
        "\tallow-update { key kea-ddns; };\n\tallow-transfer { 10.99.0.56; };\n\tnotify no;\n};\n"
    )


def api() -> Api:
    a = Api(NODE)
    a.login()
    return a


def ping() -> bool:
    return ssh(V6C, f"ping -6 -c 2 -W 2 {PREFIX}55", check=False)[0] == 0


def flagged(a: Api) -> set[str]:
    rows = a.get("/hosts/ipv6?filter=missing_ptr&per_page=500")["items"]
    return {x for r in rows for x in r["ptr_missing"]}


def no_ptr_alerts(a: Api) -> set[str]:
    items = a.get("/alerts?kind=ptr_mismatch&per_page=500")["items"]
    return {
        x["details"]["ip"]
        for x in items
        if x["state"] != "resolved"
        and x["details"]["ip"].startswith(PREFIX)
        and any("has no PTR" in p for p in x["details"]["problems"])
    }


@pytest.fixture(scope="module")
def node():
    if ssh(V6C, "true", check=False, timeout=30)[0] != 0:
        pytest.skip("lab-v6c is not running")
    rollback("lab-r5a")
    for name, text in (("home.lan", FORWARD), (REV, REVERSE)):
        put(NODE, f"/var/lib/bind/db.{name}", text)
        ssh(NODE, f"sudo chown bind:bind /var/lib/bind/db.{name}")
        ssh(NODE, "sudo tee -a /etc/bind/named.conf.local >/dev/null", data=zone_conf(name).encode())
    ssh(NODE, "sudo named-checkconf && sudo rndc reconfig")
    deb = deb_package()
    scp(NODE, deb, "/tmp/pelagos.deb")
    ssh(NODE, "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb", timeout=900)
    # Neighbors off until the zone rows are checked: no observation pass yet.
    ssh(
        NODE,
        f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
        f"--web-url https://{NODE}:8443 --replication-url https://{NODE}:8444 "
        "&& sudo systemctl start pelagos",
    )
    a = wait_for("web API", api, timeout=120)
    a.apply(a.post("/install/import/plan", {"engines": ["bind", "kea4", "d2"]}), timeout=900)
    findings = a.get("/install/security")["findings"]
    a.apply(a.post("/install/security/plan", {"finding_ids": fixable(findings)}), timeout=900)
    ssh(NODE, f"sudo ip -6 addr replace {PREFIX}55/64 dev eth0 nodad")
    ssh(V6C, f"sudo ip -6 addr replace {PREFIX}90/64 dev eth0 nodad")
    try:
        yield
    finally:
        ssh(NODE, f"sudo rm -f {DROPIN}", check=False)
        ssh(V6C, f"sudo ip -6 addr del {PREFIX}90/64 dev eth0", check=False)
        ssh(NODE, f"sudo ip -6 addr del {PREFIX}55/64 dev eth0", check=False)


def test_zone_rows_before_any_observation(node):
    a = api()
    page = a.get("/hosts/ipv6?per_page=500")
    by_name = {r["name"]: r for r in page["items"]}
    assert by_name["home.lan."]["aaaa"] == [f"{PREFIX}1", f"{PREFIX}2"]
    assert by_name["home.lan."]["ptr_missing"] == [f"{PREFIX}2"]
    assert {"desktop.home.lan.", "laptop.home.lan.", "printer.home.lan."} <= set(by_name)
    assert all(r["observed"] == [] for r in page["items"])
    assert [u["error"] for u in page["meta"]["unavailable"]] == ["no observation pass yet"]
    assert flagged(a) == MISSING


def test_observed_neighbor_joins_and_missing_ptr_agrees_with_ptr_mismatch(node):
    ssh(NODE, "sudo systemctl start pelagos-collector")
    a = api()

    def laptop() -> dict | None:
        ping()
        rows = a.get("/hosts/ipv6?per_page=500")["items"]
        row = next((r for r in rows if r["name"] == "laptop.home.lan."), None)
        return row if row and row["observed"] else None

    row = wait_for("the laptop observed", laptop, timeout=300, interval=10)
    assert [o["address"] for o in row["observed"]] == [f"{PREFIX}90"] and row["mac"]
    assert a.get("/hosts/ipv6")["meta"]["unavailable"] == []
    wait_for("ptr_mismatch of the collector", lambda: no_ptr_alerts(a) == MISSING, timeout=300, interval=10)
    assert flagged(a) == no_ptr_alerts(a) == MISSING


def test_a_failing_source_is_named_not_an_empty_list(node):
    put(NODE, DROPIN, NO_NETLINK)
    ssh(NODE, "sudo systemctl daemon-reload && sudo systemctl restart pelagos-collector")
    a = api()

    def named() -> list | None:
        out = a.get("/hosts/ipv6")["meta"]["unavailable"]
        return out if any("netlink" in u["error"].lower() for u in out) else None

    found = wait_for("the failure in meta", named, timeout=300, interval=10)
    assert [u["source"] for u in found] == ["neighbors"]
    status = next(s for s in a.get("/admin/ipv6")["status"] if s["source"] == "neighbors")
    assert "netlink" in status["problem"].lower()
    # The zone rows stay.
    assert flagged(a) == MISSING
